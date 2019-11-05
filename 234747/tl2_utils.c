/**
 * @file   tl2_utils.c
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
 *
 * The TL2 utility methods required by the TL2 algorithm
**/
// External headers
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Internal headers
#include "tl2_utils.h"

/**
 * Release all the locks acquired until the given index n in this specific read/write set. This method is only used when
 * a lock can't not be acquire in a specific segment and we need to abort the transaction
 * @param set The read/write set
 * @param n The index until we have to release the lock
 */
static void release_write_set_locks(rw_set* set, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (set->updated_value[i] != NULL) {
            unsigned int lock = atomic_load_explicit(&(set->segment->versioned_locks[i]), memory_order_acquire);
            if (is_locked((lock))) {
                unsigned int mask_unlocking = ~(0u) >> 1;
                unsigned int new_value = lock & mask_unlocking;
                atomic_store_explicit(&(set->segment->versioned_locks[i]), new_value, memory_order_release);
            }
        }
    }
}

/**
 * Release all locks gotten until this given rw_set (exclusive).
 *
 * @param r  The region of the transactional memory
 * @param txn The transaction
 * @param set The read/write set defining where we have to release the lock (exclusive)
 */
static void release_locks_until_set(region* r, transaction* txn, rw_set* set) {
    size_t align = r->align;
    rw_set* current_set = txn->read_write_set;
    while (current_set != set) {
        size_t size = current_set->segment->size;
        release_write_set_locks(current_set, get_length(size, align));
        current_set = current_set->next;
    }
}

/**
 * Release all the versioned lock acquire by this transaction.
 * @param r The region of the transactional memory
 * @param txn The transaction
 */
static void release_all_writes_set_lock(region* r, transaction* txn) {
    size_t align = r->align;
    rw_set* current_set = txn->read_write_set;
    while (current_set != NULL) {
        size_t size = current_set->segment->size;
        release_write_set_locks(current_set, get_length(size, align));
        current_set = current_set->next;
    }
}

/**
 * Lock the versioned lock of the segment associated with this read/write set. In case all the necessary locks cannot be
 * acquired, it release the acquired locks until now and the transaction fails/
 * @param r The region of the transactional memory
 * @param set The read/write set associated to the segment
 * @return True if all necessary locks were acquired else False
 */
static bool lock_write_set_locks(region* r, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t len = get_length(size, align);
    for (size_t i = 0; i < len; i++) {
        void* new_val = set->updated_value[i];
        if (new_val != NULL) {
            unsigned int lock = atomic_load_explicit(&(set->segment->versioned_locks[i]), memory_order_acquire);
            unsigned int mask_unlocking = ~(0u) >> 1;
            unsigned int expected_value = lock & mask_unlocking;
            unsigned int mask_locking = 1u << (sizeof(unsigned int) * 8 - 1);
            unsigned int new_value = lock | mask_locking;
            bool acquired = atomic_compare_exchange_strong_explicit(&(set->segment->versioned_locks[i]), &expected_value, new_value, memory_order_acquire, memory_order_relaxed);
            if (!acquired) {
                release_write_set_locks(set, i);
                return false;
            }
        }
    }
    return true;
}

/**
 * This function check the read set and is called in validate_transaction.
 * This function checks the given read set. It checks that the version number associated with the versioned locks is
 * smaller or equals than rv. It also verify that these memory locations have not been locked by other threads.
 * In the special case where rv + 1 = wv, this function is not called.
 * @param r The region of the transactional memory
 * @param tx The transaction
 * @param set The read/write set
 * @return True if valid else False
 */
static bool check_read_set(region* r, transaction* tx, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t len = get_length(size, align);
    for (size_t i = 0; i < len; i++) {
        bool was_read = set->was_read[i];
        if (was_read) {
            unsigned int lock = atomic_load_explicit(&(set->segment->versioned_locks[i]), memory_order_acquire);
            bool locked = is_locked(lock);
            if (set->updated_value[i] == NULL && locked) {
                return false;
            }
            unsigned int lock_version = get_lock_version(lock);
            if (lock_version > tx->rv) {
                return false;
            }
        }
    }
    return true;
}

/**
 * Check if the given lock is already acquired by looking at the most significant bit.
 * @param lock The lock to be checked
 * @return True if the lock is locked else False
 */
bool is_locked(unsigned int lock) {
    // Mask to extract MSB and compare with 0
    unsigned int msbMask = 1 << (sizeof(unsigned int) * 8 - 1);
    return (lock & msbMask) != 0u;
}

/**
 * Extract the version of the given versioned lock. The version is defined by all the bits of the given versioned
 * lock except the most significant bit.
 * @param lock The lock
 * @return The version of the given lock.
 */
unsigned int get_lock_version(unsigned int lock) {
    // Mask to extract everything except MSB
    unsigned int version_mask = ~(0u) >> 1;
    return lock & version_mask;
}

/**
 * Post validate a read transaction according to the TL2 algorithm.
 * This function check that the versioned lock are free and didn't change since the start of a tm_read. Additionally, it
 * also checks that the lock's version field is smaller or equal to the transaction rv.
 * Otherwise, it suggest that the memory location has been modified and we should abort.
 *
 * @param tx The transaction
 * @param startPos The first index in the segment to validate
 * @param len The number of elements in the segment to check starting at startPos
 * @param old_locks The previous locks values seen at the beginning of tm_read.
 * @param s The segment
 * @return True if valid else False
 */
bool post_validate_read(transaction* tx, size_t startPos, size_t len, const unsigned int* old_locks, const segment* s) {
    for (size_t i = 0; i < len; i++) {
        unsigned int version_lock = atomic_load_explicit(&(s->versioned_locks[i + startPos]), memory_order_acquire);
        bool locked = is_locked(version_lock);
        if (locked) {
            return false;
        }
        unsigned int new_version = get_lock_version(version_lock);
        if (new_version > tx->rv) {
            return false;
        }
        if (old_locks != NULL) {
            unsigned int prev_version = get_lock_version(old_locks[i]);
            if (new_version != prev_version) {
                return false;
            }
        }
    }
    return true;
}

/**
 * This function performs several steps of the TL2 algorithm (specifically step 3, 4, 5)w hen doing a write transaction
 * to ensure that the given transaction is valid and can be commited.
 * This function will acquire all the lock of the write-sets of the segments needed, then it increments the global
 * version clock and assign it to txn->wv variable and finally validate the read-set.
 * @param r The region of the transactional memory
 * @param txn The transaction
 * @return True if valid else False
 */
bool validate_transaction(region* r, transaction* txn) {
    // Lock the write-sets
    rw_set* current_set = txn->read_write_set;
    while (current_set != NULL) {
        bool success = lock_write_set_locks(r, current_set);
        if (!success) {
            release_locks_until_set(r, txn, current_set);
            return false;
        }
        current_set = current_set->next;
    }

    unsigned int global_clock = atomic_fetch_add_explicit(&(r->global_version_clock), 1, memory_order_relaxed);
    txn->vw = global_clock + 1;

    // Validate all the read-sets if necessary
    if (txn->rv + 1 != txn->vw) {
        current_set = txn->read_write_set;
        while (current_set != NULL) {
            if (!check_read_set(r, txn, current_set)) {
                release_all_writes_set_lock(r, txn);
                return false;
            }
            current_set = current_set->next;
        }
    }

    return true;
}

/**
 * Commit the given transaction and for each location, it release the location lock by setting the version value to the
 * write-version wv and by clearing the lock bit.
 * @param r The region of the transactional memory
 * @param tx The transaction
 * @param set The read/write set to commit
 */
void writes_in_shared_memory(region* r, transaction* tx, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t len = get_length(size, align);
    void* shared_address = set->segment->start;
    for (size_t i = 0; i < len; i++) {
        if (set->updated_value[i] != NULL) {
            memcpy(shared_address, set->updated_value[i], align);
            // Unlock this segment index
            unsigned int mask_unlocking = ~(0u) >> 1;
            unsigned int new_value = tx->vw & mask_unlocking;
            atomic_store_explicit(&(set->segment->versioned_locks[i]), new_value, memory_order_release);
        }
        shared_address += align;
    }
}