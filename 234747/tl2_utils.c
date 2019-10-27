/**
 * @file   tl2_utils.c
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
**/
// External headers
#define NDEBUG
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Internal headers
#include "tl2_utils.h"

bool is_locked(unsigned int clock) {
    // Mask to extract MSB and compare with 0
    unsigned int mask = 1 << (sizeof(unsigned int) * 8 - 1);
    return (clock & mask) != 0u;
}

unsigned int extract_version(unsigned int versioned_lock) {
    // Mask to extract everything except MSB
    unsigned int version_mask = ~(0u) >> 1;
    return versioned_lock & version_mask;
}

bool post_validate_read(transaction* tx, size_t index, size_t nb_items, const unsigned int* prev_clocks, const segment* s) {
    for (size_t i = 0; i < nb_items; i++) {
        unsigned int version_lock = atomic_load(&(s->versions_locks[i + index]));
        bool locked = is_locked(version_lock);
        if (locked) {
            return false;
        }
        unsigned int new_version = extract_version(version_lock);
        if (new_version > tx->rv) {
            return false;
        }
        if (prev_clocks != NULL) {
            unsigned int prev_clock = prev_clocks[i];
            assert(!is_locked(prev_clock));
            unsigned int prev_version = extract_version(prev_clock);
            if (new_version != prev_version) {
                return false;
            }
        }
    }
    return true;
}

bool check_read_set(region* r, transaction* tx, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t nb_items = get_nb_items(size, align);
    for (size_t i = 0; i < nb_items; i++) {
        // If is in the read-set
        bool was_read = set->was_read[i];
        if (was_read) {
            unsigned int clock = atomic_load(&(set->segment->versions_locks[i]));
            bool locked = is_locked(clock);
            if (set->updated_value[i] == NULL && locked) {
                return false;
            }
            unsigned int clock_version = extract_version(clock);
            if (clock_version > tx->rv) {
                return false;
            }
        }
    }
    return true;
}

void release_all_writes_set_lock(region* r, transaction* txn) {
    size_t align = r->align;
    rw_set* current_set = txn->read_write_set;
    while (current_set != NULL) {
        size_t size = current_set->segment->size;
        release_write_set_locks(current_set, get_nb_items(size, align));
        current_set = current_set->next;
    }
}

// Release all locks gotten until this rw_set (exclusive)
static void release_locks_until_set(region* r, transaction* txn, rw_set* set) {
    size_t align = r->align;
    rw_set* current_set = txn->read_write_set;
    while (current_set != set) {
        size_t size = current_set->segment->size;
        release_write_set_locks(current_set, get_nb_items(size, align));
        current_set = current_set->next;
    }
}

bool validate_transaction(region* r, transaction* txn) {
    // lock the write-sets
    rw_set* current_set = txn->read_write_set;
    while (current_set != NULL) {
        bool success = lock_write_set_locks(r, current_set);
        if (!success) {
            release_locks_until_set(r, txn, current_set);
            return false;
        }
        current_set = current_set->next;
    }

    unsigned int vclock = atomic_fetch_add(&(r->global_version_clock), 1);
    unsigned int vw = vclock + 1;
    txn->vw = vw;

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

// Release first n locks of the write set
void release_write_set_locks(rw_set* set, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (set->updated_value[i] != NULL) {
            unsigned int lock = atomic_load(&(set->segment->versions_locks[i]));
            assert(is_locked(lock));
            if (is_locked((lock))) {
                unsigned int unlock_mask = ~(0u) >> 1;
                unsigned int new_value = lock & unlock_mask;
                atomic_store(&(set->segment->versions_locks[i]), new_value);
            }
        }
    }
}

void writes_in_shared_memory(region* r, transaction* tx, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t nb_items = get_nb_items(size, align);
    void* shared_address = set->segment->start;
    for (size_t i = 0; i < nb_items; i++) {
        if (set->updated_value[i] != NULL) {
            memcpy(shared_address, set->updated_value[i], align);
            assert(is_locked(atomic_load(&(set->segment->versions_clocks[i]))));
            // Unlock this segment index
            unsigned int mask = ~(0u) >> 1; // Unlock
            unsigned int new_value = tx->vw & mask;
            atomic_store(&(set->segment->versions_locks[i]), new_value);
        }
        shared_address += align;
    }
}

bool lock_write_set_locks(region* r, rw_set* set) {
    size_t size = set->segment->size;
    size_t align = r->align;
    size_t nb_items = get_nb_items(size, align);
    for (size_t i = 0; i < nb_items; i++) {
        void* new_val = set->updated_value[i];
        if (new_val != NULL) {
            unsigned int ith_lock = atomic_load(&(set->segment->versions_locks[i]));
            unsigned int lock_mask = 1u << (sizeof(unsigned int) * 8 - 1);
            unsigned int unlock_mask = ~(0u) >> 1;
            unsigned int expected_value = ith_lock & unlock_mask;
            unsigned int new_value = ith_lock | lock_mask;
            bool got_the_lock = atomic_compare_exchange_strong(&(set->segment->versions_locks[i]), &expected_value, new_value);
            if (!got_the_lock) {
                release_write_set_locks(set, i);
                return false;
            }
            ith_lock = atomic_load(&(set->segment->versions_locks[i]));
            assert(is_locked(ith_lock));
        }
    }
    return true;
}