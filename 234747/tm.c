/**
 * @file   tm.c
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
//#include <pthread.h>

// Internal headers
#include <tm.h>
#include "stm_structures.h"
#include "tl2_utils.h"
#include "utils.h"

// -------------------------------------------------------------------------- //

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? 1 : 0, 1)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? 1 : 0, 0)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define one or several attributes.
 * @param type... Attribute names
**/
#undef as
#ifdef __GNUC__
    #define as(type...) \
        __attribute__((type))
#else
    #define as(type...)
    #warning This compiler has no support for GCC attributes
#endif

// -------------------------------------------------------------------------- //

/**
 * Single LinkedList of segments that need to be free. They might still be used by other
 * ongoing transactions, thus before freeing them the ref_count values needs to be 0.
 * Upcoming transactions won't have access to these segments, as they are not part of the region segments anymore.
 */
static struct _segment* free_segment_list = NULL;

/**
 * Acquire the spin-lock given
 */
static void acquire_lock(atomic_uint* lock) {
    unsigned int prev = 0;
    while (!atomic_compare_exchange_strong_explicit(lock, &prev, 1u, memory_order_acquire,
                                                    memory_order_relaxed)) {
        prev = 0;
    }
}

/**
 * Release the given lock
 */
static void release_lock(atomic_uint* lock) {
    atomic_store_explicit(lock, 0u, memory_order_release);
}

/**
 * Return the real alignment allocation of the region
 */
static inline size_t tm_align_alloc(struct _region * r) {
    return r->align_alloc;
}

/**
 * Initialize the segment with the necessary data structure and allocations
 * @return true if it succeeded else false
 */
static bool fill_segment(struct _region* r, struct _segment* s, size_t size) {
    atomic_init(&s->ref_count, 0u);
    s->size = size;
    s->removed = false;
    s->is_new = true;
    const size_t align_alloc = tm_align_alloc(r);
    if (unlikely(posix_memalign(&(s->start), align_alloc, size) != 0)) {
        return false;
    }
    memset(s->start, 0, size);

    // Construct the array with the versions locks for TL2 of size = size/align
    const size_t len = get_length(size, tm_align(r));
    atomic_uint* version_locks = calloc(len, sizeof(atomic_uint));
    if (unlikely(!version_locks)) {
        safe_free(s->start);
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        atomic_init(&(version_locks[i]), 0u);
    }
    s->versioned_locks = version_locks;
    s->prev = NULL;
    s->next = NULL;
    return true;
}

// -------------------------------------------------------------------------- //

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
    if (size % align != 0) {
        return invalid_shared;
    }
    region* r = malloc(sizeof(struct _region));
    if (unlikely(!r)) {
        return invalid_shared;
    }
    atomic_init(&r->segments_lkd_lock, 0u);
    atomic_init(&r->free_lkd_lock, 0u);

    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;
    r->align = align;
    r->align_alloc = align_alloc;
    atomic_init(&(r->global_version_clock), 0u);

    bool is_init = fill_segment(r, &(r->first_segment), size);
    if (!is_init) {
        safe_free(r);
        return invalid_shared;
    }
    r->first_segment.is_new = false; // First segment special case
    return r;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    region* r = (region*) shared;
    segment* s = r->first_segment.next;
    // Free allocated segments
    while(s != NULL) {
        segment* next = s->next;
        safe_free(s->start);
        safe_free(s->versioned_locks);
        safe_free(s);
        s = next;
    }
    safe_free(r);

    // Free the segments in lazy free list
    while(free_segment_list != NULL) {
        segment* temp = free_segment_list;
        free_segment_list = free_segment_list->next;
        safe_free(temp->versioned_locks);
        safe_free(temp->start);
        safe_free(temp);
    }
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    return ((region *)shared)->first_segment.start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    return ((region*) shared)->first_segment.size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    return ((region *) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    unsigned int global_clock = atomic_load_explicit(&(((region*) shared)->global_version_clock), memory_order_acquire);
    size_t alignment = tm_align(shared);
    region* r = (region*) shared;
    transaction* txn = (transaction *)malloc(sizeof(transaction));
    if (unlikely(!txn)) {
        return invalid_tx;
    }

    // Lock when sync the segments
    acquire_lock(&r->segments_lkd_lock);

    txn->rv = global_clock;
    txn->read_only = is_ro;
    // Initialize the transaction to have access to all segments of the region
    size_t nb_segments = get_nb_segments_region(shared);
    txn->read_write_set = malloc(sizeof(struct _rw_set));
    segment* start = &r->first_segment;
    rw_set* set = txn->read_write_set;
    for (size_t i=0; i < nb_segments; i++) {
        set->segment = start;
        set->to_remove = false;
        atomic_fetch_add_explicit(&set->segment->ref_count, 1, memory_order_relaxed);
        if (!is_ro) {
            size_t len = get_length(start->size, alignment);
            set->was_read = calloc(len, sizeof(bool));
            if (unlikely(!set->was_read)) {
                free_txn((tx_t) txn, shared);
                release_lock(&r->segments_lkd_lock);
                return invalid_tx;
            }
            set->updated_value = calloc(len, sizeof(void *));
            if (unlikely(!set->updated_value)) {
                free_txn((tx_t) txn, shared);
                release_lock(&r->segments_lkd_lock);
                return invalid_tx;
            }
        }
        // Alloc next element of the linkedList if possible
        start = start->next;
        if ((i+1) != nb_segments) {
            set->next = malloc(sizeof(struct _rw_set));
            set = set->next;
        } else {
            set->next = NULL;
        }
    }

    release_lock(&r->segments_lkd_lock);
    return (tx_t) txn;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    region* r = (region *) shared;
    transaction* txn = (transaction *) tx;
    if (txn->read_only) {
        free_txn(tx, shared);
        return true;
    }

    bool segments_list_lock = false;
    bool free_list_lock = false;
    // Acquire the lock only if necessary, if no segment is added or removed, there is no need.
    rw_set* current_set = txn->read_write_set;
    while (current_set != NULL) {
        if (current_set->segment->is_new && !current_set->to_remove) {
            segments_list_lock = true;
        } else if (current_set->to_remove && !current_set->segment->removed) {
            segments_list_lock = true;
            free_list_lock = true;
            break;
        }
        current_set = current_set->next;
    }

    if (segments_list_lock)
        acquire_lock(&r->segments_lkd_lock);

    if (free_list_lock)
        acquire_lock(&r->free_lkd_lock);

    // Validate the transaction
    bool is_valid_transaction = validate_transaction(r, txn);
    if (!is_valid_transaction) {
        free_txn(tx, shared);
        if (segments_list_lock)
            release_lock(&r->segments_lkd_lock);
        if (free_list_lock)
            release_lock(&r->free_lkd_lock);
        return false;
    }

    // Write all the updates in shared memory and release the write locks
    current_set = txn->read_write_set;
    while (current_set != NULL) {
        writes_in_shared_memory(r, txn, current_set);
        if (current_set->segment->is_new && !current_set->to_remove) {
            append_alloc_segment(current_set->segment, &r->first_segment);
            // Mark segment as old
            current_set->segment->is_new = false;
        } else if (current_set->to_remove && !current_set->segment->removed) {
            // Remove segment from region LinkedList and add it to 'to be free' list
            remove_alloc_segment(current_set->segment);
            // Mark segment as removed and set is_new to false just in case
            current_set->segment->is_new = false;
            current_set->segment->removed = true;
            if (free_segment_list == NULL) {
                free_segment_list = current_set->segment;
            } else {
               prepend_alloc_segment(current_set->segment, free_segment_list);
            }
        }

        current_set = current_set->next;
    }

    if (segments_list_lock)
        release_lock(&r->segments_lkd_lock);
    if (free_list_lock)
        release_lock(&r->free_lkd_lock);

    // Free the transaction and decrease ref_counts
    free_txn(tx, shared);
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    transaction* txn = (transaction *) tx;
    if (source == NULL || target == NULL) {
        free_txn(tx, shared);
        return false;
    }
    size_t align = tm_align(shared);
    if (size % align != 0) {
        free_txn(tx, shared);
        return false;
    }

    rw_set* set = get_rw_set(shared, source, (transaction *)tx);
    size_t start_pos = get_segment_start_pos(shared, source, set->segment);
    size_t len = get_length(size, align);

    unsigned int* old_locks = NULL;
    // Needed in post validation only if the transaction is not read only
    if (!txn->read_only) {
        old_locks = calloc(len, sizeof(unsigned int));
        if (!unlikely(old_locks)) {
            free_txn(tx, shared);
            return false;
        }
        for (size_t i=0; i < len; i++) {
            unsigned int lock = atomic_load_explicit(&(set->segment->versioned_locks[start_pos+i]), memory_order_acquire);
            old_locks[i] = lock;
            if (is_locked(lock) || get_lock_version(lock) > txn->rv) {
                safe_free(old_locks);
                free_txn(tx, shared);
                return false;
            }
        }
    }

    // Load instruction
    void* src_ptr = (void*)source;
    void* target_ptr = target;
    for (size_t i = start_pos; i < start_pos + len; i++) {
        void* new_val = NULL;
        if (!txn->read_only) {
            new_val = set->updated_value[i];
        }
        if (!txn->read_only && new_val != NULL) { // Give local value if updated
            memcpy(target_ptr, new_val, align);
        } else {
            memcpy(target_ptr, src_ptr, align);
        }
        // Add to read-set
        if(!txn->read_only) {
            set->was_read[i] = true;
        }

        src_ptr += align;
        target_ptr += align;
    }

    // Post Validate the read to
    bool validated = post_validate_read(txn, start_pos, len, old_locks, set->segment);
    if (old_locks != NULL) {
        safe_free(old_locks);
    }
    if (!validated) {
        free_txn(tx, shared);
        return false;
    }

    return true;
}


/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    transaction* txn = (transaction*) tx;
    size_t align = tm_align(shared);
    if (size % align != 0) {
        free_txn(tx, shared);
        return false;
    }

    rw_set* set = get_rw_set(shared, target, txn);
    size_t start_pos = get_segment_start_pos(shared, target, set->segment);
    size_t len = get_length(size, align);
    void* src_ptr = (void*) source;
    for (size_t i=start_pos; i < start_pos + len; i++) {
       if (set->updated_value[i] == NULL) {
           set->updated_value[i] = malloc(align);
           if (unlikely(!set->updated_value[i])) {
               free_txn(tx, shared);
               return false;
           }
       }

       memcpy(set->updated_value[i], src_ptr, align);
       src_ptr += align;
    }

    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused)) {
    size_t align = tm_align(shared);
    if (size % align != 0) {
        return abort_alloc;
    }

    transaction* txn = (transaction *) tx;
    segment* s = malloc(sizeof(struct _segment));
    if (unlikely(!s)) {
        return nomem_alloc;
    }

    bool init = fill_segment((region *)shared, s, size);
    if (!init) {
        safe_free(s);
        return nomem_alloc;
    }

    atomic_fetch_add_explicit(&s->ref_count, 1, memory_order_relaxed);

    bool is_added = add_segment_to_txn(shared, txn, s);
    if (!is_added) {
        safe_free(s->versioned_locks);
        safe_free(s->start);
        safe_free(s);
        return abort_alloc;
    }

    *target = s->start;
    return success_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused)) {
    transaction* txn = (transaction *) tx;
    // Mark this segment to be removed in tm_end
    rw_set* set = get_rw_set(shared, target, txn);
    set->to_remove = true;
    region* r = (region *) shared;

    // Best effort to free the free list
    unsigned int p = 0;
    if (!atomic_compare_exchange_strong_explicit(&r->free_lkd_lock, &p, 1u, memory_order_acquire,
                                                    memory_order_relaxed)) {
        return true;
    }

    // Check the 'to be freed' list of segments and removed the old freed segments with ref_count == 0
    segment* prev = NULL;
    segment* current = free_segment_list;
    while (current != NULL) {
        // Safe next and prev
        segment* next = current->next;
        // Check if ref count is 0 to free segment
        unsigned int ref_count = atomic_load_explicit(&(current->ref_count), memory_order_acquire);
        if (ref_count == 0) {
            // If head will be deleted, replace it with next
            if (free_segment_list == current) {
                free_segment_list = current->next;
            }
            safe_free(current->versioned_locks);
            safe_free(current->start);
            safe_free(current);
            current = NULL;
            // Update prev in linkedlist
            if (prev != NULL) {
                prev->next = next;
            }
        } else {
            prev = current;
        }

        current = next;
    }

    release_lock(&r->free_lkd_lock);
    return true;
}
