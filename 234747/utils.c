/**
 * @file   utils.c
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
 *
 * Utility methods used throughout the software transactional memory implementation
**/
// External headers
#include <stdlib.h>
#include <stdio.h>

// Internal headers
#include "utils.h"

/**
 * Utility method to free a pointer correctly, avoiding undefined behaviors.
 * @param ptr The pointer to be freed
 */
void safe_free(void* ptr) {
    free(ptr);
    ptr = NULL;
}

/**
 * Remove a segment from the double LinkedList
 * @param s The segment to be removed
 */
void remove_alloc_segment(struct _segment* s) {
    segment* prev = s->prev;
    segment* next = s->next;
    if (prev != NULL) {
        prev->next = next;
    }
    if (next != NULL) {
        next->prev = prev;
    }
    s->prev = NULL;
    s->next = NULL;
}

/**
 * Append a segment to the LinkedList starting at base
 * @param s The segment to be added
 * @param base The start of the LinkedList
 */
void append_alloc_segment(struct _segment* s, struct _segment* base) {
    segment* last = base;
    while (last->next != NULL) {
        last = last->next;
    }

    last->next = s;
    s->prev = last;
    s->next = NULL;
}

/**
 * Prepend a segment to the LinkedList starting at base
 * @param s The segment to be added
 * @param base The start of the LinkedList
 */
void prepend_alloc_segment(struct _segment* s, struct _segment* base) {
    s->next = base;
    s->prev = NULL;
    base->prev = s;
    base = s;
}

/**
 * Get the index of the source pointer in the given segment
 * @param shared The region of the transactional memory
 * @param source The source pointer
 * @param s The segment
 * @return the index corresponding to source
 */
size_t get_segment_start_pos(shared_t shared, void const* source, segment* s) {
    size_t align = tm_align(shared);
    size_t start_pos = (source - s->start) / align;
    return start_pos;
}

/**
 * Get the length of the given size assuming each element has size alignment
 * @param size The size
 * @param alignment The alignment value
 * @return the length
 */
size_t get_length(size_t size, size_t alignment) {
    return size / alignment;
}

/**
 * Traverse the LinkedList of segments of the given transactional region and compute the number of segment.
 * @param shared The region of the transactional memory
 * @return the number of segment in the transactional memory
 */
size_t get_nb_segments_region(shared_t shared) {
    region* r = (region*) shared;
    segment s = r->first_segment;
    size_t count = 1;

    segment* next = s.next;
    while(next != NULL) {
        next = next->next;
        count++;
    }
    return count;
}

/**
 * Free the given transaction by releasing all the memory acquired during the execution of the transaction. This function
 * also decrease the ref_count of the segments and release the segment allocated by this transaction.
 * @param tx The transaction
 * @param shared The region of the transactional memory
 */
void free_txn(tx_t tx, shared_t shared) {
    transaction * txn = (transaction *) tx;
    rw_set* current = txn->read_write_set;
    while (current != NULL) {
        if (!txn->read_only) {
            safe_free(current->was_read);

            size_t size = current->segment->size;
            size_t align = tm_align(shared);
            size_t len = get_length(size, align);
            for (size_t i=0; i < len; i++) {
                if(current->updated_value[i] != NULL) {
                    safe_free(current->updated_value[i]);
                }
            }
            safe_free(current->updated_value);

        }
        // Decrease ref count of this segment
        atomic_fetch_add_explicit(&current->segment->ref_count, -1, memory_order_relaxed);

        // Free local segments. No need to lock, since this segment is not sync in the region
        if (current->segment->is_new) {
            free(current->segment->versioned_locks);
            free(current->segment->start);
            free(current->segment);
        }
        rw_set* next = current->next;
        safe_free(current);
        current = next;
    }
    free((void*)tx);
}

/**
 * Get the corresponding Read/Write set of the source pointer. This function looks for the segment corresponding to the
 * given source pointer and return the read/write set associated to it.
 * @param shared The region of the transcational memory
 * @param source The source pointer
 * @param tx The transaction
 * @return The corresponding read/write set
 */
rw_set* get_rw_set(shared_t shared, void const* source, transaction* tx) {
    rw_set* current = tx->read_write_set;
    size_t align = tm_align(shared);
    while (current != NULL) {
        if (source >= current->segment->start) {
            size_t size = current->segment->size;
            size_t len = get_length(size, align);
            size_t index = (source - current->segment->start) / align;
            if (index < len) {
                return current;
            }
        }
        current = current->next;
    }
    return NULL;
}

/**
 * Add the given segment to the LinkedList of segments of the given transaction. This function also allocated the
 * necessary data structure which link a segment to a read/write set.
 * @param shared The region of the transactional memory
 * @param txn The transaction
 * @param s The segment
 * @return True if the segment is added correctly else False
 */
bool add_segment_to_txn(shared_t shared, transaction* txn, segment* s) {
    size_t align = tm_align(shared);
    rw_set* set = txn->read_write_set;

    rw_set* new_set = malloc(sizeof(struct _rw_set));
    if (new_set == NULL) {
        return false;
    }
    // Fill new rw_set
    new_set->next = set;
    txn->read_write_set = new_set;
    new_set->to_remove = false;
    new_set->segment = s;
    if (!txn->read_only) {
        size_t len = get_length(s->size, align);
        new_set->was_read = calloc(len, sizeof(bool));
        if (new_set->was_read == NULL) {
            safe_free(new_set->updated_value);
            safe_free(new_set);
            //set->next = NULL;
            txn->read_write_set = set;
            return false;
        }
        new_set->updated_value = calloc(len, sizeof(void *));
        if (new_set->updated_value == NULL) {
            safe_free(new_set);
            txn->read_write_set = set;
            //set->next = NULL;
            return false;
        }
    }
    return true;
}
