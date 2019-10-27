/**
 * @file   utils.c
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
**/
// External headers
#define NDEBUG
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

// Internal headers
#include "utils.h"

void safe_free(void* ptr) {
    free(ptr);
    ptr = NULL;
}

void remove_alloc_segment(struct _segment* s) {
    assert(s != NULL);
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

void append_alloc_segment(struct _segment* s, struct _segment* base) {
    segment* last = base;
    while (last->next != NULL) {
        last = last->next;
    }

    last->next = s;
    s->prev = last;
    s->next = NULL;
}

size_t get_segment_index(shared_t shared, void const* source, segment* s) {
    size_t alignment = tm_align(shared);
    size_t start_index = (source - s->start) / alignment;
    return start_index;
}

size_t get_nb_items(size_t size, size_t alignment) {
    return size / alignment;
}

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

void free_transaction(tx_t tx, shared_t shared) {
    transaction * txn = (transaction *) tx;
    rw_set* current = txn->read_write_set;
    while (current != NULL) {
        if (!txn->read_only) {
            size_t size = current->segment->size;
            size_t align = tm_align(shared);
            size_t nb_items = get_nb_items(size, align);
            for (size_t i=0; i < nb_items; i++) {
                if(current->updated_value[i] != NULL) {
                    safe_free(current->updated_value[i]);
                }
            }
            safe_free(current->was_read);
            safe_free(current->updated_value);

        }
        // Decrease ref count of this segment
        atomic_fetch_add(&current->segment->ref_count, -1);

        // Free local segments. No need to lock, since this segment is not sync in the region
        if (current->segment->is_new) {
            free(current->segment->versions_locks);
            free(current->segment->start);
            free(current->segment);
        }
        rw_set* next = current->next;
        safe_free(current);
        current = next;
    }
    free((void*)tx);
}

rw_set* get_rw_set(shared_t shared, void const* source, transaction* tx) {
    rw_set* current = tx->read_write_set;
    size_t align = tm_align(shared);
    while (current != NULL) {
        if (source >= current->segment->start) {
            size_t size = current->segment->size;
            size_t nb_items = get_nb_items(size, align);
            size_t index = (source - current->segment->start) / align;
            if (index < nb_items) {
                return current;
            }
        }
        current = current->next;
    }
    return NULL;
}

bool add_segment_to_txn(shared_t shared, transaction* txn, segment* s) {
    size_t align = tm_align(shared);
    rw_set* set = txn->read_write_set;
    while(set->next != NULL) {
        set = set->next;
    }

    rw_set* new_set = malloc(sizeof(struct _rw_set));
    if (new_set == NULL) {
        return false;
    }
    // Fill new rw_set
    set->next = new_set;
    new_set->to_remove = false;
    new_set->segment = s;
    new_set->next = NULL;
    if (!txn->read_only) {
        size_t nb_items = get_nb_items(s->size, align);
        new_set->updated_value = calloc(nb_items, sizeof(void *));
        if (new_set->updated_value == NULL) {
            safe_free(new_set);
            set->next = NULL;
            return false;
        }
        new_set->was_read = calloc(nb_items, sizeof(bool));
        if (new_set->was_read == NULL) {
            safe_free(new_set->updated_value);
            safe_free(new_set);
            set->next = NULL;
            return false;
        }
        for (size_t item=0; item < nb_items; item++) {
            new_set->was_read[item] = false;
            new_set->updated_value[item] = NULL;
        }
    }
    return true;
}
