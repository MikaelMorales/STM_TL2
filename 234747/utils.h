/**
 * @file   utils.h
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
 *
 * Utility methods used throughout the software transactional memory implementation
**/
#pragma once

#include <tm.h>
#include "stm_structures.h"

void safe_free(void* ptr);
void free_txn(tx_t tx, shared_t shared);
void remove_alloc_segment(struct _segment* s);
void append_alloc_segment(struct _segment* s, struct _segment* base);
void prepend_alloc_segment(struct _segment* s, struct _segment* base);
bool add_segment_to_txn(shared_t shared, transaction* txn, segment* s);
size_t get_nb_segments_region(shared_t shared);
size_t get_segment_start_pos(shared_t shared, void const* source, segment* s);
size_t get_length(size_t size, size_t alignment);
rw_set* get_rw_set(shared_t shared, void const* source, transaction* tx);
