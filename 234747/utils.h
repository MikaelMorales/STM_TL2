/**
 * @file   utils.h
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
**/
#pragma once

#include <tm.h>
#include "stm_structures.h"

void safe_free(void* ptr);
size_t get_segment_index(shared_t shared, void const* source, segment* s);
size_t get_nb_items(size_t size, size_t alignment);
void remove_alloc_segment(struct _segment* s);
void append_alloc_segment(struct _segment* s, struct _segment* base);
size_t get_nb_segments_region(shared_t shared);
void free_transaction(tx_t tx, shared_t shared);
rw_set* get_rw_set(shared_t shared, void const* source, transaction* tx);
bool add_segment_to_txn(shared_t shared, transaction* txn, segment* s);