/**
 * @file   tl2_utils.h
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
**/
#pragma once

#include <stdbool.h>
#include "utils.h"
#include "stm_structures.h"

bool is_locked(unsigned int lock);
unsigned int extract_version(unsigned int lock);
bool post_validate_read(transaction* tx, size_t index, size_t nb_items, const unsigned int* old_locks, const segment* s);
bool check_read_set(region* r, transaction* tx, rw_set* set);
bool validate_transaction(region* r, transaction* tx);
void release_write_set_locks(rw_set* set, size_t n);
void writes_in_shared_memory(region* r, transaction* tx, rw_set* set);
bool lock_write_set_locks(region* r, rw_set* set);