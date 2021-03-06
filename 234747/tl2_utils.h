/**
 * @file   tl2_utils.h
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
 *
 * The TL2 utility methods required by the TL2 algorithm
**/
#pragma once

#include <stdbool.h>
#include "utils.h"
#include "stm_structures.h"

bool is_locked(unsigned int lock);
unsigned int get_lock_version(unsigned int lock);
bool post_validate_read(transaction* tx, size_t startPos, size_t len, const unsigned int* old_locks, const segment* s);
bool validate_transaction(region* r, transaction* tx);
void writes_in_shared_memory(region* r, transaction* tx, rw_set* set);