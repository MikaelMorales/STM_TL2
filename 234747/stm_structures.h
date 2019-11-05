/**
 * @file   stm_structures.h
 * @author Morales Gonzalez Mikael <mikael.moralesgonzalez@epfl.ch>
**/
#pragma once

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * Data structure representing a segment. This also represent a node in a LinkedList.
 */
typedef struct _segment {
    void* start;
    volatile size_t size;
    struct _segment* next;
    struct _segment* prev;
    atomic_uint ref_count;
    volatile bool is_new;
    volatile bool removed; // Defines if segment is already removed from region LinkedList
    atomic_uint* versioned_locks; // Versioned locks in TL2
} segment;

/**
 * Data structure representing a Read/Write set. This also represent a node in a LinkedList.
 * Each Read/Write set of the LinkedList has access to its associated segment.
 */
typedef struct _rw_set {
    segment* segment; // Corresponding segment of this read-write-set
    bool to_remove; // Mark the segment as to be removed from global list
    bool* was_read; // List of boolean values init to false, true if read
    void** updated_value; // List of pointer to new values, NULL if not written
    struct _rw_set* next; // Pointer to a possible next rw_set associated with this tx
} rw_set;

/**
 * Data structure representing a transcation, with the necessary argument to execute TL2 algorithm.
 */
typedef struct _transaction {
    bool read_only;
    unsigned int rv;
    unsigned int vw;
    rw_set* read_write_set; // LinkedList of read_write set corresponding to the segments modified
} transaction;

/**
 * Data structure representing the single region of the transactional memory.
 */
typedef struct _region {
    atomic_uint segments_lkd_lock; // Lock on LinkedList of segment to ensure sync.
    atomic_uint free_lkd_lock; // Lock on free list of segment that needs to be free
    volatile size_t align;
    volatile size_t align_alloc;
    atomic_uint global_version_clock; // Global version clock of TL2 algorithm
    segment first_segment;
} region;