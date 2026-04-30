/*
 * arena.h — Arena Memory Allocator
 * ============================================================================
 * Instead of calling malloc() for every tiny AST node (slow!),
 * we allocate ONE big chunk and hand out pieces of it.
 *
 *   malloc:  1000 nodes = 1000 syscalls = SLOW
 *   arena:   1000 nodes = 1 syscall    = FAST
 *
 * Free everything at once when done — no individual free() calls.
 * ============================================================================
 */

#ifndef JS_ARENA_H
#define JS_ARENA_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ARENA_BLOCK_SIZE (64 * 1024)  /* 64KB blocks */

typedef struct ArenaBlock {
    uint8_t *data;
    size_t   used;
    size_t   capacity;
    struct ArenaBlock *next;
} ArenaBlock;

typedef struct {
    ArenaBlock *head;
    ArenaBlock *current;
} Arena;

static inline ArenaBlock *arena_new_block(size_t size) {
    ArenaBlock *b = (ArenaBlock *)malloc(sizeof(ArenaBlock));
    b->data = (uint8_t *)malloc(size);
    b->used = 0;
    b->capacity = size;
    b->next = NULL;
    return b;
}

static inline void arena_init(Arena *a) {
    a->head = arena_new_block(ARENA_BLOCK_SIZE);
    a->current = a->head;
}

/* Allocate from arena — NO SYSCALL if space available */
static inline void *arena_alloc(Arena *a, size_t size) {
    /* Align to 8 bytes for performance */
    size = (size + 7) & ~(size_t)7;

    if (a->current->used + size > a->current->capacity) {
        /* Need new block */
        size_t block_size = size > ARENA_BLOCK_SIZE ? size : ARENA_BLOCK_SIZE;
        ArenaBlock *b = arena_new_block(block_size);
        a->current->next = b;
        a->current = b;
    }

    void *ptr = a->current->data + a->current->used;
    a->current->used += size;
    memset(ptr, 0, size);
    return ptr;
}

/* Duplicate a string into the arena */
static inline char *arena_strdup(Arena *a, const char *s) {
    size_t len = strlen(s) + 1;
    char *copy = (char *)arena_alloc(a, len);
    memcpy(copy, s, len);
    return copy;
}

/* Free EVERYTHING at once — one call destroys all allocations */
static inline void arena_destroy(Arena *a) {
    ArenaBlock *b = a->head;
    while (b) {
        ArenaBlock *next = b->next;
        free(b->data);
        free(b);
        b = next;
    }
    a->head = NULL;
    a->current = NULL;
}

#endif /* JS_ARENA_H */
