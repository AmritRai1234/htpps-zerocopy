/*
 * fast_io.h — Direct Syscall I/O & SIMD Helpers
 * ============================================================================
 * Bypass libc entirely for hot-path I/O. Instead of going through:
 *   your code → libc send() → PLT → GOT → syscall
 * We go:
 *   your code → syscall instruction → kernel
 *
 * Also provides SSE2-accelerated memory scanning for HTTP parsing.
 * ============================================================================
 */

#ifndef FAST_IO_H
#define FAST_IO_H

#include <stddef.h>
#include <stdint.h>

/* Direct syscall wrappers — no libc overhead */
extern int64_t fast_recv(int fd, void *buf, size_t len);
extern int64_t fast_send(int fd, const void *buf, size_t len);
extern void    fast_close(int fd);
extern int     fast_accept(int server_fd, void *addr, void *addrlen);

/* SSE2-accelerated byte scan — 16 bytes at a time */
extern void   *fast_memchr(const void *s, int c, size_t n);

#endif /* FAST_IO_H */
