# ⚡ HTPPS Zero-Copy — Memory-Safe High-Performance HTTP Server

A fork of [HTPPS](https://github.com/AmritRai1234/htpps) with a **zero-copy shared memory architecture** and hardened memory safety.

## What's Different

The original HTPPS copies data 6 times per request. This version cuts it to 4 by sharing a single buffer between the HTTP layer, JS engine, and file server:

```
OLD: recv → recv_buf → parse → disk → file_buf → file_buf → send_buf → send
NEW: recv → recv_buf → parse → disk → send_buf → send  (body written in-place)
```

### Zero-Copy Architecture

```c
g_send_buf:
┌───────────────────┬──────────────────────────────────┐
│ HTTP headers      │ Body (file or JS output)         │
│ (pre-built)       │ (written DIRECTLY here)          │
└───────────────────┴──────────────────────────────────┘
                    ↑
                    JS engine & fread() write here
                    No intermediate buffer. No memcpy.
```

### Memory Safety Hardening

Every request gets:
- **Buffer wiping** — `memset(0)` on recv + send buffers between clients
- **NULL checks** on all pointer params
- **Bounds checking** on all buffer writes
- **Secure free** — TLS buffers wiped before `free()` to prevent data recovery
- **Pointer nulling** — dangling pointers set to NULL after free

## Benchmarks vs Nginx

50,000 requests, concurrency 100 (same machine, same files):

| Metric | HTPPS Zero-Copy | Nginx 1.26 |
|---|---|---|
| **Throughput** | 20,791 req/s | 21,484 req/s |
| **p99 latency** | **6ms** ✅ | 10ms |
| **Kernel CPU** | **128 ticks** ✅ | 172 ticks |
| **Memory safety** | **Full wipe** ✅ | No buffer clearing |
| **Failed requests** | 0 | 0 |

**40% better tail latency. 26% less kernel CPU. Full memory isolation between clients.**

## Build & Run

```bash
make                          # Build
./server-zc --http            # HTTP on port 8080
./server-zc --http --http-port 9096  # Custom port
make test                     # Run crypto tests
```

## Full Feature List

Everything from the original HTPPS, plus:
- ✅ Zero-copy file serving (fread → send buffer directly)
- ✅ Zero-copy JS API routes (JS output → send buffer directly)
- ✅ Pre-built HTTP headers with patchable Content-Length
- ✅ No `file_buf` allocation (eliminated 512KB buffer)
- ✅ Hardened pointer safety and bounds checking
- ✅ Secure buffer wiping between requests
- ✅ AES-NI, SHA-NI, JIT syscalls (inherited from HTPPS)

## License

MIT
