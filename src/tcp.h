/*
 * tcp.h — Raw TCP Socket Layer
 * ============================================================================
 * This is the absolute bottom of our stack. Everything else sits on top of this.
 *
 * HOW SOCKETS WORK (the 30-second version):
 * 
 *   1. socket()  — Ask the OS for a file descriptor (an integer handle) that
 *                   represents a network endpoint. Think of it like opening a
 *                   file, but for network I/O instead of disk I/O.
 *
 *   2. bind()    — Attach that socket to a specific port on this machine.
 *                   "I want to listen on port 8080."
 *
 *   3. listen()  — Tell the OS we're ready to accept incoming connections.
 *                   The OS maintains a queue of pending connections for us.
 *
 *   4. accept()  — Block (wait) until a client connects. Returns a NEW file
 *                   descriptor for that specific client connection. The original
 *                   socket keeps listening for more clients.
 *
 *   5. read()/write() — Send and receive raw bytes on the client fd.
 *                       At this level, there's no concept of HTTP, TLS, or
 *                       anything — just raw bytes going back and forth.
 *
 *   6. close()   — Done with the connection, release the fd.
 *
 * IMPORTANT CONCEPT — File Descriptors:
 *   In Unix/Linux, EVERYTHING is a file descriptor (fd). A socket is just an
 *   integer (like 3, 4, 5...) that the OS uses to track your open connections.
 *   0 = stdin, 1 = stdout, 2 = stderr, and everything after that is yours.
 * ============================================================================
 */

#ifndef TCP_H
#define TCP_H

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */

/*
 * tcp_listen — Create a server socket and start listening on a port.
 *
 * This does THREE things in one call:
 *   1. Creates a TCP socket (SOCK_STREAM = reliable, ordered byte stream)
 *   2. Binds it to 0.0.0.0:<port> (all network interfaces)
 *   3. Starts listening with a connection backlog queue
 *
 * Returns: server file descriptor on success, -1 on failure.
 *
 * The returned fd is NOT for talking to clients — it's the "front door"
 * that accepts new connections. Each client gets their own fd via tcp_accept().
 */
int tcp_listen(uint16_t port);

/*
 * tcp_accept — Wait for and accept a new client connection.
 *
 * This BLOCKS (pauses your program) until a client connects.
 * When a client connects, the OS creates a new socket just for that client
 * and returns its fd.
 *
 * Think of it like a restaurant host: the server_fd is the front door,
 * and each accepted client gets seated at their own table (their own fd).
 *
 * @param server_fd: The listening socket from tcp_listen()
 * @param client_ip: Buffer to store the client's IP address string (optional, can be NULL)
 * @param ip_buf_len: Size of the client_ip buffer
 *
 * Returns: client file descriptor on success, -1 on failure.
 */
int tcp_accept(int server_fd, char *client_ip, size_t ip_buf_len);

/*
 * tcp_send — Send raw bytes to a connected client.
 *
 * IMPORTANT: send() might not send ALL your bytes in one call!
 * If you try to send 1000 bytes, the OS might only send 500 and return 500.
 * This wrapper loops until all bytes are sent (or an error occurs).
 * This is called a "full write" or "write loop."
 *
 * Returns: total bytes sent, or -1 on error.
 */
int tcp_send(int fd, const void *buf, size_t len);

/*
 * tcp_recv — Receive raw bytes from a connected client.
 *
 * Unlike tcp_send, we DON'T loop here — we return whatever the OS gives us.
 * The caller is responsible for knowing when they've received a complete message.
 * (For HTTP, that means parsing headers to find Content-Length, etc.)
 *
 * Returns: bytes received, 0 if client disconnected, -1 on error.
 */
int tcp_recv(int fd, void *buf, size_t len);

/*
 * tcp_close — Close a connection and release the file descriptor.
 *
 * After this, the fd number can be reused by the OS for a new connection.
 * Always close fds when done, otherwise you'll leak them (like a memory leak
 * but for OS resources).
 */
void tcp_close(int fd);

#endif /* TCP_H */
