/*
 * tcp.c — Raw TCP Socket Implementation
 * ============================================================================
 * This file talks directly to the Linux kernel via system calls.
 * Every function here wraps a kernel syscall that manipulates network sockets.
 *
 * The headers we include are NOT external libraries — they're part of POSIX,
 * the standard interface that every Unix-like OS provides. They're as "standard"
 * as stdio.h, just for networking instead of file I/O.
 * ============================================================================
 */

#include "tcp.h"

#include <stdio.h>       /* perror() — prints human-readable error messages */
#include <string.h>      /* memset() */
#include <unistd.h>      /* close() — yes, closing a socket uses the same close() as files */

/*
 * These are the POSIX networking headers. They define:
 *   - socket(), bind(), listen(), accept() — the socket API
 *   - struct sockaddr_in — the "address" struct (IP + port)
 *   - htons() — host-to-network byte order conversion
 *   - inet_ntop() — convert binary IP to string like "192.168.1.1"
 */
#include <sys/socket.h>  /* socket(), bind(), listen(), accept(), send(), recv() */
#include <netinet/in.h>  /* struct sockaddr_in, INADDR_ANY, htons() */
#include <arpa/inet.h>   /* inet_ntop() — binary IP → string */

int tcp_listen(uint16_t port)
{
    /*
     * STEP 1: Create the socket
     *
     * socket(domain, type, protocol)
     *   - AF_INET    = IPv4 (Address Family: Internet)
     *   - SOCK_STREAM = TCP (reliable, ordered byte stream)
     *                   vs SOCK_DGRAM = UDP (unreliable datagrams)
     *   - 0          = let the OS pick the protocol (TCP for SOCK_STREAM)
     *
     * Returns a file descriptor (small integer), or -1 on error.
     */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket()");
        return -1;
    }

    /*
     * STEP 1.5: Set SO_REUSEADDR
     *
     * Without this, if you kill the server and restart it immediately,
     * bind() will fail with "Address already in use" because the OS keeps
     * the port reserved for ~60 seconds (TIME_WAIT state).
     *
     * SO_REUSEADDR says "I know, let me bind anyway."
     * Every server in existence sets this option.
     */
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(server_fd);
        return -1;
    }

    /*
     * STEP 2: Bind to an address (IP + port)
     *
     * struct sockaddr_in is the IPv4 address structure:
     *   - sin_family = AF_INET (must match what we passed to socket())
     *   - sin_addr   = which IP to listen on
     *                   INADDR_ANY (0.0.0.0) = all interfaces
     *   - sin_port   = which port, in NETWORK BYTE ORDER
     *
     * BYTE ORDER MATTERS:
     *   Your CPU (x86) is little-endian: stores least-significant byte first.
     *   Network protocols use big-endian: most-significant byte first.
     *   htons() = "Host TO Network Short" — swaps bytes if needed.
     *   Port 8080 = 0x1F90 → htons → 0x901F on x86.
     */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;   /* 0.0.0.0 — listen on all interfaces */
    addr.sin_port        = htons(port);  /* convert port to network byte order */

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind()");
        close(server_fd);
        return -1;
    }

    /*
     * STEP 3: Start listening
     *
     * listen(fd, backlog)
     *   - backlog = how many pending connections the OS will queue up
     *     before refusing new ones. 128 is a typical value.
     *   - After this call, the OS will accept TCP SYN packets on this port
     *     and complete the TCP three-way handshake automatically.
     *   - But the connections sit in a queue until YOU call accept().
     */
    if (listen(server_fd, 128) < 0) {
        perror("listen()");
        close(server_fd);
        return -1;
    }

    printf("[TCP] Listening on port %u (fd=%d)\n", port, server_fd);
    return server_fd;
}

int tcp_accept(int server_fd, char *client_ip, size_t ip_buf_len)
{
    /*
     * accept() blocks until a client connects, then returns a NEW fd
     * for that specific client.
     *
     * It also fills in the client's address (IP + port) so we can log it.
     *
     * The cast to (struct sockaddr *) is required because accept() uses
     * a generic address type that works for both IPv4 and IPv6.
     */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept()");
        return -1;
    }

    /*
     * Convert the client's binary IP address to a human-readable string.
     * inet_ntop = "Internet Network TO Presentation"
     * e.g., 0x7F000001 → "127.0.0.1"
     */
    if (client_ip && ip_buf_len > 0) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, (socklen_t)ip_buf_len);
    }

    return client_fd;
}

int tcp_send(int fd, const void *buf, size_t len)
{
    /*
     * WHY WE LOOP:
     *
     * send() is not guaranteed to send all your bytes at once.
     * If you ask to send 10000 bytes, the kernel's send buffer might only
     * have room for 4096 right now. send() returns 4096, meaning
     * "I sent 4096 bytes, you deal with the rest."
     *
     * So we loop: send what we can, advance the pointer, repeat.
     * This is a pattern you'll see in literally every network program.
     */
    size_t total_sent = 0;
    const char *ptr = (const char *)buf;

    while (total_sent < len) {
        ssize_t sent = send(fd, ptr + total_sent, len - total_sent, 0);
        if (sent < 0) {
            perror("send()");
            return -1;
        }
        if (sent == 0) {
            /* Shouldn't happen on a blocking socket, but be safe */
            break;
        }
        total_sent += (size_t)sent;
    }

    return (int)total_sent;
}

int tcp_recv(int fd, void *buf, size_t len)
{
    /*
     * recv() returns:
     *   > 0  = number of bytes received
     *   = 0  = client disconnected (sent FIN packet)
     *   < 0  = error
     *
     * We DON'T loop here because the caller needs to decide when they've
     * received a complete message. For HTTP, that means parsing headers
     * to find Content-Length or detecting the end of headers (\r\n\r\n).
     */
    ssize_t received = recv(fd, buf, len, 0);
    if (received < 0) {
        perror("recv()");
        return -1;
    }
    return (int)received;
}

void tcp_close(int fd)
{
    /*
     * close() releases the file descriptor back to the OS.
     * This also sends a TCP FIN to the remote end, starting the
     * connection teardown (the "four-way handshake" — yes, closing
     * is more complex than opening in TCP).
     */
    close(fd);
}
