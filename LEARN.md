# Learning from the C FTP Project

This document provides a detailed explanation of the concepts, design, and implementation details used in this minimal FTP-like server and client project written in C.

## 1. Socket Programming Fundamentals

Sockets are the fundamental mechanism for network communication between processes, potentially across different machines. This project uses the **Berkeley Sockets API**, a standard interface available on most Unix-like systems (Linux, macOS) and Windows (Winsock).

### Key Concepts:

*   **Socket**: An endpoint for communication. Think of it like a file descriptor, but for network connections. It's identified by an IP address and a port number.
*   **TCP (Transmission Control Protocol)**: A connection-oriented, reliable, stream-based protocol.
    *   **Connection-Oriented**: A connection must be established before data transfer (like a phone call).
    *   **Reliable**: Guarantees that data arrives in order and without errors (using acknowledgments and retransmissions).
    *   **Stream-Based**: Data is treated as a continuous stream of bytes, without inherent message boundaries.
*   **IP (Internet Protocol)**: Responsible for addressing and routing packets across networks.
*   **Port**: A number (0-65535) used to identify a specific process or service on a host machine. Ports 0-1023 are "well-known" ports often requiring root privileges. This project uses higher ports (like 2121) to avoid needing root.
*   **Client-Server Model**:
    *   **Server**: Listens for incoming connections on a specific port.
    *   **Client**: Initiates a connection to the server's IP address and port.

### Socket API Functions Used:

1.  **`socket(domain, type, protocol)`**: Creates a new socket.
    *   `domain`: `AF_INET` (for IPv4 internet protocols).
    *   `type`: `SOCK_STREAM` (for TCP, providing sequenced, reliable, two-way connection-based byte streams).
    *   `protocol`: `0` (usually lets the system choose the appropriate protocol for the type, which is TCP for `SOCK_STREAM`).
    *   *Returns*: A socket file descriptor (an integer) or -1 on error.

2.  **`bind(sockfd, addr, addrlen)`**: Assigns a local address (IP address and port) to a socket. Typically used by the server.
    *   `sockfd`: The socket file descriptor returned by `socket()`.
    *   `addr`: A pointer to a `struct sockaddr` containing the address (IP and port). For IPv4, a `struct sockaddr_in` is used and cast.
        *   `sin_family`: `AF_INET`.
        *   `sin_port`: The port number (must be in network byte order, use `htons()` - Host TO Network Short).
        *   `sin_addr.s_addr`: The IP address (e.g., `INADDR_ANY` to listen on all available network interfaces, or a specific IP). Must be in network byte order (use `htonl()` - Host TO Network Long, though `INADDR_ANY` is often pre-defined correctly).
    *   `addrlen`: The size of the address structure.
    *   *Returns*: 0 on success, -1 on error.

3.  **`listen(sockfd, backlog)`**: Marks the socket as a passive socket, one that will be used to accept incoming connection requests. Used only by the server.
    *   `sockfd`: The bound socket file descriptor.
    *   `backlog`: The maximum length of the queue for pending connections. If the queue is full, new connection attempts might be rejected.
    *   *Returns*: 0 on success, -1 on error.

4.  **`accept(sockfd, addr, addrlen)`**: Extracts the first connection request on the queue of pending connections for the listening socket (`sockfd`), creates a *new* connected socket, and returns its file descriptor. Used only by the server.
    *   `sockfd`: The listening socket file descriptor.
    *   `addr`: A pointer to a `struct sockaddr` (usually `struct sockaddr_in`) that will be filled with the address of the connecting client. Can be `NULL` if you don't need the client's address.
    *   `addrlen`: A pointer to a `socklen_t` initially holding the size of `addr`, which gets updated by the call to the actual size of the client address.
    *   *Returns*: A *new* socket file descriptor for the established connection, or -1 on error. The original listening socket (`sockfd`) remains open and listening for more connections. **All communication with this specific client happens on the new socket.**

5.  **`connect(sockfd, addr, addrlen)`**: Establishes a connection to a server. Used only by the client.
    *   `sockfd`: The client's socket file descriptor (created with `socket()`).
    *   `addr`: A pointer to a `struct sockaddr` containing the *server's* address (IP and port).
    *   `addrlen`: The size of the server address structure.
    *   *Returns*: 0 on success, -1 on error.

6.  **`send(sockfd, buf, len, flags)`**: Sends data on a connected socket.
    *   `sockfd`: The connected socket file descriptor (either the client's socket or the one returned by `accept()` on the server).
    *   `buf`: Pointer to the buffer containing data to send.
    *   `len`: Number of bytes to send from the buffer.
    *   `flags`: Usually `0`. Can be used for options like `MSG_NOSIGNAL` (prevents `SIGPIPE` signal if the connection is broken).
    *   *Returns*: The number of bytes actually sent, or -1 on error. (Note: It might send fewer bytes than requested, requiring loop logic for large sends, though less common with TCP than UDP).

7.  **`recv(sockfd, buf, len, flags)`**: Receives data from a connected socket.
    *   `sockfd`: The connected socket file descriptor.
    *   `buf`: Pointer to the buffer where received data will be stored.
    *   `len`: Maximum number of bytes to receive into the buffer.
    *   `flags`: Usually `0`.
    *   *Returns*: The number of bytes received, 0 if the peer has closed the connection gracefully, or -1 on error.

8.  **`close(sockfd)`**: Closes a socket file descriptor, releasing associated resources.

9.  **`setsockopt(sockfd, level, optname, optval, optlen)`**: Sets socket options. Used in this project for:
    *   `SO_REUSEADDR`: Allows the server to bind to a port even if it's in the `TIME_WAIT` state from a previous run, speeding up restarts during development.
    *   `SO_RCVTIMEO` / `SO_SNDTIMEO`: Set timeouts for receive and send operations to prevent the program from blocking indefinitely if the network or the peer stalls.

10. **`getsockname(sockfd, addr, addrlen)`**: Gets the local address (IP and port) bound to a socket. Used by the server in passive mode to find its own IP address and the ephemeral port assigned by `bind()` for the data connection.

11. **`inet_ntoa()` / `inet_ntop()`**: Convert IP addresses from binary network format to human-readable string format (e.g., "127.0.0.1"). `inet_ntop` is more modern and supports IPv6.
12. **`inet_pton()`**: Convert IP addresses from human-readable string format to binary network format.
13. **`htons()` / `htonl()`**: Convert values between host byte order and network byte order (which is Big Endian). Necessary for port numbers and IP addresses in socket address structures.

## 2. Computer Network Concepts Applied

*   **TCP/IP**: The project relies entirely on TCP for reliable communication and IP for addressing.
*   **Client-Server Architecture**: A standard model where the server waits for requests and the client initiates them.
*   **Ports**: The server listens on a specific port (e.g., 2121), and the client connects to that port. For data transfers (Passive Mode), the server listens on a *temporary* (ephemeral) port chosen by the OS.
*   **IP Addresses**: The client needs the server's IP address to connect. The server uses `INADDR_ANY` to accept connections on any of its network interfaces. For Passive Mode, the server needs to tell the client *which* of its IP addresses the client should connect to for the data transfer (handled somewhat simplistically by `get_local_ip` in this project).
*   **Control Connection vs. Data Connection**: This is a core concept in protocols like FTP.
    *   **Control Connection**: The initial connection established between client and server (on port 2121 in this project). Used for sending commands (e.g., `SLS`, `UP`, `DOWN`) and receiving status responses (e.g., `200`, `550`, `227`). This connection stays open for the duration of the session.
    *   **Data Connection**: A *separate*, temporary connection established *only* when file contents or directory listings need to be transferred. This project uses **Passive Mode (PASV)**:
        1.  Client sends a command requiring data transfer (e.g., `UP filename`, `DOWN filename`, `SLS`).
        2.  Server receives the command.
        3.  Server creates a *new* listening socket on an ephemeral port (using `bind` with port 0).
        4.  Server sends a `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` response back to the client over the *control connection*. `h1-h4` represent the server's IP address, and `p1,p2` represent the ephemeral port number (`port = p1*256 + p2`).
        5.  Client receives the `227` response, parses the IP and port.
        6.  Client initiates a *new* TCP connection (the data connection) to the server's specified IP and ephemeral port.
        7.  Server `accept`s this incoming data connection.
        8.  Server sends a `150` status code over the *control connection* indicating it's ready for transfer.
        9.  The actual file data or directory listing is transferred over the *data connection*.
        10. Once the transfer is complete, *both* client and server close the *data connection*.
        11. Server sends a final status code (`226 Transfer complete`) over the *control connection*.
        12. The control connection remains open for further commands.
*   **FTP Response Codes**: The server communicates status back to the client using 3-digit numeric codes (defined in RFC 959). This project uses a subset:
    *   `2xx` (Positive Completion): `200` (OK), `220` (Service ready - though commented out), `221` (Goodbye), `226` (Transfer complete), `227` (Entering Passive Mode).
    *   `1xx` (Positive Intermediate): `150` (File status okay; about to open data connection).
    *   `4xx` (Transient Negative Completion): `421` (Service not available, closing connection), `425` (Can't open data connection), `426` (Connection closed; transfer aborted).
    *   `5xx` (Permanent Negative Completion): `500` (Syntax error/Internal error), `502` (Command not implemented), `550` (Requested action not taken - e.g., file unavailable, permission error), `553` (Path/Filename invalid).

## 3. Directory and File Operations

Standard C library and POSIX functions are used to interact with the filesystem on both the client and server sides.

*   **Changing Directory (`SCD`, `CCD`)**:
    *   `chdir(path)`: Changes the current working directory of the *calling process* to `path`. Used by the server for `SCD` and the client for `CCD`.
    *   `getcwd(buf, size)`: Gets the pathname of the current working directory and stores it in `buf`. Used by the server (`SLS`) and client (`CCD`, `CLS`) to display the current path.

*   **Listing Directory Contents (`SLS`, `CLS`)**:
    *   `opendir(name)`: Opens a directory stream corresponding to the directory `name` (e.g., "." for the current directory). Returns a `DIR *` pointer.
    *   `readdir(dirp)`: Reads the next directory entry from the directory stream `dirp`. Returns a pointer to a `struct dirent` containing the entry's name (`d_name`) or `NULL` at the end or on error.
    *   `closedir(dirp)`: Closes the directory stream.
    *   `stat(pathname, &statbuf)` / `lstat()`: Retrieves information about the file pointed to by `pathname` and stores it in a `struct stat` (`statbuf`). Used to determine if a directory entry is a file or a subdirectory.
        *   `S_ISDIR(statbuf.st_mode)`: Macro that returns true if the `st_mode` field indicates a directory.
    *   The code iterates through entries using `readdir`, uses `stat` to check the type, formats the name (adding `/` for directories), and sends/prints the list.

*   **File Transfer (`UP`, `DOWN`)**:
    *   `fopen(filename, mode)`: Opens a file.
        *   `"rb"`: Read Binary mode (for downloading from server or uploading from client).
        *   `"wb"`: Write Binary mode (for uploading to server or downloading to client). Binary mode is crucial to handle files containing non-text data correctly without newline translation issues.
    *   `fread(ptr, size, nmemb, stream)`: Reads `nmemb` items of data, each `size` bytes long, from the `stream` into the buffer pointed to by `ptr`. Used by the server for `DOWN` and the client for `UP`.
    *   `fwrite(ptr, size, nmemb, stream)`: Writes `nmemb` items of data, each `size` bytes long, to the `stream` from the buffer pointed to by `ptr`. Used by the server for `UP` and the client for `DOWN`.
    *   `fclose(stream)`: Closes the file stream.
    *   `ferror(stream)`: Checks the error indicator for the given stream. Used after `fread` loop to detect read errors.

## 4. System Design

The project employs a simple, iterative design suitable for learning.

*   **Server Design**:
    *   **Iterative (Single-Threaded)**: The server handles one client connection completely before accepting the next one. The `accept()` call blocks until a client connects, and then `handle_client()` runs until that client disconnects or sends `QUIT`.
    *   **Blocking I/O**: All socket operations (`accept`, `recv`, `send`) and file operations (`fread`, `fwrite`) are blocking. This means the server process waits until the operation completes before continuing. This simplifies the code significantly compared to non-blocking I/O or multi-threading/multi-processing, but it means the server cannot handle other clients while busy with one (especially during long file transfers).
    *   **Passive Mode Only**: Simplifies implementation by avoiding the complexities of Active Mode FTP (where the *server* connects back to the *client* for data transfers, often problematic with firewalls/NAT).
    *   **Basic Command Parsing**: Uses `strncmp` to identify commands. Arguments (like filenames/paths) are extracted by simple pointer arithmetic after the command keyword.
    *   **Error Handling**: Uses return values of system/library calls and `perror()` to detect and report errors. Sends appropriate FTP error codes (`4xx`, `5xx`) to the client. Includes basic path validation (`strstr(path, "..")`) as a minimal security measure against directory traversal.
    *   **Signal Handling**: Catches `SIGINT` / `SIGTERM` to attempt a slightly more graceful shutdown by closing the main listening socket.
    *   **Timeouts**: Uses `setsockopt` with `SO_RCVTIMEO` / `SO_SNDTIMEO` on both control and data sockets to prevent indefinite blocking if a client becomes unresponsive.

*   **Client Design**:
    *   **Interactive**: Reads commands from standard input (`fgets`).
    *   **Local vs. Remote Commands**: Distinguishes between commands handled locally (`CLS`, `CCD`) and those sent to the server.
    *   **State Management**: Implicitly manages the state required for multi-step operations like `UP` and `DOWN` (waiting for `227`, connecting data port, waiting for `150`, transferring data, waiting for `226`).
    *   **Error Handling**: Checks return codes, uses `perror`, prints server error messages, and handles timeouts. Includes basic local path validation.
    *   **Signal Handling**: Catches `SIGINT` to try and send `QUIT` before exiting.

## 5. End-to-End Understanding

*   **Goal**: To create a minimal, functional client-server application demonstrating core network programming concepts (TCP sockets, client-server model, basic protocol implementation) and file system interaction in C. It mimics some basic features of the File Transfer Protocol (FTP).
*   **Why C?**: C provides low-level access to the sockets API and system calls, making it ideal for understanding the underlying mechanisms of network communication and OS interaction.
*   **Why TCP?**: Chosen for its reliability, which is essential for file transfers where data integrity is paramount.
*   **Why Passive Mode?**: Easier to implement and works better in modern network environments with firewalls and NAT compared to FTP's Active Mode.
*   **Development Phases**: The `README.md` outlines a phased approach, starting with the basic connection, adding directory operations, then file transfers, and finally robustness features (error handling, timeouts, signals). This iterative development makes the project manageable and allows focusing on specific concepts at each stage.
*   **Limitations & Simplifications**:
    *   Iterative server cannot handle multiple clients concurrently.
    *   Basic command parsing, not a robust parser.
    *   Minimal security (only basic path validation).
    *   No user authentication.
    *   Limited command set compared to full FTP.
    *   Simplistic local IP detection for PASV response.
    *   Error handling during data transfer could be more robust (e.g., handling partial sends/receives more gracefully).

This project serves as an excellent starting point for learning network programming in C, illustrating how to build a networked application from the ground up using fundamental APIs and protocols.
