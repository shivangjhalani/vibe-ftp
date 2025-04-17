# Minimal FTP Protocol in C

A simple, educational FTP-like application implemented from scratch in C using raw TCP sockets. Supports basic directory navigation, file transfers, and directory listings on both client and server.

## Features

- **SCD & CCD**
  - SCD `<path>`: Change working directory on the server side.
  - CCD `<path>`: Change local working directory on the client side.

- **SLS & CLS**
  - SLS: List files and directories in the server’s current working directory.
  - CLS: List files and directories in the client’s current working directory.

- **File Transfers**
  - UP `<file>`: Upload a file from the client to the server.
  - DOWN `<file>`: Download a file from the server to the client.

- **Session Management**
  - QUIT: Close the control connection and exit.

## Prerequisites

- Linux or macOS
- GCC or compatible C compiler
- Make

## Build

```bash
make all
```

## Usage

### Server

```bash
./server <port>
```

- Listens for client connections on the specified control port.

### Client

```bash
./client <server_ip> <port>
```

- Connects to the FTP server's control port.
- Supported commands after connecting:
  - `SCD <path>`
  - `CCD <path>`
  - `SLS`
  - `CLS`
  - `UP <file>`
  - `DOWN <file>`
  - `QUIT`

## Development Plan

### Phase 1: Control Channel & Command Parsing
- Scaffold `server.c` and `client.c`.
- Establish a TCP control connection.<br>
- Implement basic command parsing and response codes (e.g., `200`, `550`).

### Phase 2: Directory Navigation & Listings
- Add `SCD` command handling on the server (use `chdir`).
- Add `CCD` command on the client (use `chdir`).
- Implement `SLS` on server (execute `opendir`, `readdir`).
- Implement `CLS` on client.

### Phase 3: Data Channel & File Transfers
- Adopt passive mode: server opens ephemeral data port on `UP`/`DOWN`.
- Client parses `227` response, connects to data port.
- Transfer files using buffered read/write.
- Close data connection, notify control channel.

### Phase 4: Error Handling & Security
- Validate and sanitize paths (prevent `..` escapes).
- Handle partial reads/writes correctly.
- Add timeouts and signal handling (e.g., `SIGINT`).

### Phase 5: Testing & Documentation
- Write shell scripts or unit tests to automate `UP`/`DOWN`/`SLS` workflows.
- Finalize comments and README.
- Package and version the project.

## Protocol & Data Flow

**Control Connection (TCP)**
- Server listens on a control port (default 2121).
- Client connects and sends text commands:
  - SCD `<path>`
  - CCD `<path>`
  - SLS
  - CLS
  - UP `<file>`
  - DOWN `<file>`
  - QUIT
- Server responds with standard FTP-style codes: 2xx on success, 4xx/5xx on errors.

**Data Connection (TCP) – Passive Mode Only**
1. For UP/DOWN, server opens an ephemeral data port and replies with `227 <port>`.
2. Client connects to server on the data port.
3. Raw file bytes are transferred in fixed-size buffers (e.g., 4 KB).
4. Both sides close the data connection; control connection remains open.

### Example Session
```
ftp> SCD /var/files
200 Directory changed to /var/files
ftp> SLS
200 file1.txt file2.txt images/
ftp> UP local.txt
227 56890
150 Data connection open; transfer starting.
226 Transfer complete.
ftp> DOWN remote.pdf
227 56891
150 Data connection open; transfer starting.
226 Transfer complete.
ftp> QUIT
221 Goodbye.
```