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
1. For UP/DOWN/SLS, server opens a listening socket on a port within a pre-defined range (e.g., 50000-50099) and replies with `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` indicating the chosen IP and port.
2. Client connects to the server on the specified data port.
3. Raw file bytes or directory listing are transferred over the data connection.
4. Both sides close the data connection; control connection remains open.

**Important Firewall Note:** You must ensure the passive port range (e.g., TCP ports 50000-50099) is allowed through the server's firewall for data transfers (UP/DOWN/SLS) to work.
