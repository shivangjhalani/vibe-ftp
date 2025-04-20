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
./server <port> [--public-ip <public_ip_address>]
```

- Listens for client connections on the specified control port `<port>`.
- **`--public-ip <public_ip_address>` (Optional):** If the server is behind a NAT router and needs to be accessible from the internet, provide its public IP address here. This IP will be used in the `227 Passive Mode` response. If omitted, the server will likely use its local network IP.

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
1. For UP/DOWN/SLS, server opens a listening socket on a port within a pre-defined range (e.g., 50000-50099) and replies with `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` indicating the chosen IP and port. The IP address `h1.h2.h3.h4` *should* be the server's public IP address if it was provided (e.g., via `--public-ip`), otherwise it will likely be its local IP. The port is calculated as `p1 * 256 + p2`.
2. Client connects to the server on the specified data port using the IP address from the `227` response.
3. Raw file bytes or directory listing are transferred over the data connection.
4. Both sides close the data connection; control connection remains open.

**Troubleshooting Data Connections (UP/DOWN/SLS Hangs)**

If the client hangs after receiving the `227 Entering Passive Mode...` message (e.g., stuck at "Connecting to data port..."), check the following:

1.  **Server Firewall:** This is the most common issue. Ensure the passive port range (e.g., TCP ports 50000-50099) is explicitly allowed for **incoming** connections on the **server's** firewall *and* any intermediate firewalls/routers (including port forwarding on the router if behind NAT).
2.  **Server IP Address (NAT):** If the server is behind a NAT router and the client is on a different network:
    *   The server **must** be started with its correct public IP address provided (e.g., using the `--public-ip` option described above).
    *   If the server sends its private IP in the `227` response (like `10.x.x.x`, `192.168.x.x`), the external client cannot connect to it.
    *   Verify the IP address shown in the client's "Connecting to data port..." message matches the server's actual public IP.
3.  **Client Firewall:** Less likely, but ensure the client's firewall allows **outgoing** connections to the server's public IP and passive port range.
4.  **Server Process:** Verify the server process is correctly attempting to listen on the advertised data port.
