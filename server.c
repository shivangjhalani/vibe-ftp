#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa, inet_addr
#include <dirent.h> // For directory listing
#include <errno.h> // For errno
#include <sys/stat.h> // For stat
#include <fcntl.h> // For file operations (O_RDONLY, O_WRONLY, etc.)
#include <signal.h> // For signal handling
#include <sys/time.h> // For timeval struct
#include <time.h> // For srand
#include <stdbool.h> // For bool type

#define BUFFER_SIZE 4096 // Increased buffer for file transfer
#define DEFAULT_PORT 2121
#define MAX_PATH_LEN (BUFFER_SIZE - 128) // Increased reserve space
#define SOCKET_TIMEOUT_SEC 60 // Timeout for send/recv in seconds
#define PASSIVE_PORT_START 50000 // Define the start of the passive port range
#define PASSIVE_PORT_END 50099   // Define the end of the passive port range (100 ports)

// Global variable for server socket descriptor (for signal handler)
int g_server_fd = -1;
// Global variable to store the public IP address if provided
char* g_public_ip = NULL;

// Signal handler for SIGINT/SIGTERM
// Attempts to gracefully close the listening socket before exiting.
void handle_signal(int sig) {
    printf("\nCaught signal %d. Shutting down server...\n", sig);
    if (g_server_fd != -1) {
        close(g_server_fd);
        g_server_fd = -1; // Prevent double close
    }
    // Note: This doesn't close active client connections, a more complex
    // handler would iterate through active connections if tracked.
    exit(0);
}

// Helper function to set socket timeouts (SO_RCVTIMEO and SO_SNDTIMEO)
// This prevents indefinite blocking on send/recv operations.
int set_socket_timeouts(int sockfd) {
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_SNDTIMEO failed");
        return -1;
    }
    return 0;
}

// Helper function to validate path (basic security check)
// Prevents directory traversal attacks using '..'.
int is_path_valid(const char *path) {
    if (strstr(path, "..") != NULL) {
        return 0; // Invalid
    }
    // Add other checks if needed (e.g., absolute paths, allowed characters)
    return 1; // Valid
}

// Helper function to create a listening socket for passive mode data transfers
// Binds to a port within the defined range [PASSIVE_PORT_START, PASSIVE_PORT_END]
// Returns the listener FD and the port number.
int setup_passive_listener(int *port) {
    int listener_fd = -1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int opt = 1;
    int current_port;
    int bind_success = 0;

    // Seed random number generator (optional, for starting port randomization)
    // srand(time(NULL));
    // int start_offset = rand() % (PASSIVE_PORT_END - PASSIVE_PORT_START + 1);

    for (int i = 0; i <= (PASSIVE_PORT_END - PASSIVE_PORT_START); ++i) {
        // current_port = PASSIVE_PORT_START + (start_offset + i) % (PASSIVE_PORT_END - PASSIVE_PORT_START + 1);
        current_port = PASSIVE_PORT_START + i; // Simple sequential try

        if ((listener_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("passive socket creation failed");
            return -1; // Critical error, stop trying
        }

        // Allow reuse of local addresses
        if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            perror("passive setsockopt SO_REUSEADDR failed");
            close(listener_fd);
            listener_fd = -1;
            continue; // Try next port
        }

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(current_port); // Try specific port

        if (bind(listener_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            // Bind successful!
            *port = current_port;
            bind_success = 1;
            break; // Exit the loop
        } else {
            // Bind failed (likely EADDRINUSE), close socket and try next port
            if (errno != EADDRINUSE) {
                 perror("passive bind failed (non-EADDRINUSE)");
            }
            close(listener_fd);
            listener_fd = -1;
        }
    }

    if (!bind_success) {
        fprintf(stderr, "Failed to bind to any port in the range %d-%d\n", PASSIVE_PORT_START, PASSIVE_PORT_END);
        return -1;
    }

    // Get the assigned port info again (optional, confirms bind)
    if (getsockname(listener_fd, (struct sockaddr *)&addr, &addrlen) < 0) {
        perror("getsockname failed after successful bind");
        close(listener_fd);
        return -1;
    }
    // *port = ntohs(addr.sin_port); // Should match current_port

    if (listen(listener_fd, 1) < 0) { // Listen for one connection
        perror("passive listen failed");
        close(listener_fd);
        return -1;
    }

    printf("Passive listener set up on port %d\n", *port);
    return listener_fd;
}

// Helper function to get local IP address associated with the control socket.
// Returns IP in standard dotted-decimal format (e.g., "127.0.0.1").
char* get_local_interface_ip(int control_socket) {
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(control_socket, (struct sockaddr*)&local_addr, &addr_len) == -1) {
        perror("getsockname for local IP failed");
        // Return a static buffer for safety, inet_ntoa might use a static buffer too
        static char fallback_ip[] = "127.0.0.1";
        return fallback_ip;
    }
    // inet_ntoa returns a pointer to a static buffer, which is fine here
    // as we expect the caller to use it immediately.
    return inet_ntoa(local_addr.sin_addr);
}

// Main function to handle a single client connection
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int n;
    char current_dir[BUFFER_SIZE];
    int data_listener_fd = -1;
    int data_socket_fd = -1;

    // Set timeouts for the client control socket
    if (set_socket_timeouts(client_socket) < 0) {
        fprintf(stderr, "Failed to set timeouts for client socket %d\n", client_socket);
        close(client_socket);
        return;
    }

    // Send welcome message (optional)
    // send(client_socket, "220 Service ready", 19, 0);

    while ((n = recv(client_socket, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        // Remove trailing \r\n if present
        if (n >= 2 && buffer[n-2] == '\r' && buffer[n-1] == '\n') {
            buffer[n-2] = '\0';
        } else if (n >= 1 && buffer[n-1] == '\n') {
             buffer[n-1] = '\0';
        }

        printf("Received command: %s\n", buffer);

        // Basic command parsing
        if (strncmp(buffer, "QUIT", 4) == 0) {
            printf("Client requested QUIT.\n");
            send(client_socket, "221 Goodbye.\r\n", 15, 0);
            break; // Exit loop and close connection
        } else if (strncmp(buffer, "SCD ", 4) == 0) {
            char *path = buffer + 4;
            if (!is_path_valid(path)) {
                send(client_socket, "550 Invalid path (contains '..').\r\n", 33, 0);
                continue;
            }
            if (strlen(path) > MAX_PATH_LEN) {
                send(client_socket, "553 Requested action not taken. Path name too long.\r\n", 55, 0);
            } else if (chdir(path) == 0) {
                printf("Changed directory to %s\n", path);
                // Check length before snprintf
                if (strlen("200 Directory changed to \r\n") + strlen(path) < sizeof(response)) {
                    snprintf(response, sizeof(response), "200 Directory changed to %s\r\n", path);
                    send(client_socket, response, strlen(response), 0);
                } else {
                     // Should not happen due to MAX_PATH_LEN check, but as fallback:
                     send(client_socket, "500 Internal error: Path too long for response buffer.\r\n", 58, 0);
                }
            } else {
                perror("chdir failed");
                snprintf(response, sizeof(response), "550 Failed to change directory: %s\r\n", strerror(errno));
                send(client_socket, response, strlen(response), 0);
            }
        } else if (strncmp(buffer, "SLS", 3) == 0) {
            DIR *d;
            struct dirent *dir;
            struct stat statbuf;
            char listing[BUFFER_SIZE * 6] = {0}; // Buffer for the listing itself
            char entry_path[BUFFER_SIZE * 2];

            // Get current directory to construct full path for stat
            if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
                perror("getcwd failed for SLS");
                snprintf(response, sizeof(response), "550 Failed to get current directory: %s\r\n", strerror(errno));
                send(client_socket, response, strlen(response), 0);
                continue; // Skip processing this command
            }

            d = opendir(".");
            if (d) {
                // Format the initial response line to include the directory path
                snprintf(listing, sizeof(listing), "200 Directory listing for %s:\r\n", current_dir);

                while ((dir = readdir(d)) != NULL) {
                    // Skip . and ..
                    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
                        continue;
                    }

                    snprintf(entry_path, sizeof(entry_path), "%s/%s", current_dir, dir->d_name);

                    char formatted_entry[BUFFER_SIZE + 2]; // name + / + \r\n + null
                    if (stat(entry_path, &statbuf) == 0) {
                        if (S_ISDIR(statbuf.st_mode)) {
                            snprintf(formatted_entry, sizeof(formatted_entry), "%s/\r\n", dir->d_name);
                        } else {
                            snprintf(formatted_entry, sizeof(formatted_entry), "%s\r\n", dir->d_name);
                        }
                    } else {
                        // If stat fails, just list the name (might be a broken link, etc.)
                        perror("stat failed for entry");
                        snprintf(formatted_entry, sizeof(formatted_entry), "%s (stat failed)\r\n", dir->d_name);
                    }

                    // Check for buffer overflow before appending
                    if (strlen(listing) + strlen(formatted_entry) < sizeof(listing) - 1) {
                        strcat(listing, formatted_entry);
                    } else {
                        // Avoid buffer overflow if listing is too long
                        strcat(listing, "... (listing truncated)\r\n");
                        break;
                    }
                }
                closedir(d);
                // Send the accumulated listing
                send(client_socket, listing, strlen(listing), 0);
            } else {
                perror("opendir failed");
                snprintf(response, sizeof(response), "550 Failed to open directory: %s\r\n", strerror(errno));
                send(client_socket, response, strlen(response), 0);
            }
        } else if (strncmp(buffer, "UP ", 3) == 0) {
            char *filename = buffer + 3;
            if (!is_path_valid(filename)) {
                send(client_socket, "550 Invalid filename (contains '..').\r\n", 36, 0);
                continue;
            }
            if (strlen(filename) > MAX_PATH_LEN) {
                send(client_socket, "553 Requested action not taken. File name too long.\r\n", 56, 0);
                continue;
            }
            int data_port;
            printf("Upload request for: %s\n", filename);

            data_listener_fd = setup_passive_listener(&data_port);
            if (data_listener_fd < 0) {
                send(client_socket, "425 Can't open data connection.\r\n", 31, 0);
                continue;
            }

            // Determine IP for PASV response
            char *ip_for_pasv = g_public_ip; // Use public IP if provided
            if (ip_for_pasv == NULL) {
                ip_for_pasv = get_local_interface_ip(client_socket); // Otherwise, get local interface IP
            }

            // Format 227 response - IMPORTANT: Replace dots with commas for FTP PASV format
            char pasv_ip_formatted[INET_ADDRSTRLEN + 1]; // Max length for IPv4 + null terminator
            strncpy(pasv_ip_formatted, ip_for_pasv, sizeof(pasv_ip_formatted) - 1);
            pasv_ip_formatted[sizeof(pasv_ip_formatted) - 1] = '\0'; // Ensure null termination
            for (char *p = pasv_ip_formatted; *p; ++p) {
                if (*p == '.') {
                    *p = ',';
                }
            }

            int p1 = data_port / 256;
            int p2 = data_port % 256;
            snprintf(response, sizeof(response), "227 Entering Passive Mode (%s,%d,%d)\r\n", pasv_ip_formatted, p1, p2);
            send(client_socket, response, strlen(response), 0);

            // Accept data connection (blocking)
            printf("Waiting for data connection on port %d...\n", data_port);
            struct sockaddr_in data_addr;
            socklen_t data_addrlen = sizeof(data_addr);
            data_socket_fd = accept(data_listener_fd, (struct sockaddr *)&data_addr, &data_addrlen);
            close(data_listener_fd); // Close listener once connection accepted
            data_listener_fd = -1;

            if (data_socket_fd < 0) {
                perror("data accept failed");
                send(client_socket, "425 Can't open data connection.\r\n", 31, 0);
                continue;
            } else {
                printf("Data connection accepted.\n");
                // Set timeouts for the data socket
                if (set_socket_timeouts(data_socket_fd) < 0) {
                    fprintf(stderr, "Failed to set timeouts for data socket\n");
                    send(client_socket, "425 Can't set up data connection timeouts.\r\n", 43, 0);
                    close(data_socket_fd);
                    data_socket_fd = -1;
                    continue;
                }
            }

            // Send 150 status - Check length before snprintf
            if (strlen("150 Ok to send data for .\r\n") + strlen(filename) < sizeof(response)) {
                snprintf(response, sizeof(response), "150 Ok to send data for %s.\r\n", filename);
                send(client_socket, response, strlen(response), 0);
            } else {
                 send(client_socket, "500 Internal error: Filename too long for response buffer.\r\n", 60, 0);
                 close(data_socket_fd);
                 data_socket_fd = -1;
                 continue;
            }

            // Receive file data
            FILE *fp = fopen(filename, "wb"); // Open in binary write mode
            if (!fp) {
                perror("fopen failed for upload");
                send(client_socket, "550 Requested action not taken. File unavailable.\r\n", 54, 0);
                close(data_socket_fd);
                data_socket_fd = -1;
                continue;
            }

            ssize_t bytes_received;
            while ((bytes_received = recv(data_socket_fd, buffer, BUFFER_SIZE, 0)) > 0) {
                fwrite(buffer, 1, bytes_received, fp);
            }
            fclose(fp);
            close(data_socket_fd);
            data_socket_fd = -1;

            if (bytes_received < 0) {
                perror("recv data failed");
                send(client_socket, "426 Connection closed; transfer aborted.\r\n", 42, 0);
            } else {
                printf("%s\n", filename);
                send(client_socket, "226 Transfer complete.\r\n", 24, 0);
            }

        } else if (strncmp(buffer, "DOWN ", 5) == 0) {
            char *filename = buffer + 5;
            if (!is_path_valid(filename)) {
                send(client_socket, "550 Invalid filename (contains '..').\r\n", 36, 0);
                continue;
            }
            if (strlen(filename) > MAX_PATH_LEN) {
                send(client_socket, "553 Requested action not taken. File name too long.\r\n", 56, 0);
                continue;
            }

            // Check if file exists and is readable before setting up data connection
            FILE *fp_check = fopen(filename, "rb");
            if (!fp_check) {
                perror("fopen check failed for download");
                snprintf(response, sizeof(response), "550 Requested action not taken. File unavailable: %s\r\n", strerror(errno));
                send(client_socket, response, strlen(response), 0);
                continue;
            }
            fclose(fp_check);

            int data_port;
            printf("Download request for: %s\n", filename);

            data_listener_fd = setup_passive_listener(&data_port);
            if (data_listener_fd < 0) {
                send(client_socket, "425 Can't open data connection.\r\n", 31, 0);
                continue;
            }

            // Determine IP for PASV response
            char *ip_for_pasv = g_public_ip; // Use public IP if provided
            if (ip_for_pasv == NULL) {
                ip_for_pasv = get_local_interface_ip(client_socket); // Otherwise, get local interface IP
            }

            // Format 227 response - IMPORTANT: Replace dots with commas for FTP PASV format
            char pasv_ip_formatted[INET_ADDRSTRLEN + 1]; // Max length for IPv4 + null terminator
            strncpy(pasv_ip_formatted, ip_for_pasv, sizeof(pasv_ip_formatted) - 1);
            pasv_ip_formatted[sizeof(pasv_ip_formatted) - 1] = '\0'; // Ensure null termination
            for (char *p = pasv_ip_formatted; *p; ++p) {
                if (*p == '.') {
                    *p = ',';
                }
            }

            int p1 = data_port / 256;
            int p2 = data_port % 256;
            snprintf(response, sizeof(response), "227 Entering Passive Mode (%s,%d,%d)\r\n", pasv_ip_formatted, p1, p2);
            send(client_socket, response, strlen(response), 0);

            // Accept data connection (blocking)
            printf("Waiting for data connection on port %d...\n", data_port);
            struct sockaddr_in data_addr;
            socklen_t data_addrlen = sizeof(data_addr);
            data_socket_fd = accept(data_listener_fd, (struct sockaddr *)&data_addr, &data_addrlen);
            close(data_listener_fd);
            data_listener_fd = -1;

            if (data_socket_fd < 0) {
                perror("data accept failed");
                send(client_socket, "425 Can't open data connection.\r\n", 31, 0);
                continue;
            } else {
                printf("Data connection accepted.\n");
                // Set timeouts for the data socket
                if (set_socket_timeouts(data_socket_fd) < 0) {
                    fprintf(stderr, "Failed to set timeouts for data socket\n");
                    send(client_socket, "425 Can't set up data connection timeouts.\r\n", 43, 0);
                    close(data_socket_fd);
                    data_socket_fd = -1;
                    continue;
                }
            }

            // Send 150 status - Check length before snprintf
            if (strlen("150 Opening data connection for .\r\n") + strlen(filename) < sizeof(response)) {
                 snprintf(response, sizeof(response), "150 Opening data connection for %s.\r\n", filename);
                 send(client_socket, response, strlen(response), 0);
            } else {
                 send(client_socket, "500 Internal error: Filename too long for response buffer.\r\n", 60, 0);
                 close(data_socket_fd);
                 data_socket_fd = -1;
                 continue;
            }

            // Send file data
            FILE *fp = fopen(filename, "rb"); // Open in binary read mode
            if (!fp) { // Should not happen due to check above, but double-check
                perror("fopen failed for download");
                send(client_socket, "550 Requested action not taken. File unavailable.\r\n", 54, 0);
                close(data_socket_fd);
                data_socket_fd = -1;
                continue;
            }

            ssize_t bytes_read;
            ssize_t bytes_sent_total = 0;
            int read_error = 0;
            while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
                ssize_t bytes_sent = send(data_socket_fd, buffer, bytes_read, 0);
                if (bytes_sent < 0) {
                    perror("send data failed");
                    break;
                }
                if (bytes_sent < bytes_read) {
                     fprintf(stderr, "Warning: Partial send occurred during download.\n");
                     // Ideally, handle partial sends by retrying, but for simplicity, we'll break
                     break;
                }
                bytes_sent_total += bytes_sent;
            }
            // Check for read error *before* closing the file
            if (ferror(fp)) {
                perror("fread error during download");
                read_error = 1;
            }
            fclose(fp);
            close(data_socket_fd);
            data_socket_fd = -1;

            // Check for errors after closing sockets
            if (read_error || (bytes_sent_total == 0 && bytes_read < 0)) { // Check for read errors or send errors
                 fprintf(stderr, "Error during file read or send.\n");
                 send(client_socket, "426 Connection closed; transfer aborted.\r\n", 42, 0);
            } else {
                printf("File %s downloaded successfully (%zd bytes sent).\n", filename, bytes_sent_total);
                send(client_socket, "226 Transfer complete.\r\n", 24, 0);
            }

        } else {
            // Placeholder for other commands
            send(client_socket, "502 Command not implemented.\r\n", 30, 0);
        }
    }

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Client socket timeout occurred.\n");
            send(client_socket, "421 Service not available, closing control connection (timeout).\r\n", 68, 0);
        } else {
            perror("recv failed");
        }
    } else if (n == 0) {
        printf("Client disconnected.\n");
    }

    // Clean up data sockets if connection drops unexpectedly
    if (data_listener_fd >= 0) close(data_listener_fd);
    if (data_socket_fd >= 0) close(data_socket_fd);

    close(client_socket);
    printf("Connection closed.\n");
}

int main(int argc, char *argv[]) {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int port = DEFAULT_PORT;
    bool port_set = false;

    // Setup signal handling for graceful shutdown
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--public-ip") == 0) {
            if (i + 1 < argc) {
                g_public_ip = argv[i + 1];
                // Basic validation: check if it contains dots (not a robust check)
                if (strchr(g_public_ip, '.') == NULL) {
                     fprintf(stderr, "Error: Invalid public IP address format: %s\n", g_public_ip);
                     fprintf(stderr, "Usage: %s [<port>] [--public-ip <ip_address>]\n", argv[0]);
                     return 1;
                }
                printf("Using public IP for PASV: %s\n", g_public_ip);
                i++; // Skip the next argument (the IP address)
            } else {
                fprintf(stderr, "Error: --public-ip requires an argument.\n");
                fprintf(stderr, "Usage: %s [<port>] [--public-ip <ip_address>]\n", argv[0]);
                return 1;
            }
        } else if (!port_set) {
            // Assume the first non-option argument is the port
            port = atoi(argv[i]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port number: %s\n", argv[i]);
                fprintf(stderr, "Usage: %s [<port>] [--public-ip <ip_address>]\n", argv[0]);
                return 1;
            }
            port_set = true;
        } else {
             fprintf(stderr, "Warning: Ignoring extra argument: %s\n", argv[i]);
        }
    }

    if (!port_set) {
         printf("Usage: %s [<port>] [--public-ip <ip_address>]\nUsing default port %d\n", argv[0], DEFAULT_PORT);
    }

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    g_server_fd = server_fd; // Store globally for signal handler

    // Forcefully attaching socket to the port (allow reuse)
    // SO_REUSEADDR allows binding even if the port is in TIME_WAIT state.
    // SO_REUSEPORT (Linux specific) allows multiple sockets to bind to the same port.
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Binding the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port);

    // Main accept loop: wait for and handle incoming connections one by one.
    while (1) {
        printf("Waiting for a connection...\n");
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue; // Continue waiting for next connection
        }

        struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&address;
        struct in_addr ipAddr = pV4Addr->sin_addr;
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop( AF_INET, &ipAddr, client_ip, INET_ADDRSTRLEN );

        printf("Connection accepted from %s:%d\n", client_ip, ntohs(address.sin_port));

        handle_client(client_socket); // Handle client in the main process for now
    }

    // Close the listening socket (technically unreachable in this loop)
    if (g_server_fd != -1) {
        close(g_server_fd);
    }

    return 0;
}
