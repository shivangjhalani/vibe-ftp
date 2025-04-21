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
#include <openssl/ssl.h>
#include <openssl/err.h>

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
// Global SSL context
SSL_CTX *g_ssl_ctx = NULL;

// Function to initialize OpenSSL and create SSL context
SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method(); // Use modern TLS method
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the key and cert
    // Replace "server.crt" and "server.key" with your actual file paths
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    printf("SSL Context created and certificates loaded.\n");
    return ctx;
}

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
void handle_client(int client_socket, SSL_CTX *ctx) { // Pass SSL_CTX
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int n;
    char current_dir[BUFFER_SIZE];
    int data_listener_fd = -1;
    int data_socket_fd = -1;
    SSL *ssl = NULL; // SSL object for control connection
    SSL *data_ssl = NULL; // SSL object for data connection

    // Create SSL structure for client connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating SSL structure.\n");
        ERR_print_errors_fp(stderr);
        close(client_socket);
        return;
    }
    SSL_set_fd(ssl, client_socket);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Error performing SSL handshake.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }
    printf("SSL handshake successful with client.\n");

    // Set timeouts for the client control socket (already done before SSL_accept)
    // if (set_socket_timeouts(client_socket) < 0) { ... }

    // Send welcome message (optional) - Use SSL_write
    // SSL_write(ssl, "220 Service ready (SSL/TLS)\r\n", strlen("220 Service ready (SSL/TLS)\r\n"));

    // Use SSL_read instead of recv
    while ((n = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        // Remove trailing \r\n if present
        if (n >= 2 && buffer[n-2] == '\r' && buffer[n-1] == '\n') {
            buffer[n-2] = '\0';
        } else if (n >= 1 && buffer[n-1] == '\n') {
             buffer[n-1] = '\0';
        }

        printf("Received command (SSL): %s\n", buffer);

        // Basic command parsing
        if (strncmp(buffer, "QUIT", 4) == 0) {
            printf("Client requested QUIT.\n");
            SSL_write(ssl, "221 Goodbye.\r\n", 15);
            break; // Exit loop and close connection
        } else if (strncmp(buffer, "SCD ", 4) == 0) {
            char *path = buffer + 4;
            if (!is_path_valid(path)) {
                SSL_write(ssl, "550 Invalid path (contains '..').\r\n", 33);
                continue;
            }
            if (strlen(path) > MAX_PATH_LEN) {
                SSL_write(ssl, "553 Requested action not taken. Path name too long.\r\n", 55);
            } else if (chdir(path) == 0) {
                printf("Changed directory to %s\n", path);
                if (strlen("200 Directory changed to \r\n") + strlen(path) < sizeof(response)) {
                    snprintf(response, sizeof(response), "200 Directory changed to %s\r\n", path);
                    SSL_write(ssl, response, strlen(response));
                } else {
                     SSL_write(ssl, "500 Internal error: Path too long for response buffer.\r\n", 58);
                }
            } else {
                perror("chdir failed");
                snprintf(response, sizeof(response), "550 Failed to change directory: %s\r\n", strerror(errno));
                SSL_write(ssl, response, strlen(response));
            }
        } else if (strncmp(buffer, "SLS", 3) == 0) {
            // ... (SLS logic - replace send with SSL_write)
            DIR *d;
            struct dirent *dir;
            struct stat statbuf;
            char listing[BUFFER_SIZE * 6] = {0}; // Buffer for the listing itself
            char entry_path[BUFFER_SIZE * 2];

            if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
                perror("getcwd failed for SLS");
                snprintf(response, sizeof(response), "550 Failed to get current directory: %s\r\n", strerror(errno));
                SSL_write(ssl, response, strlen(response));
                continue;
            }

            d = opendir(".");
            if (d) {
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

                    if (strlen(listing) + strlen(formatted_entry) < sizeof(listing) - 1) {
                        strcat(listing, formatted_entry);
                    } else {
                        strcat(listing, "... (listing truncated)\r\n");
                        break;
                    }
                }
                closedir(d);
                SSL_write(ssl, listing, strlen(listing));
            } else {
                perror("opendir failed");
                snprintf(response, sizeof(response), "550 Failed to open directory: %s\r\n", strerror(errno));
                SSL_write(ssl, response, strlen(response));
            }
        } else if (strncmp(buffer, "UP ", 3) == 0) {
            // ... (UP logic - needs significant changes for data connection SSL)
            char *filename = buffer + 3;
            if (!is_path_valid(filename)) {
                SSL_write(ssl, "550 Invalid filename (contains '..').\r\n", 36);
                continue;
            }
            if (strlen(filename) > MAX_PATH_LEN) {
                SSL_write(ssl, "553 Requested action not taken. File name too long.\r\n", 56);
                continue;
            }
            int data_port;
            printf("Upload request for: %s\n", filename);

            data_listener_fd = setup_passive_listener(&data_port);
            if (data_listener_fd < 0) {
                SSL_write(ssl, "425 Can't open data connection.\r\n", 31);
                continue;
            }

            // Determine IP for PASV response
            char *ip_for_pasv = g_public_ip; // Use public IP if provided
            if (ip_for_pasv == NULL) {
                ip_for_pasv = get_local_interface_ip(client_socket); // Otherwise, get local interface IP
            }
            // ... (Format 227 response)
            char pasv_ip_formatted[INET_ADDRSTRLEN + 1];
            strncpy(pasv_ip_formatted, ip_for_pasv, sizeof(pasv_ip_formatted) - 1);
            pasv_ip_formatted[sizeof(pasv_ip_formatted) - 1] = '\0';
            for (char *p = pasv_ip_formatted; *p; ++p) { if (*p == '.') *p = ','; }
            int p1 = data_port / 256; int p2 = data_port % 256;
            snprintf(response, sizeof(response), "227 Entering Passive Mode (%s,%d,%d)\r\n", pasv_ip_formatted, p1, p2);
            SSL_write(ssl, response, strlen(response));

            // Accept data connection
            printf("Waiting for data connection on port %d...\n", data_port);
            struct sockaddr_in data_addr;
            socklen_t data_addrlen = sizeof(data_addr);
            data_socket_fd = accept(data_listener_fd, (struct sockaddr *)&data_addr, &data_addrlen);
            close(data_listener_fd); data_listener_fd = -1;

            if (data_socket_fd < 0) {
                perror("data accept failed");
                SSL_write(ssl, "425 Can't open data connection.\r\n", 31);
                continue;
            } else {
                printf("Data connection accepted. Performing SSL handshake for data...\n");
                // Create SSL object for data connection
                data_ssl = SSL_new(ctx);
                if (!data_ssl) {
                    fprintf(stderr, "Error creating data SSL structure.\n");
                    ERR_print_errors_fp(stderr);
                    SSL_write(ssl, "425 Can't set up data connection (SSL init failed).\r\n", 55);
                    close(data_socket_fd); data_socket_fd = -1;
                    continue;
                }
                SSL_set_fd(data_ssl, data_socket_fd);

                // Perform SSL handshake on data connection
                if (SSL_accept(data_ssl) <= 0) {
                    fprintf(stderr, "Error performing data SSL handshake.\n");
                    ERR_print_errors_fp(stderr);
                    SSL_write(ssl, "425 Can't set up data connection (SSL handshake failed).\r\n", 61);
                    SSL_free(data_ssl); data_ssl = NULL;
                    close(data_socket_fd); data_socket_fd = -1;
                    continue;
                }
                printf("Data SSL handshake successful.\n");

                // Set timeouts for the data socket (optional, after handshake)
                // if (set_socket_timeouts(data_socket_fd) < 0) { ... }
            }

            // Send 150 status via control connection
            if (strlen("150 Ok to send data for .\r\n") + strlen(filename) < sizeof(response)) {
                snprintf(response, sizeof(response), "150 Ok to send data for %s.\r\n", filename);
                SSL_write(ssl, response, strlen(response));
            } else {
                 SSL_write(ssl, "500 Internal error: Filename too long for response buffer.\r\n", 60);
                 SSL_shutdown(data_ssl); SSL_free(data_ssl); data_ssl = NULL;
                 close(data_socket_fd); data_socket_fd = -1;
                 continue;
            }

            // Receive file data via data connection (use SSL_read)
            FILE *fp = fopen(filename, "wb");
            if (!fp) {
                perror("fopen failed for upload");
                SSL_write(ssl, "550 Requested action not taken. File unavailable.\r\n", 54);
                SSL_shutdown(data_ssl); SSL_free(data_ssl); data_ssl = NULL;
                close(data_socket_fd); data_socket_fd = -1;
                continue;
            }

            ssize_t bytes_received;
            while ((bytes_received = SSL_read(data_ssl, buffer, BUFFER_SIZE)) > 0) {
                fwrite(buffer, 1, bytes_received, fp);
            }
            fclose(fp);
            // Check SSL_read error status if needed (SSL_get_error)
            int ssl_error = SSL_get_error(data_ssl, bytes_received);
            if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_NONE) {
                 perror("SSL_read data failed");
                 ERR_print_errors_fp(stderr);
                 SSL_write(ssl, "426 Connection closed; transfer aborted (SSL read error).\r\n", 61);
            } else {
                 printf("Upload complete for %s\n", filename);
                 SSL_write(ssl, "226 Transfer complete.\r\n", 24);
            }

            // Clean up data SSL
            SSL_shutdown(data_ssl); // Initiate SSL shutdown
            SSL_free(data_ssl); data_ssl = NULL;
            close(data_socket_fd); data_socket_fd = -1;

        } else if (strncmp(buffer, "DOWN ", 5) == 0) {
            // ... (DOWN logic - needs similar changes for data connection SSL)
            char *filename = buffer + 5;
            // ... (path/filename validation)
            if (!is_path_valid(filename)) {
                SSL_write(ssl, "550 Invalid filename (contains '..').\r\n", 36);
                continue;
            }
            if (strlen(filename) > MAX_PATH_LEN) {
                SSL_write(ssl, "553 Requested action not taken. File name too long.\r\n", 56);
                continue;
            }

            FILE *fp_check = fopen(filename, "rb");
            if (!fp_check) {
                perror("fopen check failed for download");
                snprintf(response, sizeof(response), "550 Requested action not taken. File unavailable: %s\r\n", strerror(errno));
                SSL_write(ssl, response, strlen(response));
                continue;
            }
            fclose(fp_check);

            int data_port;
            printf("Download request for: %s\n", filename);

            data_listener_fd = setup_passive_listener(&data_port);
            if (data_listener_fd < 0) {
                SSL_write(ssl, "425 Can't open data connection.\r\n", 31);
                continue;
            }

            // ... (Determine IP for PASV response & Format 227 response)
            char *ip_for_pasv = g_public_ip; if (!ip_for_pasv) ip_for_pasv = get_local_interface_ip(client_socket);
            char pasv_ip_formatted[INET_ADDRSTRLEN + 1];
            strncpy(pasv_ip_formatted, ip_for_pasv, sizeof(pasv_ip_formatted) - 1);
            pasv_ip_formatted[sizeof(pasv_ip_formatted) - 1] = '\0';
            for (char *p = pasv_ip_formatted; *p; ++p) { if (*p == '.') *p = ','; }
            int p1 = data_port / 256; int p2 = data_port % 256;
            snprintf(response, sizeof(response), "227 Entering Passive Mode (%s,%d,%d)\r\n", pasv_ip_formatted, p1, p2);
            SSL_write(ssl, response, strlen(response));

            // Accept data connection & perform SSL handshake
            printf("Waiting for data connection on port %d...\n", data_port);
            struct sockaddr_in data_addr;
            socklen_t data_addrlen = sizeof(data_addr);
            data_socket_fd = accept(data_listener_fd, (struct sockaddr *)&data_addr, &data_addrlen);
            close(data_listener_fd); data_listener_fd = -1;

            if (data_socket_fd < 0) {
                perror("data accept failed");
                SSL_write(ssl, "425 Can't open data connection.\r\n", 31);
                continue;
            } else {
                printf("Data connection accepted. Performing SSL handshake for data...\n");
                data_ssl = SSL_new(ctx);
                if (!data_ssl) {
                    fprintf(stderr, "Error creating data SSL structure.\n"); ERR_print_errors_fp(stderr);
                    SSL_write(ssl, "425 Can't set up data connection (SSL init failed).\r\n", 55);
                    close(data_socket_fd); data_socket_fd = -1;
                    continue;
                }
                SSL_set_fd(data_ssl, data_socket_fd);
                if (SSL_accept(data_ssl) <= 0) {
                    fprintf(stderr, "Error performing data SSL handshake.\n"); ERR_print_errors_fp(stderr);
                    SSL_write(ssl, "425 Can't set up data connection (SSL handshake failed).\r\n", 61);
                    SSL_free(data_ssl); data_ssl = NULL;
                    close(data_socket_fd); data_socket_fd = -1;
                    continue;
                }
                printf("Data SSL handshake successful.\n");
                // Set timeouts for the data socket (optional)
            }

            // Send 150 status via control connection
            if (strlen("150 Opening data connection for .\r\n") + strlen(filename) < sizeof(response)) {
                 snprintf(response, sizeof(response), "150 Opening data connection for %s.\r\n", filename);
                 SSL_write(ssl, response, strlen(response));
            } else {
                 SSL_write(ssl, "500 Internal error: Filename too long for response buffer.\r\n", 60);
                 SSL_shutdown(data_ssl); SSL_free(data_ssl); data_ssl = NULL;
                 close(data_socket_fd); data_socket_fd = -1;
                 continue;
            }

            // Send file data via data connection (use SSL_write)
            FILE *fp = fopen(filename, "rb");
            if (!fp) {
                perror("fopen failed for download");
                SSL_write(ssl, "550 Requested action not taken. File unavailable.\r\n", 54);
                SSL_shutdown(data_ssl); SSL_free(data_ssl); data_ssl = NULL;
                close(data_socket_fd); data_socket_fd = -1;
                continue;
            }

            ssize_t bytes_read;
            ssize_t bytes_sent_total = 0;
            int read_error = 0;
            int ssl_write_error = 0;
            while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
                ssize_t bytes_sent = SSL_write(data_ssl, buffer, bytes_read);
                if (bytes_sent <= 0) {
                    int ssl_error = SSL_get_error(data_ssl, bytes_sent);
                    fprintf(stderr, "SSL_write data failed (code: %d)\n", ssl_error);
                    ERR_print_errors_fp(stderr);
                    ssl_write_error = 1;
                    break;
                }
                bytes_sent_total += bytes_sent;
            }
            if (ferror(fp)) {
                perror("fread error during download");
                read_error = 1;
            }
            fclose(fp);

            // Clean up data SSL first
            SSL_shutdown(data_ssl); // Initiate SSL shutdown
            SSL_free(data_ssl); data_ssl = NULL;
            close(data_socket_fd); data_socket_fd = -1;

            // Send final status on control connection
            if (read_error || ssl_write_error) {
                 fprintf(stderr, "Error during file read or SSL send.\n");
                 SSL_write(ssl, "426 Connection closed; transfer aborted (read/write error).\r\n", 63);
            } else {
                printf("File %s downloaded successfully (%zd bytes sent).\n", filename, bytes_sent_total);
                SSL_write(ssl, "226 Transfer complete.\r\n", 24);
            }

        } else {
            // Placeholder for other commands
            SSL_write(ssl, "502 Command not implemented.\r\n", 30);
        }
    }

    // Handle SSL_read errors or client disconnect
    if (n <= 0) {
        int ssl_error = SSL_get_error(ssl, n);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            printf("Client closed SSL connection gracefully.\n");
        } else if (ssl_error == SSL_ERROR_SYSCALL) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                 printf("Client socket timeout occurred (SSL).\n");
                 // SSL_write might fail here too, ignore errors
                 SSL_write(ssl, "421 Service not available, closing control connection (timeout).\r\n", 68);
            } else if (n == 0) { // Check underlying socket EOF
                 printf("Client disconnected abruptly (socket closed).\n");
            } else {
                 perror("SSL_read failed (SYSCALL)");
                 ERR_print_errors_fp(stderr);
            }
        } else {
            fprintf(stderr, "SSL_read failed with error code: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
        }
    }

    // Clean up data sockets if connection drops unexpectedly
    if (data_listener_fd >= 0) close(data_listener_fd);
    if (data_ssl) { SSL_shutdown(data_ssl); SSL_free(data_ssl); }
    if (data_socket_fd >= 0) close(data_socket_fd);

    // Clean up control connection SSL
    if (ssl) {
        SSL_shutdown(ssl); // Initiate SSL shutdown
        SSL_free(ssl);
    }
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
    SSL_CTX *ctx;

    // Initialize OpenSSL
    ctx = create_ssl_context();
    g_ssl_ctx = ctx; // Store globally if needed elsewhere, though not currently used

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

    printf("Server listening on port %d (SSL/TLS enabled)\n", port);

    // Main accept loop: wait for and handle incoming connections one by one.
    while (1) {
        printf("Waiting for a connection...\n");
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            // Check for EINTR if signals are used more extensively
            if (errno == EINTR) continue;
            perror("accept failed");
            continue; // Continue waiting for next connection
        }

        struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&address;
        struct in_addr ipAddr = pV4Addr->sin_addr;
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop( AF_INET, &ipAddr, client_ip, INET_ADDRSTRLEN );

        printf("Connection accepted from %s:%d\n", client_ip, ntohs(address.sin_port));

        // Handle client using SSL context
        handle_client(client_socket, ctx);
    }

    // Clean up SSL context and close listening socket (technically unreachable)
    if (g_server_fd != -1) {
        close(g_server_fd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    EVP_cleanup(); // Clean up OpenSSL resources

    return 0;
}
