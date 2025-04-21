#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For chdir, getcwd
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_pton
#include <dirent.h> // For directory listing
#include <errno.h> // For errno
#include <sys/stat.h> // For stat
#include <fcntl.h> // For file operations
#include <signal.h> // For signal handling
#include <sys/time.h> // For timeval struct
#include <openssl/ssl.h> // For SSL
#include <openssl/err.h> // For SSL error handling

#define BUFFER_SIZE 4096 // Increased buffer for file transfer
#define MAX_FILENAME_LEN (BUFFER_SIZE - 128) // Increased reserve space
#define SOCKET_TIMEOUT_SEC 60 // Timeout for send/recv in seconds

// Global variable for control socket (for signal handler)
int g_control_sock = -1;
SSL *g_control_ssl = NULL; // Global SSL object for control connection

// Forward declarations
void cleanup_openssl_client();

// Definition for cleanup_openssl_client
void cleanup_openssl_client() {
    // Clean up OpenSSL library resources
    // Note: SSL objects (g_control_ssl, data_ssl) should be freed when their connections close.
    // The SSL_CTX is typically freed at the very end.
    // ERR_free_strings(); // Deprecated in OpenSSL 1.1.0+
    // EVP_cleanup();      // Deprecated in OpenSSL 1.1.0+
    // SSL_COMP_free_compression_methods(); // If compression was used, also deprecated/handled differently now.
    // Consider if specific SSL objects need freeing here if not handled elsewhere.
    // If g_control_ssl is used and needs cleanup here:
    // if (g_control_ssl) {
    //     SSL_shutdown(g_control_ssl); // Attempt graceful shutdown
    //     SSL_free(g_control_ssl);
    //     g_control_ssl = NULL;
    // }
    // The context (ctx) is freed in main after the loop.
    // If OpenSSL_add_ssl_algorithms() was called, FIPS_mode_set(0) might be needed for cleanup in some contexts.
    // For modern OpenSSL (1.1.0+), much of the global cleanup is automatic on exit.
    // This function might be minimal or empty depending on exact OpenSSL version and usage.
    printf("Performing OpenSSL cleanup (if necessary)...\n");
}

// Signal handler for SIGINT
void handle_sigint_client(int sig) {
    printf("\nCaught signal %d. Closing connection and exiting...\n", sig);
    if (g_control_sock != -1) {
        // Attempt to send QUIT gracefully, but don't wait long
        send(g_control_sock, "QUIT\r\n", 6, MSG_NOSIGNAL); // MSG_NOSIGNAL prevents SIGPIPE
        close(g_control_sock);
        g_control_sock = -1;
    }
    exit(0);
}

// Helper function to set socket timeouts
int set_socket_timeouts_client(int sockfd) {
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

// Helper function to validate path (basic check for '..')
int is_path_valid_client(const char *path) {
    if (strstr(path, "..") != NULL) {
        return 0; // Invalid
    }
    // Add other checks if needed
    return 1; // Valid
}

// Function to create SSL context for client
SSL_CTX* create_ssl_context_client() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method(); // Use modern TLS method for client

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Enable peer verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Load the server's self-signed certificate as the trusted CA
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
        fprintf(stderr, "Error loading server certificate file (server.crt).\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to handle CLS command
void handle_cls() {
    DIR *d;
    struct dirent *dir;
    struct stat statbuf;
    char current_dir[BUFFER_SIZE];
    char entry_path[BUFFER_SIZE * 2];

    // Get current directory to construct full path for stat
    if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
        perror("getcwd failed for CLS");
        return;
    }

    d = opendir(".");
    if (d) {
        printf("Local directory listing for: %s\n", current_dir); // Print current directory
        while ((dir = readdir(d)) != NULL) {
             // Skip . and ..
            if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
                continue;
            }

            snprintf(entry_path, sizeof(entry_path), "%s/%s", current_dir, dir->d_name);

            if (stat(entry_path, &statbuf) == 0) {
                if (S_ISDIR(statbuf.st_mode)) {
                    printf("%s/\n", dir->d_name);
                } else {
                    printf("%s\n", dir->d_name);
                }
            } else {
                 // If stat fails, just list the name (might be a broken link, etc.)
                 perror("stat failed for entry");
                 printf("%s (stat failed)\n", dir->d_name);
            }
        }
        closedir(d);
    } else {
        perror("opendir failed locally");
    }
}

// Function to handle CCD command
void handle_ccd(const char *path) {
    if (!is_path_valid_client(path)) {
        fprintf(stderr, "Error: Invalid local path (contains '..').\n");
        return;
    }
    if (chdir(path) == 0) {
        char cwd[BUFFER_SIZE];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
             printf("Local directory changed to %s\n", cwd);
        } else {
             perror("getcwd failed");
             printf("Local directory changed successfully, but couldn't get current path.\n");
        }
    } else {
        fprintf(stderr, "Failed to change local directory to %s: %s\n", path, strerror(errno));
    }
}

// Helper function to parse the PASV response (227)
// Extracts IP (as string) and port (as int)
// Returns 0 on success, -1 on failure
int parse_pasv_response(const char *response, char *ip_addr, int *port) {
    int h1, h2, h3, h4, p1, p2;
    // Example: 227 Entering Passive Mode (127,0,0,1,195,149)
    if (sscanf(response, "%*[^(](%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) == 6) {
        sprintf(ip_addr, "%d.%d.%d.%d", h1, h2, h3, h4);
        *port = p1 * 256 + p2;
        return 0;
    } else {
        fprintf(stderr, "Error: Could not parse PASV response: %s\n", response);
        return -1;
    }
}

// Helper function to connect to the data port
int connect_to_data_port(const char *ip_addr, int port) {
    int data_sock = 0;
    struct sockaddr_in data_serv_addr;

    if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Data socket creation error");
        return -1;
    }

    data_serv_addr.sin_family = AF_INET;
    data_serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &data_serv_addr.sin_addr) <= 0) {
        perror("Invalid data address/ Address not supported");
        close(data_sock);
        return -1;
    }

    printf("Connecting to data port %s:%d...\n", ip_addr, port);
    if (connect(data_sock, (struct sockaddr *)&data_serv_addr, sizeof(data_serv_addr)) < 0) {
        perror("Data connection Failed");
        close(data_sock);
        return -1;
    }

    // Set timeouts for the data socket
    if (set_socket_timeouts_client(data_sock) < 0) {
        fprintf(stderr, "Failed to set timeouts for data socket\n");
        close(data_sock);
        return -1;
    }

    printf("Data connection established.\n");
    return data_sock;
}

// Helper function to connect to the data port and perform SSL handshake
SSL* connect_to_data_port_ssl(const char *ip_addr, int port, SSL_CTX *ctx) {
    int data_sock = 0;
    struct sockaddr_in data_serv_addr;
    SSL *data_ssl = NULL;

    if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Data socket creation error");
        return NULL;
    }

    data_serv_addr.sin_family = AF_INET;
    data_serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr, &data_serv_addr.sin_addr) <= 0) {
        perror("Invalid data address/ Address not supported");
        close(data_sock);
        return NULL;
    }

    printf("Connecting to data port %s:%d...\n", ip_addr, port);
    if (connect(data_sock, (struct sockaddr *)&data_serv_addr, sizeof(data_serv_addr)) < 0) {
        perror("Data connection Failed");
        close(data_sock);
        return NULL;
    }

    // Set timeouts for the data socket
    if (set_socket_timeouts_client(data_sock) < 0) {
        fprintf(stderr, "Failed to set timeouts for data socket\n");
        close(data_sock);
        return NULL;
    }

    // Create SSL object and associate with the socket
    data_ssl = SSL_new(ctx);
    if (!data_ssl) {
        perror("Unable to create SSL object for data connection");
        ERR_print_errors_fp(stderr);
        close(data_sock);
        return NULL;
    }

    SSL_set_fd(data_ssl, data_sock);

    // Perform SSL handshake
    if (SSL_connect(data_ssl) <= 0) {
        perror("Data SSL handshake failed");
        ERR_print_errors_fp(stderr);
        SSL_free(data_ssl);
        close(data_sock);
        return NULL;
    }
    printf("Data SSL handshake successful.\n");

    // Verify server certificate after handshake
    long verify_result = SSL_get_verify_result(data_ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Data connection certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
        // Handle verification failure (e.g., close connection)
        SSL_shutdown(data_ssl);
        SSL_free(data_ssl);
        close(data_sock);
        return NULL;
    }
    printf("Data connection certificate verified successfully.\n");

    return data_ssl; // Return SSL object (socket fd is managed by SSL object)
}

int main(int argc, char *argv[]) {
    int control_sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char command[BUFFER_SIZE] = {0};
    char user_input[BUFFER_SIZE] = {0};
    char server_ip_arg[INET_ADDRSTRLEN]; // Store original server IP
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    // Setup signal handling
    signal(SIGINT, handle_sigint_client);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %s\n", argv[2]);
        return 1;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL context
    ctx = create_ssl_context_client();

    // Create socket
    if ((control_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        SSL_CTX_free(ctx);
        return 1;
    }
    g_control_sock = control_sock; // Store globally for signal handler

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(control_sock);
        g_control_sock = -1;
        SSL_CTX_free(ctx);
        return 1;
    }

    // Connect to the server
    if (connect(control_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(control_sock);
        g_control_sock = -1;
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create SSL object and associate with the socket
    ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Unable to create SSL object for control connection");
        ERR_print_errors_fp(stderr);
        close(control_sock);
        g_control_sock = -1;
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_set_fd(ssl, control_sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("Control SSL handshake failed");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(control_sock);
        g_control_sock = -1;
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("SSL handshake successful with server %s:%d\n", server_ip, port);

    // Verify server certificate after handshake
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Control connection certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
        // Handle verification failure
        SSL_shutdown(ssl); SSL_free(ssl); g_control_ssl = NULL;
        close(control_sock); g_control_sock = -1;
        SSL_CTX_free(ctx);
        cleanup_openssl_client();
        return 1;
    }
    printf("Control connection certificate verified successfully.\n");

    // Set timeouts for the control socket
    if (set_socket_timeouts_client(control_sock) < 0) {
        fprintf(stderr, "Failed to set timeouts for control socket\n");
        SSL_shutdown(ssl); SSL_free(ssl); g_control_ssl = NULL;
        close(control_sock); g_control_sock = -1;
        SSL_CTX_free(ctx);
        cleanup_openssl_client();
        return 1;
    }

    strncpy(server_ip_arg, argv[1], INET_ADDRSTRLEN -1);
    server_ip_arg[INET_ADDRSTRLEN -1] = '\0';

    printf("Connected to server %s:%d\n", server_ip, port);
    // Optional: Receive initial welcome message if server sends one
    // int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    // if (n > 0) {
    //     buffer[n] = '\0';
    //     printf("Server: %s", buffer); // Assume server sends \r\n
    // }

    printf("ftp> ");
    while (fgets(user_input, BUFFER_SIZE, stdin) != NULL) {
        // Remove trailing newline from fgets
        user_input[strcspn(user_input, "\n")] = 0;

        if (strlen(user_input) == 0) {
             printf("ftp> ");
             continue; // Skip empty input
        }

        // Handle local commands (CCD, CLS)
        if (strncmp(user_input, "CCD ", 4) == 0) {
            char *path = user_input + 4;
            // Validation is now inside handle_ccd
            handle_ccd(path);
            printf("ftp> ");
            continue; // Don't send local command to server
        } else if (strcmp(user_input, "CLS") == 0) {
            handle_cls();
            printf("ftp> ");
            continue; // Don't send local command to server
        }

        // Handle UP command
        if (strncmp(user_input, "UP ", 3) == 0) {
            char *filename = user_input + 3;
            if (!is_path_valid_client(filename)) {
                fprintf(stderr, "Error: Invalid local filename (contains '..').\n");
                printf("ftp> ");
                continue;
            }
            if (strlen(filename) > MAX_FILENAME_LEN) {
                fprintf(stderr, "Error: Filename too long: %s\n", filename);
                printf("ftp> ");
                continue;
            }
            FILE *fp = fopen(filename, "rb");
            if (!fp) {
                perror("Local file open failed");
                printf("ftp> ");
                continue;
            }

            // Send UP command to server using SSL
            snprintf(command, sizeof(command), "UP %s\r\n", filename);
            if (SSL_write(ssl, command, strlen(command)) <= 0) { // NEW: Use SSL_write
                perror("SSL_write UP command failed");
                ERR_print_errors_fp(stderr); // Print SSL errors
                fclose(fp);
                break;
            }

            // Receive response (expect 227) using SSL
            int n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
            if (n <= 0) {
                 fprintf(stderr, "SSL_read failed after UP command (error code: %d)\n", SSL_get_error(ssl, n));
                 ERR_print_errors_fp(stderr);
                 fclose(fp);
                 break;
            }
            buffer[n] = '\0';
            printf("%s", buffer);

            if (strncmp(buffer, "227", 3) == 0) {
                char data_ip[INET_ADDRSTRLEN];
                int data_port;
                if (parse_pasv_response(buffer, data_ip, &data_port) == 0) {
                    SSL *data_ssl = connect_to_data_port_ssl(data_ip, data_port, ctx); // NEW: Use SSL version
                    if (data_ssl != NULL) { // NEW: Check SSL object
                        // Receive next response (expect 150) using control SSL
                        n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
                        if (n <= 0) {
                             fprintf(stderr, "SSL_read failed waiting for 150 (error code: %d)\n", SSL_get_error(ssl, n));
                             ERR_print_errors_fp(stderr);
                             SSL_shutdown(data_ssl); SSL_free(data_ssl); // close(data_sock); // OLD
                             break;
                        }
                        buffer[n] = '\0';
                        printf("%s", buffer);

                        if (strncmp(buffer, "150", 3) == 0) {
                            // Send file data using data SSL
                            ssize_t bytes_read, bytes_sent;
                            while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
                                bytes_sent = SSL_write(data_ssl, buffer, bytes_read); // NEW: Use SSL_write
                                if (bytes_sent <= 0) {
                                    fprintf(stderr, "SSL_write data failed (code: %d)\n", SSL_get_error(data_ssl, bytes_sent));
                                    ERR_print_errors_fp(stderr);
                                    break;
                                }
                                // Note: SSL_write might send less than requested, proper handling would loop
                                // if (bytes_sent < bytes_read) { ... }
                            }
                            if (ferror(fp)) {
                                perror("Local file read error");
                            }
                            printf("File transfer initiated (SSL)...\n");
                        }
                        SSL_shutdown(data_ssl); // NEW: Initiate SSL shutdown
                        SSL_free(data_ssl);     // NEW: Free SSL object (closes underlying socket)

                        // Receive final response (expect 226) using control SSL
                        n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
                        if (n <= 0) {
                             fprintf(stderr, "SSL_read failed waiting for 226 (error code: %d)\n", SSL_get_error(ssl, n));
                             ERR_print_errors_fp(stderr);
                             break;
                        }
                        buffer[n] = '\0';
                        printf("%s", buffer);
                    } else { // Handle data_ssl connection failure
                         fprintf(stderr, "Failed to establish SSL data connection.\n");
                         // Server might still be waiting, maybe send ABOR? For now, just continue.
                    }
                } else { // Handle PASV parse failure
                     fprintf(stderr, "Failed to parse PASV response for UP.\n");
                }
            } else { // Handle non-227 response
                 fprintf(stderr, "Server did not enter passive mode for UP.\n");
            }
            fclose(fp);
            printf("ftp> ");
            continue;
        }
        // Handle DOWN command
        else if (strncmp(user_input, "DOWN ", 5) == 0) {
            char *filename = user_input + 5;
            if (!is_path_valid_client(filename)) {
                fprintf(stderr, "Error: Invalid local filename (contains '..').\n");
                printf("ftp> ");
                continue;
            }
            if (strlen(filename) > MAX_FILENAME_LEN) {
                fprintf(stderr, "Error: Filename too long: %s\n", filename);
                printf("ftp> ");
                continue;
            }

            // Send DOWN command to server using SSL
            snprintf(command, sizeof(command), "DOWN %s\r\n", filename);
            if (SSL_write(ssl, command, strlen(command)) <= 0) { // NEW: Use SSL_write
                perror("SSL_write DOWN command failed");
                ERR_print_errors_fp(stderr);
                break;
            }

            // Receive response (expect 227 or 550) using SSL
            int n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
            if (n <= 0) {
                 fprintf(stderr, "SSL_read failed after DOWN command (error code: %d)\n", SSL_get_error(ssl, n));
                 ERR_print_errors_fp(stderr);
                 break;
            }
            buffer[n] = '\0';
            printf("%s", buffer);

            if (strncmp(buffer, "227", 3) == 0) {
                char data_ip[INET_ADDRSTRLEN];
                int data_port;
                if (parse_pasv_response(buffer, data_ip, &data_port) == 0) {
                    SSL *data_ssl = connect_to_data_port_ssl(data_ip, data_port, ctx); // NEW: Use SSL version
                    if (data_ssl != NULL) { // NEW: Check SSL object
                        // Receive next response (expect 150) using control SSL
                        n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
                        if (n <= 0) {
                             fprintf(stderr, "SSL_read failed waiting for 150 (error code: %d)\n", SSL_get_error(ssl, n));
                             ERR_print_errors_fp(stderr);
                             SSL_shutdown(data_ssl); SSL_free(data_ssl); // close(data_sock); // OLD
                             break;
                        }
                        buffer[n] = '\0';
                        printf("%s", buffer);

                        if (strncmp(buffer, "150", 3) == 0) {
                            FILE *fp = fopen(filename, "wb");
                            if (!fp) {
                                perror("Local file open failed for writing");
                                // How to notify server? Not easy in basic FTP without ABOR
                                // Close data connection gracefully anyway
                                SSL_shutdown(data_ssl); SSL_free(data_ssl); // close(data_sock); // OLD
                            } else {
                                // Receive file data using data SSL
                                ssize_t bytes_received;
                                while ((bytes_received = SSL_read(data_ssl, buffer, BUFFER_SIZE)) > 0) { // NEW: Use SSL_read
                                    fwrite(buffer, 1, bytes_received, fp);
                                }
                                // Check SSL_read error status
                                int ssl_error = SSL_get_error(data_ssl, bytes_received);
                                if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_NONE) {
                                     fprintf(stderr, "SSL_read data failed (code: %d)\n", ssl_error);
                                     ERR_print_errors_fp(stderr);
                                     // File might be incomplete
                                }
                                fclose(fp);
                                printf("File transfer initiated (SSL)...\n");
                            }
                        }
                        SSL_shutdown(data_ssl); // NEW: Initiate SSL shutdown
                        SSL_free(data_ssl);     // NEW: Free SSL object

                        // Receive final response (expect 226) using control SSL
                        n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
                        if (n <= 0) {
                             fprintf(stderr, "SSL_read failed waiting for 226 (error code: %d)\n", SSL_get_error(ssl, n));
                             ERR_print_errors_fp(stderr);
                             break;
                        }
                        buffer[n] = '\0';
                        printf("%s", buffer);
                    } else { // Handle data_ssl connection failure
                         fprintf(stderr, "Failed to establish SSL data connection.\n");
                    }
                } else { // Handle PASV parse failure
                     fprintf(stderr, "Failed to parse PASV response for DOWN.\n");
                }
            } else if (strncmp(buffer, "550", 3) == 0) {
                 // Server reported file not found or other error, no data connection expected.
                 fprintf(stderr, "Server reported error: %s", buffer); // Print the 550 message
            } else {
                 fprintf(stderr, "Unexpected response after DOWN command: %s", buffer);
            }
            printf("ftp> ");
            continue;
        }

        // Prepare command for server
        if (strlen(user_input) + 2 > sizeof(command) -1) { // +2 for \r\n
             fprintf(stderr, "Error: Command too long: %s\n", user_input);
             printf("ftp> ");
             continue;
        }
        strncpy(command, user_input, sizeof(command) - 3); // Leave space for \r\n\0
        command[sizeof(command) - 3] = '\0'; // Ensure null termination if strncpy truncated
        strcat(command, "\r\n");

        // Send command to server using SSL
        if (SSL_write(ssl, command, strlen(command)) <= 0) { // NEW: Use SSL_write
            int ssl_error = SSL_get_error(ssl, -1); // Use -1 as SSL_write returns <= 0 on error
            if (ssl_error == SSL_ERROR_SYSCALL) {
                 if (errno == EAGAIN || errno == EWOULDBLOCK) {
                     fprintf(stderr, "Error: SSL_write timeout occurred.\n");
                 } else {
                     perror("SSL_write failed (SYSCALL)");
                 }
            } else {
                fprintf(stderr, "SSL_write failed (error code: %d)\n", ssl_error);
                ERR_print_errors_fp(stderr);
            }
            break;
        }

        // Receive response from server using SSL
        int n = SSL_read(ssl, buffer, BUFFER_SIZE - 1); // NEW: Use SSL_read
        if (n <= 0) {
            int ssl_error = SSL_get_error(ssl, n);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                printf("Server closed SSL connection gracefully.\n");
            } else if (ssl_error == SSL_ERROR_SYSCALL) {
                 if (errno == EAGAIN || errno == EWOULDBLOCK) {
                     fprintf(stderr, "Error: SSL_read timeout occurred.\n");
                 } else if (n == 0) { // Check underlying socket EOF
                     printf("Server disconnected abruptly (socket closed).\n");
                 } else {
                     perror("SSL_read failed (SYSCALL)");
                 }
            } else {
                fprintf(stderr, "SSL_read failed (error code: %d)\n", ssl_error);
                ERR_print_errors_fp(stderr);
            }
            break;
        }

        buffer[n] = '\0';
        printf("%s", buffer); // Print server response

        // Check if the command was QUIT and server responded appropriately
        if (strncmp(command, "QUIT", 4) == 0 && strncmp(buffer, "221", 3) == 0) {
            break; // Exit loop after QUIT acknowledged
        }
         printf("ftp> ");
    }

    // Clean up SSL connection before closing socket
    if (ssl) {
        SSL_shutdown(ssl); // Initiate SSL shutdown
        SSL_free(ssl);
        g_control_ssl = NULL; // Clear global pointer if used
    }

    // Close the control socket (already done by SSL_free)
    // if (g_control_sock != -1) {
    //     close(g_control_sock);
    // }
    printf("Connection closed.\n");

    // Clean up SSL context
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    cleanup_openssl_client(); // Call general OpenSSL cleanup if needed

    return 0;
}
