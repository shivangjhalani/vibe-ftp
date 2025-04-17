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

#define BUFFER_SIZE 4096 // Increased buffer for file transfer
#define MAX_FILENAME_LEN (BUFFER_SIZE - 128) // Increased reserve space
#define SOCKET_TIMEOUT_SEC 60 // Timeout for send/recv in seconds

// Global variable for control socket (for signal handler)
int g_control_sock = -1;

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

int main(int argc, char *argv[]) {
    int control_sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char command[BUFFER_SIZE] = {0};
    char user_input[BUFFER_SIZE] = {0};
    char server_ip_arg[INET_ADDRSTRLEN]; // Store original server IP

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

    // Create socket
    if ((control_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
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
        return 1;
    }

    // Connect to the server
    if (connect(control_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(control_sock);
        g_control_sock = -1;
        return 1;
    }

    // Set timeouts for the control socket
    if (set_socket_timeouts_client(control_sock) < 0) {
        fprintf(stderr, "Failed to set timeouts for control socket\n");
        close(control_sock);
        g_control_sock = -1;
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

            // Send UP command to server
            snprintf(command, sizeof(command), "UP %s\r\n", filename);
            if (send(control_sock, command, strlen(command), 0) < 0) {
                perror("Send UP command failed");
                fclose(fp);
                break;
            }

            // Receive response (expect 227)
            int n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
            if (n <= 0) { /* Handle error/disconnect */ break; }
            buffer[n] = '\0';
            printf("%s", buffer);

            if (strncmp(buffer, "227", 3) == 0) {
                char data_ip[INET_ADDRSTRLEN];
                int data_port;
                // Use server_ip_arg for simplicity, though parsing buffer is more robust
                if (parse_pasv_response(buffer, data_ip, &data_port) == 0) {
                    int data_sock = connect_to_data_port(data_ip, data_port);
                    if (data_sock >= 0) {
                        // Receive next response (expect 150)
                        n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
                        if (n <= 0) { /* Handle error/disconnect */ close(data_sock); break; }
                        buffer[n] = '\0';
                        printf("%s", buffer);

                        if (strncmp(buffer, "150", 3) == 0) {
                            // Send file data
                            ssize_t bytes_read, bytes_sent;
                            while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
                                bytes_sent = send(data_sock, buffer, bytes_read, 0);
                                if (bytes_sent < 0) {
                                    perror("Send data failed");
                                    break;
                                }
                                if (bytes_sent < bytes_read) {
                                     fprintf(stderr, "Warning: Partial send during upload.\n");
                                     break; // Simplistic handling
                                }
                            }
                            if (ferror(fp)) {
                                perror("Local file read error");
                            }
                            printf("File transfer initiated...\n");
                        }
                        close(data_sock); // Close data connection after sending

                        // Receive final response (expect 226)
                        n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
                        if (n <= 0) { /* Handle error/disconnect */ break; }
                        buffer[n] = '\0';
                        printf("%s", buffer);
                    }
                }
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

            // Send DOWN command to server
            snprintf(command, sizeof(command), "DOWN %s\r\n", filename);
            if (send(control_sock, command, strlen(command), 0) < 0) {
                perror("Send DOWN command failed");
                break;
            }

            // Receive response (expect 227 or 550)
            int n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
            if (n <= 0) { /* Handle error/disconnect */ break; }
            buffer[n] = '\0';
            printf("%s", buffer);

            if (strncmp(buffer, "227", 3) == 0) {
                char data_ip[INET_ADDRSTRLEN];
                int data_port;
                if (parse_pasv_response(buffer, data_ip, &data_port) == 0) {
                    int data_sock = connect_to_data_port(data_ip, data_port);
                    if (data_sock >= 0) {
                        // Receive next response (expect 150)
                        n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
                        if (n <= 0) { /* Handle error/disconnect */ close(data_sock); break; }
                        buffer[n] = '\0';
                        printf("%s", buffer);

                        if (strncmp(buffer, "150", 3) == 0) {
                            FILE *fp = fopen(filename, "wb");
                            if (!fp) {
                                perror("Local file open failed for writing");
                                // How to notify server? Not easy in basic FTP without ABOR
                            } else {
                                // Receive file data
                                ssize_t bytes_received;
                                while ((bytes_received = recv(data_sock, buffer, BUFFER_SIZE, 0)) > 0) {
                                    fwrite(buffer, 1, bytes_received, fp);
                                }
                                if (bytes_received < 0) {
                                    perror("Recv data failed");
                                }
                                fclose(fp);
                                printf("File transfer initiated...\n");
                            }
                        }
                        close(data_sock); // Close data connection after receiving

                        // Receive final response (expect 226)
                        n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
                        if (n <= 0) { /* Handle error/disconnect */ break; }
                        buffer[n] = '\0';
                        printf("%s", buffer);
                    }
                }
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

        // Send command to server
        if (send(control_sock, command, strlen(command), 0) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                 fprintf(stderr, "Error: Send timeout occurred.\n");
                 // Optionally break or retry
            } else {
                perror("Send failed");
            }
            break;
        }

        // Receive response from server
        int n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                 fprintf(stderr, "Error: Receive timeout occurred.\n");
                 // Optionally break or retry
            } else {
                perror("Recv failed");
            }
            break;
        } else if (n == 0) {
            printf("Server closed connection.\n");
            break;
        }

        buffer[n] = '\0';
        printf("%s", buffer); // Print server response (includes \r\n)

        // Check if the command was QUIT and server responded appropriately (e.g., 221)
        // A more robust check would parse the response code.
        if (strncmp(command, "QUIT", 4) == 0 && strncmp(buffer, "221", 3) == 0) {
            break; // Exit loop after QUIT acknowledged
        }
         printf("ftp> ");
    }

    // Close the control socket
    if (g_control_sock != -1) {
        close(g_control_sock);
    }
    printf("Connection closed.\n");

    return 0;
}
