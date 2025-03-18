#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <getopt.h>
#include <sys/wait.h>

// Default port (can be overridden with -p flag)
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024
#define LOG_FILE "/tmp/server_log.txt"
#define MAX_FILENAME 256

// Global configuration that can be overwritten to trigger data-only attacks
char log_file_path[MAX_FILENAME] = LOG_FILE;
char data_directory[MAX_FILENAME] = "/tmp";

// Function to log a message to file
void log_message(const char *message) {
    // Open log file
    int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("Failed to open log file");
        return;
    }
    
    // Write message
    write(fd, message, strlen(message));
    write(fd, "\n", 1);
    
    // Close file
    close(fd);
}

// Function to handle a file read request
void handle_read_file(const char *filename, int client_socket) {
    printf("Handling READ request for file: %s\n", filename);
    char path[MAX_FILENAME * 2];
    char buffer[BUFFER_SIZE];
    
    // Create full path by combining data directory and filename
    snprintf(path, sizeof(path), "%s/%s", data_directory, filename);
    
    // Log the file access attempt
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "Attempting to read file: %s", path);
    log_message(log_msg);
    
    // Open the file
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *error_msg = "Error: File not found\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        return;
    }
    
    // Read and send file contents
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }
    
    // Close file
    close(fd);
}

// Function to handle a file write request
void handle_write_file(const char *filename, const char *content, int client_socket) {
    printf("Handling WRITE request for file: %s\n", filename);
    char path[MAX_FILENAME * 2];
    
    // Create full path by combining data directory and filename
    snprintf(path, sizeof(path), "%s/%s", data_directory, filename);
    
    // Log the file write attempt
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "Attempting to write to file: %s", path);
    log_message(log_msg);
    
    // Open the file
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        const char *error_msg = "Error: Cannot write to file\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        return;
    }
    
    // Write content to file
    write(fd, content, strlen(content));
    
    // Close file
    close(fd);
    
    // Send success response
    const char *success_msg = "File written successfully\n";
    send(client_socket, success_msg, strlen(success_msg), 0);
}

// Function to handle executing a command
void handle_execute(const char *command, int client_socket) {
    printf("Handling EXECUTE request: %s\n", command);
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "Executing command: %s", command);
    log_message(log_msg);
    
    // Create pipes for capturing command output
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        const char *error_msg = "Error: Failed to create pipe\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        return;
    }
    
    // Fork a new process
    pid_t pid = fork();
    
    if (pid == -1) {
        // Fork failed
        const char *error_msg = "Error: Fork failed\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    } else if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close read end
        
        // Redirect stdout and stderr to the pipe
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        // Split the command into args
        char *args[64] = {NULL};
        char cmd_copy[BUFFER_SIZE];
        strncpy(cmd_copy, command, BUFFER_SIZE - 1);
        cmd_copy[BUFFER_SIZE - 1] = '\0';
        
        // Parse command into args array
        char *token = strtok(cmd_copy, " ");
        int i = 0;
        while (token != NULL && i < 63) {
            args[i++] = token;
            token = strtok(NULL, " ");
        }
        args[i] = NULL;
        
        // Determine path to executable
        char *path = args[0];
        
        // Create environment variables (empty for simplicity)
        char *envp[] = {NULL};
        
        // Execute the command using execve
        execve(path, args, envp);
        
        // If execve returns, it failed
        fprintf(stderr, "Error: execve failed: %s\n", path);
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        close(pipefd[1]); // Close write end
        
        // Read and send output from the pipe
        char buffer[BUFFER_SIZE];
        ssize_t bytes_read;
        
        while ((bytes_read = read(pipefd[0], buffer, BUFFER_SIZE - 1)) > 0) {
            buffer[bytes_read] = '\0';
            send(client_socket, buffer, bytes_read, 0);
        }
        
        close(pipefd[0]);
        
        // Wait for child to complete
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            char error_buf[BUFFER_SIZE];
            snprintf(error_buf, BUFFER_SIZE, "Command exited with status %d\n", WEXITSTATUS(status));
            send(client_socket, error_buf, strlen(error_buf), 0);
        }
    }
}

// Main function to handle client requests
void handle_client(int client_socket) {
    printf("New client connection accepted\n");
    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_received;
    
    // Receive client request
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        printf("No data received from client or error\n");
        return;
    }
    
    // Ensure null termination
    buffer[bytes_received] = '\0';
    
    // Log the request
    char log_msg[BUFFER_SIZE + 32];
    snprintf(log_msg, sizeof(log_msg), "Received request: %s", buffer);
    log_message(log_msg);
    
    // Parse the request
    printf("Parsing request: %s\n", buffer);
    char *token = strtok(buffer, " ");
    if (token == NULL) {
        const char *error_msg = "Error: Invalid request format\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        printf("Sent error: Invalid request format\n");
        return;
    }
    
    // Handle different request types
    if (strcmp(token, "READ") == 0) {
        token = strtok(NULL, "\n");
        if (token) {
            handle_read_file(token, client_socket);
        }
    } else if (strcmp(token, "WRITE") == 0) {
        char *filename = strtok(NULL, " ");
        char *content = strtok(NULL, "\n");
        if (filename && content) {
            handle_write_file(filename, content, client_socket);
        }
    } else if (strcmp(token, "EXECUTE") == 0) {
        token = strtok(NULL, "\n");
        if (token) {
            handle_execute(token, client_socket);
        }
    } else if (strcmp(token, "CONFIG") == 0) {
        char *key = strtok(NULL, " ");
        char *value = strtok(NULL, "\n");
        
        if (key && value) {
            if (strcmp(key, "LOG_PATH") == 0) {
                strncpy(log_file_path, value, MAX_FILENAME - 1);
                log_file_path[MAX_FILENAME - 1] = '\0';
            } else if (strcmp(key, "DATA_DIR") == 0) {
                strncpy(data_directory, value, MAX_FILENAME - 1);
                data_directory[MAX_FILENAME - 1] = '\0';
            }
            
            const char *success_msg = "Configuration updated\n";
            send(client_socket, success_msg, strlen(success_msg), 0);
        }
    } else {
        const char *error_msg = "Error: Unknown command\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        printf("Sent error: Unknown command '%s'\n", token);
    }
    
    printf("Client request handling completed\n");
}

// Function to print usage information
void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -p, --port PORT    Set server port (default: %d)\n", DEFAULT_PORT);
    printf("  -h, --help         Display this help message\n");
}

int main(int argc, char **argv) {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = DEFAULT_PORT;
    
    // Parse command line options
    int opt;
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "p:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Error: Invalid port number. Must be between 1-65535.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int sock_opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server started on port %d\n", port);
    
    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "Server started on port %d", port);
    log_message(log_buf);
    
    // Accept and handle client connections
    while (1) {
        // Accept a connection
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Handle client request
        handle_client(client_socket);
        
        // Close client socket
        close(client_socket);
    }
    
    // Close server socket
    close(server_fd);
    
    return 0;
}