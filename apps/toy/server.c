#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/select.h>

// Default port (can be overridden with -p flag)
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024
#define UDS


// Global variables for cleanup
int tcp_fd = -1;
int uds_fd = -1;
char *cmd_ls = "/bin/ls";
char *cmd_exec = "/bin/bash";
char *cmd_echo = "/bin/echo";
char *path = "/tmp/attack.sh";
char *args[3] = {NULL, NULL, NULL};

void execute_ls() {
    printf("Executing: %s %s\n", cmd_ls, path);

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        return;
    } else if (pid == 0) {
        args[0] = cmd_ls;
        args[1] = path;
        args[2] = NULL;
        execve(cmd_ls, args, NULL);
        perror("execve failed");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}

void execute_exec() {
    printf("Executing: %s %s\n", cmd_exec, path);

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        return;
    } else if (pid == 0) {
        args[0] = cmd_exec;
        args[1] = path;
        args[2] = NULL;
        execve(cmd_exec, args, NULL);
        perror("execve failed");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}

void execute_echo() {
    printf("Writing to file: %s\n", path);

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        return;
    } else if (pid == 0) {
        // Open file for writing
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd == -1) {
            perror("File open failed");
            exit(EXIT_FAILURE);
        }

        // Redirect stdout to the file
        dup2(fd, STDOUT_FILENO);
        close(fd);

        // Execute echo
        args[0] = cmd_echo;
        args[1] = "touch /tmp/attacker-was-here";
        args[2] = NULL;
        execve(cmd_echo, args, NULL);

        perror("execve failed");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (chmod(path, 0755) == -1) {
            perror("chmod failed");
        } else {
            printf("Set file to executable: %s\n", path);
        }
    }
}

void handle_execute(char *token) {
    if (strcmp(token, "ls") == 0) {
        execute_ls();
    } else if (strcmp(token, "echo") == 0) {
        execute_echo();
    } else if(strcmp(token,"exec") == 0){
        execute_exec();
    }
}

void handle_client(int client_socket, int is_uds) {
    char buffer[BUFFER_SIZE] = {0};
    
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        return;
    }
    
    buffer[bytes_received] = '\0';

    if (is_uds) {
        printf("Received UDS command: %s\n", buffer);
        const char *response = "OK\n";
        send(client_socket, response, strlen(response), 0);
        return;
    }

    char *token = strtok(buffer, " ");

    if (token == NULL) {
        return;
    }

    if (strcmp(token, "EXECUTE") == 0) {
        token = strtok(NULL, "\n");
        if (token) {
            handle_execute(token);
        }
    } else if (strcmp(token, "SET") == 0) {
        token = strtok(NULL, "\n");
        if (token) {
            path = strdup(token);
            printf("Set the path to %s\n", path);
        }
    }
}


int main(int argc, char **argv) {
    struct sockaddr_in tcp_addr;
    int addrlen = sizeof(tcp_addr);
    int port = DEFAULT_PORT;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    // Create TCP socket
    if ((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("TCP socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int sock_opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
    
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_port = htons(port);
    
    if (bind(tcp_fd, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) < 0) {
        perror("TCP bind failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }
    
    if (listen(tcp_fd, 5) < 0) {
        perror("TCP listen failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }

    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(tcp_fd, &master_fds);

#ifdef UDS
    // Create UDS socket
    uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (uds_fd < 0) {
        perror("UDS socket creation failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }
    
    // Get process ID
    pid_t pid = getpid();
    printf("Server PID: %d\n", pid);
    
    // Get CMDDIR from environment or default to /tmp
    const char *cmd_dir = getenv("CMDDIR");
    if (!cmd_dir) cmd_dir = "/tmp";
    
    // Create socket path
    char *socket_path = malloc(strlen(cmd_dir) + 32);
    sprintf(socket_path, "%s/dbt.cmd.%d", cmd_dir, pid);

    

    printf("Creating UDS socket at: %s\n", socket_path);
    
    // Remove existing socket file
    unlink(socket_path);
    
    // Bind UDS socket
    struct sockaddr_un uds_addr;
    memset(&uds_addr, 0, sizeof(uds_addr));
    uds_addr.sun_family = AF_UNIX;
    strncpy(uds_addr.sun_path, socket_path, sizeof(uds_addr.sun_path) - 1);
    
    if (bind(uds_fd, (struct sockaddr *)&uds_addr, sizeof(uds_addr)) < 0) {
        perror("UDS bind failed");
        close(tcp_fd);
        close(uds_fd);
        exit(EXIT_FAILURE);
    }
    
    // Make socket accessible to all users
    chmod(socket_path, 0666);
    
    if (listen(uds_fd, 5) < 0) {
        perror("UDS listen failed");
        close(tcp_fd);
        close(uds_fd);
        unlink(socket_path);
        exit(EXIT_FAILURE);
    }
    
    printf("Server started on TCP port %d and UDS socket %s (PID: %d)\n", 
           port, socket_path, pid);
    
    // Set up select to monitor both sockets
   
    FD_SET(uds_fd, &master_fds);
#endif

    int max_fd = (tcp_fd > uds_fd) ? tcp_fd : uds_fd;
    
    while (1) {
        read_fds = master_fds;
        
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, just continue
                continue;
            }
            perror("select failed");
            break;
        }
        
        // Check for TCP connections
        if (FD_ISSET(tcp_fd, &read_fds)) {
            int client_socket = accept(tcp_fd, (struct sockaddr *)&tcp_addr, (socklen_t*)&addrlen);
            if (client_socket < 0) continue;
            
            handle_client(client_socket, 0);  // 0 = TCP
            close(client_socket);
        }

#ifdef UDS
        // Check for UDS connections
        if (FD_ISSET(uds_fd, &read_fds)) {
            struct sockaddr_un client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_socket = accept(uds_fd, (struct sockaddr*)&client_addr, &addr_len);
            if (client_socket < 0) continue;
            
            handle_client(client_socket, 1);  // 1 = UDS
            close(client_socket);
        }
#endif

    }
    
    return 0;
}