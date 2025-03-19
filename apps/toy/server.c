#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <getopt.h>

// Default port (can be overridden with -p flag)
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024

// Function to handle executing a command
void handle_execute(const char *command) {
    printf("Handling EXECUTE request: %s\n", command);
    
    pid_t pid = fork();
    
    if (pid == -1) {
        printf("Error: Fork failed\n");
        return;
    } else if (pid == 0) {
        
        char *args[64] = {NULL};
        char cmd_copy[BUFFER_SIZE];
        strncpy(cmd_copy, command, BUFFER_SIZE - 1);
        cmd_copy[BUFFER_SIZE - 1] = '\0';
        
        char *token = strtok(cmd_copy, " ");
        int i = 0;
        while (token != NULL && i < 63) {
            args[i++] = token;
            token = strtok(NULL, " ");
        }
        args[i] = NULL;
        
        execve(args[0], args, NULL);
        
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
        
    }
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0) {
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    char *token = strtok(buffer, " ");
    
    if (token == NULL) {
        return;
    }
    
    if (strcmp(token, "EXECUTE") == 0) {
        token = strtok(NULL, "\n");
        if (token) {
            handle_execute(token);
        }
    }
}

int main(int argc, char **argv) {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = DEFAULT_PORT;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int sock_opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    listen(server_fd, 5);
    
    printf("Server started on port %d\n", port);
    
    while (1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;
        
        handle_client(client_socket);
        
        close(client_socket);
    }
    
    return 0;
}