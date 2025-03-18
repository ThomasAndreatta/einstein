#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SERVER_IP "127.0.0.1"

// Function to send a request to the server and print the response
void send_request(const char *request) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return;
    }
    
    // Configure server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IP address to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address or address not supported\n");
        close(sock);
        return;
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection failed\n");
        close(sock);
        return;
    }
    
    // Send request
    send(sock, request, strlen(request), 0);
    printf("Request sent: %s\n", request);
    
    // Receive and print response
    int bytes_received = 0;
    int total_received = 0;
    
    printf("\nResponse:\n");
    while ((bytes_received = read(sock, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);
        total_received += bytes_received;
        
        // Clear buffer for next read
        memset(buffer, 0, BUFFER_SIZE);
    }
    printf("\n");
    
    if (total_received == 0) {
        printf("No response received from server\n");
    }
    
    // Close socket
    close(sock);
}

// Print usage instructions
void print_usage() {
    printf("Usage:\n");
    printf("  READ <filename> - Read a file from the server\n");
    printf("  WRITE <filename> <content> - Write content to a file on the server\n");
    printf("  EXECUTE <command> - Execute a command on the server\n");
    printf("  CONFIG LOG_PATH <path> - Change the log file path\n");
    printf("  CONFIG DATA_DIR <directory> - Change the data directory\n");
}

int main(int argc, char **argv) {
    // Check for command line arguments
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    // Build request string from command line arguments
    char request[BUFFER_SIZE] = {0};
    
    for (int i = 1; i < argc; i++) {
        strcat(request, argv[i]);
        if (i < argc - 1) {
            strcat(request, " ");
        }
    }
    
    // Send request to server
    send_request(request);
    
    return 0;
}