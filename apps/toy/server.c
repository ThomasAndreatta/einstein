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
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

// Default port (can be overridden with -p flag)
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024
#define UDS_

// Function to get current instruction pointer (PC)
static inline void *get_pc()
{
    return __builtin_return_address(0);
}

void handle_client(int client_socket, int is_uds);

// Function to print current PC with context
#define PRINT_PC(context)                     \
    do                                        \
    {                                         \
        void *pc = get_pc();                  \
        printf("[PC] %s: %p\n", context, pc); \
    } while (0)

// Global variables for cleanup
int tcp_fd = -1;
int uds_fd = -1;
char *cmd_ls = "/bin/ls";
char *cmd_exec = "/bin/bash";
char *cmd_echo = "/bin/echo";
char *path = "/tmp/attack.sh";
int fd;
mode_t mode = S_IRUSR; // 0644 permissions

char *args[3] = {NULL, NULL, NULL};

void execute_ls()
{
    // PRINT_PC("execute_ls entry");

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("Fork failed");
        return;
    }
    else if (pid == 0)
    {
        args[0] = cmd_ls;
        args[1] = path;
        args[2] = NULL;

        // PRINT_PC("before execve in execute_ls");
        execve(cmd_ls, args, NULL);
        perror("execve failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
    }
}

void execute_exec()
{
    // PRINT_PC("execute_exec entry");

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("Fork failed");
        return;
    }
    else if (pid == 0)
    {
        args[0] = cmd_exec;
        args[1] = path;
        args[2] = NULL;

        // PRINT_PC("before execve in execute_exec");
        execve(cmd_exec, args, NULL);
        perror("execve failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
    }
}

volatile uid_t euid = 1024;

void *mmap_addr = NULL;
size_t mmap_length = 4096;
int mmap_prot = PROT_READ;
int mmap_flags = MAP_PRIVATE;
int mmap_fd;
off_t mmap_offset = 0;

void random_function(){
    fprintf(stderr,"Im just a random function to change some addresses\n");
    for (volatile int i = 0; i < 1000; i++)
        fprintf(stderr,"%d",i);
    
}
void execute_echo()
{
    // PRINT_PC("execute_echo entry");
    
    random_function();
    
    void *mapped_addr = mmap(mmap_addr, mmap_length, mmap_prot, mmap_flags,
                             mmap_fd, mmap_offset);

    // PRINT_PC("after syscall call");

    // printf("handle_client function address: %p\n", (void *)handle_client);
    // printf("Address of mmap_prot: %p\n", &mmap_prot);
    // printf("======================\n");

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("Fork failed");
        return;
    }
    else if (pid == 0)
    {
        // Open file for writing
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (fd == -1)
        {
            perror("File open failed");
            exit(EXIT_FAILURE);
        }

        dup2(fd, STDOUT_FILENO);
        close(fd);
        
        args[0] = cmd_echo;
        args[1] = "touch /tmp/attacker-was-here";
        args[2] = NULL;

        // printf("Address of cmd_echo: %p\n", (void *)cmd_echo);
        // printf("Address of args: %p\n", (void *)args);


        // PRINT_PC("before execve in execute_echo");
        execve(cmd_echo, args, NULL);

        perror("execve failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);

        if (chmod(path, 0755) == -1)
        {
            perror("chmod failed");
        }
    }
}

void handle_execute(char *token)
{
    // PRINT_PC("handle_execute entry");

    if (strcmp(token, "ls") == 0)
    {
        execute_ls();
    }
    else if (strcmp(token, "echo") == 0)
    {
        execute_echo();
    }
    else if (strcmp(token, "exec") == 0)
    {
        execute_exec();
    }
}

void handle_client(int client_socket, int is_uds)
{
    // PRINT_PC("handle_client entry");

    char buffer[BUFFER_SIZE] = {0};

    // printf("=== CLIENT HANDLING ===\n");
    // printf("Function address: %p\n", (void *)handle_client);
    // printf("Buffer address: %p\n", (void *)buffer);
    // printf("Client socket: %d\n", client_socket);
    // printf("Is UDS: %d\n", is_uds);
    // printf("=======================\n");

    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0)
    {
        return;
    }

    buffer[bytes_received] = '\0';

    if (is_uds)
    {
        const char *response = "OK\n";
        send(client_socket, response, strlen(response), 0);
        return;
    }

    char *token = strtok(buffer, " ");

    if (token == NULL)
    {
        return;
    }

    if (strcmp(token, "EXECUTE") == 0)
    {
        token = strtok(NULL, "\n");
        if (token)
        {
            handle_execute(token);
        }
    }
    else if (strcmp(token, "SET") == 0)
    {
        token = strtok(NULL, "\n");
        if (token)
        {
            path = strdup(token);
            // printf("Set the path to %s\n", path);
        }
    }
}

int main(int argc, char **argv)
{
    // PRINT_PC("main entry");
    mmap_fd = open("/tmp/mmap_test", O_RDWR | O_CREAT, 0644);
    struct sockaddr_in tcp_addr;
    int addrlen = sizeof(tcp_addr);
    int port = DEFAULT_PORT;

    if (argc > 1)
    {
        port = atoi(argv[1]);
    }

    // printf("=== SERVER STARTUP ===\n");
    // printf("Main function address: %p\n", (void *)main);
    // printf("TCP addr struct address: %p\n", (void *)&tcp_addr);
    // printf("Port: %d\n", port);
    // printf("======================\n");

    // Create TCP socket
    if ((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("TCP socket creation failed");
        exit(EXIT_FAILURE);
    }

    int sock_opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));

    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_port = htons(port);

    // printf("=== BIND OPERATION ===\n");
    // PRINT_PC("before bind call");
    // printf("TCP socket fd: %d\n", tcp_fd);
    // printf("Address structure: family=%d, addr=%u, port=%d\n",
    //       tcp_addr.sin_family, tcp_addr.sin_addr.s_addr, ntohs(tcp_addr.sin_port));

    if (bind(tcp_fd, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) < 0)
    {
        perror("TCP bind failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }
    // PRINT_PC("after bind call");
    // printf("======================\n");

    if (listen(tcp_fd, 5) < 0)
    {
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
    if (uds_fd < 0)
    {
        perror("UDS socket creation failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }

    // Get process ID
    pid_t pid = getpid();
    // printf("Server PID: %d\n", pid);

    // Get CMDDIR from environment or default to /tmp
    const char *cmd_dir = getenv("CMDDIR");
    if (!cmd_dir)
        cmd_dir = "/tmp";

    // Create socket path
    char *socket_path = malloc(strlen(cmd_dir) + 32);
    sprintf(socket_path, "%s/dbt.cmd.%d", cmd_dir, pid); // Fixed the sprintf

    // printf("Creating UDS socket at: %s\n", socket_path);

    // Remove existing socket file
    unlink(socket_path);

    // Bind UDS socket
    struct sockaddr_un uds_addr;
    memset(&uds_addr, 0, sizeof(uds_addr));
    uds_addr.sun_family = AF_UNIX;
    strncpy(uds_addr.sun_path, socket_path, sizeof(uds_addr.sun_path) - 1);

    if (bind(uds_fd, (struct sockaddr *)&uds_addr, sizeof(uds_addr)) < 0)
    {
        perror("UDS bind failed");
        close(tcp_fd);
        close(uds_fd);
        exit(EXIT_FAILURE);
    }

    // Make socket accessible to all users
    chmod(socket_path, 0666);

    if (listen(uds_fd, 5) < 0)
    {
        perror("UDS listen failed");
        close(tcp_fd);
        close(uds_fd);
        unlink(socket_path);
        exit(EXIT_FAILURE);
    }

    // printf("Server started on TCP port %d and UDS socket %s (PID: %d)\n",
           port, socket_path, pid);

    // Set up select to monitor both sockets
    FD_SET(uds_fd, &master_fds);
#endif

    int max_fd = (tcp_fd > uds_fd) ? tcp_fd : uds_fd;

    // printf("=== SERVER LISTENING ===\n");
    // printf("Max FD: %d\n", max_fd);
    // PRINT_PC("entering main loop");
    // printf("========================\n");

    while (1)
    {
        read_fds = master_fds;
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0)
        {
            if (errno == EINTR)
            {
                // Interrupted by signal, just continue
                continue;
            }
            perror("select failed");
            break;
        }

        // Check for TCP connections
        if (FD_ISSET(tcp_fd, &read_fds))
        {
            // PRINT_PC("before TCP accept");
            int client_socket = accept(tcp_fd, (struct sockaddr *)&tcp_addr, (socklen_t *)&addrlen);
            if (client_socket < 0)
                continue;

            handle_client(client_socket, 0); // 0 = TCP
            close(client_socket);
        }

#ifdef UDS
        // Check for UDS connections
        if (FD_ISSET(uds_fd, &read_fds))
        {
            struct sockaddr_un client_addr;
            socklen_t addr_len = sizeof(client_addr);

            // PRINT_PC("before UDS accept");
            int client_socket = accept(uds_fd, (struct sockaddr *)&client_addr, &addr_len);
            if (client_socket < 0)
                continue;

            handle_client(client_socket, 1); // 1 = UDS
            close(client_socket);
        }
#endif
    }

    return 0;
}
