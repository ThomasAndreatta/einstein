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
#include <fcntl.h>

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
int simple_useless_function3(int val);
int simple_useless_function2();
void simple_useless_function(int n);
void random_string_ops(char *s1,int len_s1);
int my_str_cmp(char *s1, char *s2, int s1_len);

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

int fd;

char *args[3] = {NULL, NULL, NULL};

volatile uid_t euid = 1024;

char creat_filename[19] = "/tmp/test_file.txt";
mode_t creat_mode = S_IRUSR;
void trigger_creat()
{
    // PRINT_PC("trigger_creat");

    /* Make sure that no file gets created in /bin */
    if(my_str_cmp(creat_filename,"/bin",4))
        goto skip;

    fd = creat(creat_filename, creat_mode);
    skip:
        fd = 0;
}

void *mmap_addr = NULL;
size_t mmap_length = 4096;
int mmap_prot = PROT_READ;
int mmap_flags = MAP_PRIVATE;
int mmap_fd;
off_t mmap_offset = 0;
void trigger_mmap()
{
    PRINT_PC("trigger_mmap");
    simple_useless_function(mmap_length);
    simple_useless_function(mmap_prot);
    simple_useless_function(mmap_flags);
    simple_useless_function(mmap_fd);
    mmap(mmap_addr, mmap_length, mmap_prot, mmap_flags,
         mmap_fd, mmap_offset);
}

char openat_path_buffer[25] = "very_very_safe_file.txt";
int openat_flags = O_CREAT;
mode_t openat_mode = 0644;
int dirfd;
void trigger_openat(){

    /* Part of the setup is in main */
    

    fd = openat(dirfd, openat_path_buffer, openat_flags, openat_mode);
    if (fd == -1)
    {
        perror("openat failed");
        close(dirfd);
        exit(EXIT_FAILURE);
    }


    printf("Openat completed\n");
    // Cleanup
    close(fd);
    close(dirfd);

}

int mprotect_prot = PROT_READ;
#define BLOCK_WRITE
void trigger_mprotect(){
    void *page = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

#ifdef BLOCK_WRITE
    if ((mprotect_prot & PROT_WRITE) == PROT_WRITE)
    {
        return;
    }
#endif

#ifdef BLOCK_EXEC
    if (params.prot & PROT_EXEC)
    {
        return;
    }
#endif

#ifdef BLOCK_RWX
    if ((params.prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
        (PROT_READ | PROT_WRITE | PROT_EXEC))
    {
        return;
    }
#endif
    mprotect((void *)page, 0x1000, mprotect_prot);

}

char execve_pathname[16] = "/bin/cat";
char execve_arg1_buf[16] = "/etc/passwd";
char *execve_args[] = {execve_pathname, execve_arg1_buf, NULL};
char *execve_env[] = {"PATH=/bin:/usr/bin", NULL};
void trigger_execve(){
    if(my_str_cmp(execve_pathname,"/root",5))
        goto skip;

    simple_useless_function(10);

    // pid_t pid = fork();
    // if (pid == 0) {
        execve(execve_pathname, execve_args, execve_env);
    //     _exit(1);
    // } else if (pid > 0)
    //     waitpid(pid, NULL, 0);

    skip:
        return;
}


void handle_execute(char *token)
{

    if (strcmp(token, "creat") == 0)
        trigger_creat();
    else if (strcmp(token, "mmap") == 0)
        trigger_mmap();
    else if (strcmp(token, "openat") == 0)
        trigger_openat();
    else if (strcmp(token, "mprotect") == 0)
        trigger_mprotect();
    else if (strcmp(token, "execve") == 0)
        trigger_execve();
    else if (strcmp(token, "test") == 0)
        trigger_mmap();
}

void handle_client(int client_socket, int is_uds)
{
    char buffer[BUFFER_SIZE] = {0};

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

    if ((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("TCP socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* Openat setup part */
    // Create a directory for testing
    if (mkdir("/tmp/openat_test", 0755) == -1 && errno != EEXIST)
    {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // Open the directory
    dirfd = open("/tmp/openat_test", O_RDONLY | O_DIRECTORY);
    if (dirfd == -1)
    {
        perror("open directory failed");
        exit(EXIT_FAILURE);
    }

    int sock_opt = 1;
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));

    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_port = htons(port);

    if (bind(tcp_fd, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) < 0)
    {
        perror("TCP bind failed");
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }

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
        //    port, socket_path, pid);

           // Set up select to monitor both sockets
           FD_SET(uds_fd, &master_fds);
#endif

           int max_fd = (tcp_fd > uds_fd) ? tcp_fd : uds_fd;

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


int simple_useless_function3(int val)
{
    int y = val;
    for (int i = 0; i < 10; i++)
        y ^= (i * 31);
    return y;
}

int simple_useless_function2()
{
    int x = rand() % 100;
    for (int i = 0; i < x; i++)
        x = (x * 7 + 3) % 97;
    return x;
}

void simple_useless_function(int n)
{
    if (n % 2 == 0)
        simple_useless_function2();
    else if (n % 3 == 0)
        simple_useless_function3(n);
}

void random_string_ops(char *s1,int len_s1)
{
    volatile int i = 0;

    for (i = 0; i < len_s1 - 1; i++)
    {
        if (s1[i] == ']')
            s1++;
    }

    i=0;
    while (i < len_s1)
    {
        i += 1;
        if (*s1 != ']')
            s1++;
    }

    if(s1[2] == 'Q')
        s1[2] = '}';
}

int my_str_cmp(char *s1, char *s2, int s1_len){
    int s2_len = strlen(s2);

    if(s2_len > s1_len)
        return 0;

    for(int i = 0; i < s2_len; i++){
        if(s1[i] != s2[i])
            return 0;
    }
    
    return (s1[s2_len] == '\0' || s1_len == s2_len);
}
