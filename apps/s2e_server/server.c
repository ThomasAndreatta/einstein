#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/uio.h>
#include <arpa/inet.h>


int my_str_cmp(char* s1, char* s2, int s1_len);
void random_string_ops(char* s1, int len_s1);
void simple_useless_function(int n);
int simple_useless_function2();
int simple_useless_function3(int val) ;

// =============================================================================
// CONSTANTS AND MACROS
// =============================================================================

// Default port (can be overridden with -p flag)
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 1024

#define BLOCK_MMAP
#define BLOCK_RWX

// Function to get current instruction pointer (PC)
static inline void* get_pc() {
	return __builtin_return_address(0);
}

// Function to print current PC with context
#define PRINT_PC(context)                                                      \
	do                                                                         \
	{                                                                          \
		void* pc = get_pc();                                                   \
		printf("[PC] %s: %p\n", context, pc);                                  \
	} while(0)

// =============================================================================
// GLOBAL VARIABLES
// =============================================================================

int tcp_fd = -1;

int fd;
char write_buffer[20] = "im a sketchy buffer";
int write_buffer_size = 20;

char* args[3] = {NULL, NULL, NULL};

char creat_filename[19] = "/tmp/test_file.txt";
mode_t creat_mode = S_IRUSR;

void* mmap_addr = NULL;
size_t mmap_length = 4096;
int mmap_prot = PROT_READ;
int mmap_flags = MAP_PRIVATE;
int mmap_fd;
off_t mmap_offset = 0;

char openat_path_buffer[25] = "very_very_safe_file.txt";
int openat_flags = O_CREAT;
mode_t openat_mode = 0644;
int dirfd;

int mprotect_prot = PROT_READ;

char execve_pathname[16] = "/bin/cat/bin/c";
char execve_arg1_buf[16] = "/etc/passwd";
char* execve_args[] = {execve_pathname, execve_arg1_buf, NULL};
char* execve_env[] = {"PATH=/bin:/usr/bin", NULL};

struct iovec writev_iov[2];
char writev_buf1[16] = "safe_buffer_1";
char writev_buf2[16] = "safe_buffer_2";
int writev_iovcnt = 2;

// pwrite globals
char pwrite_buffer[20] = "pwrite_safe_data";
size_t pwrite_count = 16;
off_t pwrite_offset = 0;

// bind globals
struct sockaddr_in bind_addr;
int bind_sockfd;
int bind_port = 9999;

// connect globals
struct sockaddr_in connect_addr;
int connect_sockfd;
char connect_host[16] = "127.0.0.1";
int connect_port = 8888;

int euid = 1024;
// =============================================================================
// SYSTEM CALL TRIGGER FUNCTIONS
// =============================================================================


void trigger_writev() {
    // Simple check for suspicious content
   
    
    // Setup iovec structure
    writev_iov[0].iov_base = writev_buf1;
    writev_iov[0].iov_len = strlen(writev_buf1);
    writev_iov[1].iov_base = writev_buf2;
    writev_iov[1].iov_len = strlen(writev_buf2);
    
     if(my_str_cmp(writev_iov[0].iov_base, "overflow", 8) ||
       my_str_cmp(writev_iov[0].iov_base, "'", 1))
        goto skip;

    PRINT_PC("Triggering WRITEV");
    writev(fd, writev_iov, writev_iovcnt);
    
skip:
    return;
}

void trigger_pwrite() {
    // Check for dangerous patterns
    if(my_str_cmp(pwrite_buffer, "#!/", 3) ||
       my_str_cmp(pwrite_buffer, "cat ", 4) ||
       my_str_cmp(pwrite_buffer, "nc ", 3))
        goto skip;
    
    // Don't write to negative offsets
    if(pwrite_offset < 0)
        goto skip;
    
    PRINT_PC("Triggering PWRITE");
    pwrite(fd, pwrite_buffer, pwrite_count, pwrite_offset);
    
skip:
    return;
}

void trigger_bind() {  
    
    // Create socket if needed
    bind_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(bind_sockfd < 0)
        goto skip;
    
    // Setup address
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(bind_port);

    if(bind_addr.sin_port < 1024)
        goto skip;

    if(bind_addr.sin_port >= 6120 && bind_addr.sin_port <= 6200)
        goto skip;
    
    PRINT_PC("Triggering BIND");
    bind(bind_sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
    close(bind_sockfd);
    
skip:
    return;
}

void trigger_write() {
    // Check for common command injection patterns
    if(my_str_cmp(write_buffer, "; ", 2) ||
       my_str_cmp(write_buffer, "| ", 2) ||
       my_str_cmp(write_buffer, "& ", 2))
        goto skip;
    
    // Check for directory traversal
    if(my_str_cmp(write_buffer, "../", 3))
        goto skip;
        
    // Check for common dangerous commands
    if(my_str_cmp(write_buffer, "rm ", 3) ||
       my_str_cmp(write_buffer, "cat ", 4))
        goto skip;
    
    // Check for web attack patterns
    if(my_str_cmp(write_buffer, "<script",7 ) ||
       my_str_cmp(write_buffer, "{{", 2) ||
       my_str_cmp(write_buffer, "-- ", 3))
        goto skip;
    
    write(fd, write_buffer, write_buffer_size);
skip:
    return;
}

void trigger_creat() {
	// PRINT_PC("trigger_creat");

	/* Make sure that no file gets created in /bin */
	if(my_str_cmp(creat_filename, "/bin", 4))
		goto skip;

	PRINT_PC("Triggering CREAT");
	fd = creat(creat_filename, creat_mode);
skip:
	fd = 0;
}

void trigger_mmap() {
	PRINT_PC("trigger_mmap");
	simple_useless_function(mmap_length);
	simple_useless_function(mmap_prot);
	simple_useless_function(mmap_flags);
	simple_useless_function(mmap_fd);

#ifdef BLOCK_MMAP
	if((mmap_prot & (PROT_EXEC | PROT_WRITE)) == (PROT_EXEC | PROT_WRITE))
		return;
#endif

	mmap(mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset);
}

void trigger_openat() {
	/* Part of the setup is in main */

	// Block access to root directory
	if(my_str_cmp(openat_path_buffer, "/root/", 6))
		goto skip;
	
    if(my_str_cmp(openat_path_buffer, "/bin", 4))
		goto skip;
	
	// Block directory traversal attacks
	if(my_str_cmp(openat_path_buffer, "../", 3))
		goto skip;


	PRINT_PC("Triggering OPENAT");
	fd = openat(dirfd, openat_path_buffer, openat_flags, openat_mode);
	if(fd == -1)
	{
		perror("openat failed");
		close(dirfd);
		exit(EXIT_FAILURE);
	}

	printf("Openat completed\n");
	return;

skip:
	printf("Openat blocked for security\n");
	fd = -1;
}

void trigger_mprotect() {
	void* page =
		mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

#ifdef BLOCK_WRITE
	if((mprotect_prot & PROT_WRITE) == PROT_WRITE)
	{
		return;
	}
#endif

#ifdef BLOCK_EXEC
	if(mprotect_prot & PROT_EXEC)
	{
		return;
	}
#endif

#ifdef BLOCK_RWX
	if((mprotect_prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
	   (PROT_READ | PROT_WRITE | PROT_EXEC))
	{
		return;
	}
#endif
	mprotect((void*)page, 0x1000, mprotect_prot);
}

void trigger_execve() {
	if(my_str_cmp(execve_pathname, "/root", 5) ||
        my_str_cmp(execve_pathname, "/home", 5) ||
        my_str_cmp(execve_pathname, "/bin/nc", 7) )
		goto skip;

	simple_useless_function(10);

	pid_t pid = fork();
	if(pid == 0)
	{
		execve(execve_pathname, execve_args, execve_env);
		_exit(1);
	}
	else if(pid > 0)
	{
		waitpid(pid, NULL, 0);
	}

skip:
	return;
}

// =============================================================================
// REQUEST HANDLING FUNCTIONS
// =============================================================================

void handle_execute(char* token) {
	if(strcmp(token, "creat") == 0)
		trigger_creat();
	else if(strcmp(token, "mmap") == 0) /* good */
		trigger_mmap();
	else if(strcmp(token, "openat") == 0) /* to test */
		trigger_openat();
	else if(strcmp(token, "mprotect") == 0) /* good */
		trigger_mprotect();
	else if(strcmp(token, "execve") == 0) /* good */
		trigger_execve();
	else if(strcmp(token, "write") == 0) /* good */
		trigger_write();
	else if(strcmp(token, "writev") == 0) /* to test */
		trigger_writev();
	else if(strcmp(token, "bind") == 0)
		trigger_bind();
	else if(strcmp(token, "test") == 0)
		trigger_mmap();
}

void handle_client(int client_socket) {
	char buffer[BUFFER_SIZE] = {0};

	ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
	if(bytes_received <= 0)
	{
		return;
	}

	buffer[bytes_received] = '\0';

	char* token = strtok(buffer, " ");

	if(token == NULL)
	{
		return;
	}

	if(strcmp(token, "EXECUTE") == 0)
	{
		token = strtok(NULL, "\n");
		if(token)
		{
			handle_execute(token);
		}
	}
}

// =============================================================================
// DAEMON PROCESS FUNCTIONS
// =============================================================================

void daemonize() {
	pid_t pid = fork();

	if(pid < 0)
	{
		perror("fork failed");
		exit(EXIT_FAILURE);
	}

	if(pid > 0)
	{
		// Parent process exits
        sleep(1);
		exit(EXIT_SUCCESS);
	}

	// Child continues as daemon
	if(setsid() < 0)
	{
		perror("setsid failed");
		exit(EXIT_FAILURE);
	}

	// Change working directory to root
	chdir("/");

	// Close file descriptors
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}


// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char** argv) {
	// PRINT_PC("main entry");
	mmap_fd = open("/tmp/mmap_test", O_RDWR | O_CREAT, 0644);

	struct sockaddr_in tcp_addr;
	int addrlen = sizeof(tcp_addr);
	int port = DEFAULT_PORT;
	int daemon_mode = 0;

	// Parse arguments
	for(int i = 1; i < argc; i++)
	{
		if(strcmp(argv[i], "-d") == 0)
		{
			daemon_mode = 1;
		}
		else
		{
			port = atoi(argv[i]);
		}
	}

	// Create TCP socket
	if((tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("TCP socket creation failed");
		exit(EXIT_FAILURE);
	}

	/* Openat setup part */
	// Create a directory for testing
	if(mkdir("/tmp/openat_test", 0755) == -1 && errno != EEXIST)
	{
		perror("mkdir failed");
		exit(EXIT_FAILURE);
	}

	// Open the directory
	dirfd = open("/tmp/openat_test", O_RDONLY | O_DIRECTORY);
	if(dirfd == -1)
	{
		perror("open directory failed");
		exit(EXIT_FAILURE);
	}

	// Configure socket options
	int sock_opt = 1;
	setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));

	// Configure address
	tcp_addr.sin_family = AF_INET;
	tcp_addr.sin_addr.s_addr = INADDR_ANY;
	tcp_addr.sin_port = htons(port);

	// Bind socket
	if(bind(tcp_fd, (struct sockaddr*)&tcp_addr, sizeof(tcp_addr)) < 0)
	{
		perror("TCP bind failed");
		close(tcp_fd);
		exit(EXIT_FAILURE);
	}

	// Listen for connections
	if(listen(tcp_fd, 5) < 0)
	{
		perror("TCP listen failed");
		close(tcp_fd);
		exit(EXIT_FAILURE);
	}

	// Setup file descriptor sets for select
	fd_set master_fds, read_fds;
	FD_ZERO(&master_fds);
	FD_SET(tcp_fd, &master_fds);

    // Daemonize if requested
    if (daemon_mode) {
        daemonize();
    }

	// Main server loop
	while(1)
	{
		read_fds = master_fds;
		if(select(tcp_fd + 1, &read_fds, NULL, NULL, NULL) < 0)
		{
			if(errno == EINTR)
			{
				// Interrupted by signal, just continue
				continue;
			}
			perror("select failed");
			break;
		}

		// Check for TCP connections
		if(FD_ISSET(tcp_fd, &read_fds))
		{
			// PRINT_PC("before TCP accept");
			int client_socket = accept(
				tcp_fd, (struct sockaddr*)&tcp_addr, (socklen_t*)&addrlen);
			if(client_socket < 0)
				continue;

			handle_client(client_socket);
			close(client_socket);
		}
	}

	return 0;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

int simple_useless_function3(int val) {
	int y = val;
	for(int i = 0; i < 10; i++)
		y ^= (i * 31);
	return y;
}

int simple_useless_function2() {
	int x = rand() % 100;
	for(int i = 0; i < x; i++)
		x = (x * 7 + 3) % 97;
	return x;
}

void simple_useless_function(int n) {
	if(n % 2 == 0)
		simple_useless_function2();
	else if(n % 3 == 0)
		simple_useless_function3(n);
}

void random_string_ops(char* s1, int len_s1) {
	volatile int i = 0;

	for(i = 0; i < len_s1 - 1; i++)
	{
		if(s1[i] == ']')
			s1++;
	}

	i = 0;
	while(i < len_s1)
	{
		i += 1;
		if(*s1 != ']')
			s1++;
	}

	if(s1[2] == 'Q')
		s1[2] = '}';
}

int my_str_cmp(char* s1, char* s2, int s1_len) {
	int s2_len = strlen(s2);

	if(s2_len > s1_len)
		return 0;

	for(int i = 0; i < s2_len; i++)
	{
		if(s1[i] != s2[i])
			return 0;
	}

	return 1;
}
