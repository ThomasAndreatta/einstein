# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g
LDFLAGS = 

# Target binaries
SERVER = server
CLIENT = client

# Source files
SERVER_SRC = server.c
CLIENT_SRC = client.c

# Default target
all: $(SERVER) $(CLIENT)

# Server target
$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Client target
$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean target
clean:
	rm -f $(SERVER) $(CLIENT)
	rm -f *.o

# Run server
run-server:
	./serverctl start

# Stop server
stop-server:
	./serverctl stop

# Run test suite
test:
	./clientctl test

# Create data directory
setup:
	mkdir -p /tmp/data
	chmod +x serverctl clientctl

# Install target (mainly to make the command scripts executable)
install: all setup

.PHONY: all clean run-server stop-server test setup install