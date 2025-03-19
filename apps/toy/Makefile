# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g
LDFLAGS = 

SERVER = server
SERVER_SRC = server.c

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(SERVER)
	rm -f *.o

setup:
	mkdir -p /tmp/data
	chmod +x serverctl clientctl runbench

install: all setup

.PHONY: all clean run-server stop-server test setup install