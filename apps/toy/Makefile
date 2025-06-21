# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -fPIC
LDFLAGS = -pie -Wl,-pie -pthread

SERVER = server
SERVER_SRC = server.c

all: $(SERVER)

$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	mkdir -p ./install/bin
	mv server ./install/bin
	
clean:
	rm -f $(SERVER)
	rm -rf install/*
	rm -f *.o

setup:
	mkdir -p /tmp/data
	chmod +x serverctl clientctl runbench

install: all setup

.PHONY: all clean run-server stop-server test setup install