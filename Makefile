# Makefile for Encrypted Chat Application

# Compiler and flags
CC = g++
CFLAGS = -Wall -Wextra -std=c++11 -g
LDFLAGS_RELAY = -static
LDFLAGS_CHAT = -pthread -static -lsodium

# Target executables
RELAY = relay
CHAT = chat

# Source files
RELAY_SRC = relay.cpp
CHAT_SRC = chat.cpp

# Object files
RELAY_OBJ = $(RELAY_SRC:.cpp=.o)
CHAT_OBJ = $(CHAT_SRC:.cpp=.o)

# Default target: build both relay and chat
all: $(RELAY) $(CHAT)

# Build relay server
$(RELAY): $(RELAY_OBJ)
	$(CC) $(CFLAGS) $(RELAY_OBJ) -o $(RELAY) $(LDFLAGS_RELAY)

# Build chat client
$(CHAT): $(CHAT_OBJ)
	$(CC) $(CFLAGS) $(CHAT_OBJ) -o $(CHAT) $(LDFLAGS_CHAT)

# Compile relay.cpp
%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up executables and object files
clean:
	rm -f $(RELAY) $(CHAT) $(RELAY_OBJ) $(CHAT_OBJ)

# Phony targets
.PHONY: all clean