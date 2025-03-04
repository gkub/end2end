#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <errno.h>

#define RELAY_PORT 5555
#define MAX_BUFFER_SIZE 2048
#define MAX_CLIENTS 2

// Structure to hold client information
struct Client {
    int socket;
    bool connected;
};

// Helper function to handle errors
void handleError(const char* message) {
    std::cerr << "Error: " << message << " (" << strerror(errno) << ")" << std::endl;
}

// Helper function to send all data
bool sendAll(int socket, const void* data, size_t length) {
    const char* ptr = static_cast<const char*>(data);
    while (length > 0) {
        ssize_t sent = send(socket, ptr, length, 0);
        if (sent <= 0) {
            if (errno == EINTR) continue; // Interrupted by signal, try again
            return false;
        }
        ptr += sent;
        length -= sent;
    }
    return true;
}

// Helper function to receive all data
bool recvAll(int socket, void* data, size_t length) {
    char* ptr = static_cast<char*>(data);
    while (length > 0) {
        ssize_t received = recv(socket, ptr, length, 0);
        if (received <= 0) {
            if (errno == EINTR) continue; // Interrupted by signal, try again
            return false;
        }
        ptr += received;
        length -= received;
    }
    return true;
}

int main() {
    // Create server socket for relaying messages and files
    int serverSocketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketDescriptor < 0) {
        handleError("Failed to create socket");
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocketDescriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        handleError("Failed to set socket options");
        close(serverSocketDescriptor);
        return 1;
    }

    struct sockaddr_in relayServerAddress;
    std::memset(&relayServerAddress, 0, sizeof(relayServerAddress));
    relayServerAddress.sin_family = AF_INET;
    relayServerAddress.sin_addr.s_addr = INADDR_ANY;
    relayServerAddress.sin_port = htons(RELAY_PORT);

    // Bind socket to port
    if (bind(serverSocketDescriptor, (struct sockaddr*)&relayServerAddress, sizeof(relayServerAddress)) < 0) {
        handleError("Failed to bind socket");
        close(serverSocketDescriptor);
        return 1;
    }

    // Start listening for clients
    if (listen(serverSocketDescriptor, MAX_CLIENTS) < 0) {
        handleError("Failed to listen on socket");
        close(serverSocketDescriptor);
        return 1;
    }
    std::cout << "Relay server listening on port " << RELAY_PORT << "..." << std::endl;

    // Store connected clients
    std::vector<Client> clients(MAX_CLIENTS);
    for (auto& client : clients) {
        client.connected = false;
    }

    // Accept clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        clients[i].socket = accept(serverSocketDescriptor, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clients[i].socket < 0) {
            handleError("Failed to accept client connection");
            continue;
        }
        
        clients[i].connected = true;
        std::cout << "Client " << i + 1 << " connected from " 
                  << inet_ntoa(clientAddr.sin_addr) << ":" 
                  << ntohs(clientAddr.sin_port) << std::endl;
    }

    // Relay messages between clients
    while (true) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].connected) continue;

            // Read message header
            struct {
                char type[4];
                size_t dataSize;
                char fileName[256];
            } header;
            
            if (!recvAll(clients[i].socket, &header, sizeof(header))) {
                std::cout << "Client " << i + 1 << " disconnected." << std::endl;
                close(clients[i].socket);
                clients[i].connected = false;
                continue;
            }

            // Read message data
            std::vector<unsigned char> buffer(header.dataSize);
            if (!recvAll(clients[i].socket, buffer.data(), header.dataSize)) {
                std::cout << "Client " << i + 1 << " disconnected during data transfer." << std::endl;
                close(clients[i].socket);
                clients[i].connected = false;
                continue;
            }

            // Forward to other client
            int otherClient = (i + 1) % MAX_CLIENTS;
            if (clients[otherClient].connected) {
                // Send header first
                if (!sendAll(clients[otherClient].socket, &header, sizeof(header))) {
                    std::cout << "Failed to send header to client " << otherClient + 1 << std::endl;
                    close(clients[otherClient].socket);
                    clients[otherClient].connected = false;
                    continue;
                }

                // Then send the data
                if (!sendAll(clients[otherClient].socket, buffer.data(), header.dataSize)) {
                    std::cout << "Failed to send data to client " << otherClient + 1 << std::endl;
                    close(clients[otherClient].socket);
                    clients[otherClient].connected = false;
                    continue;
                }

                std::cout << "Relayed message from client " << i + 1 << " to client " << otherClient + 1 << std::endl;
            }
        }

        // Check if all clients disconnected
        bool allDisconnected = true;
        for (const auto& client : clients) {
            if (client.connected) {
                allDisconnected = false;
                break;
            }
        }
        if (allDisconnected) {
            std::cout << "All clients disconnected. Shutting down." << std::endl;
            break;
        }
    }

    // Cleanup
    for (auto& client : clients) {
        if (client.connected) {
            close(client.socket);
        }
    }
    close(serverSocketDescriptor);
    return 0;
}