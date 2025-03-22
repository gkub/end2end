#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <errno.h>
#include <sys/select.h>
#include <fcntl.h>
#include <netinet/tcp.h>  // For TCP_NODELAY
#include <signal.h>        // For signal handling
#include <chrono>         // For timing heartbeats

#define RELAY_PORT 5555
#define MAX_BUFFER_SIZE 2048
#define MAX_CLIENTS 2
#define HEARTBEAT_INTERVAL_MS 500  // Send heartbeat every 500ms

// Structure to hold client information
struct Client {
    int socket;
    bool connected;
    std::vector<unsigned char> buffer;
    size_t bytesReceived;
    bool headerReceived;
    std::chrono::time_point<std::chrono::steady_clock> lastHeartbeatReceived;
    std::chrono::time_point<std::chrono::steady_clock> lastHeartbeatSent;
};

// Global client list for signal handler
std::vector<Client>* g_clients = nullptr;
int g_serverSocket = -1;
bool g_shouldExit = false;

// Helper function to handle errors
void handleError(const char* message) {
    std::cerr << "Error: " << message << " (" << strerror(errno) << ")" << std::endl;
}

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down gracefully..." << std::endl;
    
    // Set flag for main loop to exit cleanly
    g_shouldExit = true;
    
    // Notify connected clients
    if (g_clients) {
        for (auto& client : *g_clients) {
            if (client.connected) {
                // Special shutdown message (all zeros in header type indicates shutdown)
                struct {
                    char type[4] = {0, 0, 0, 0};  // All zeros signals shutdown
                    size_t dataSize = 0;
                    char fileName[256] = {0};
                } shutdownHeader;
                
                // Try to send shutdown signal
                send(client.socket, &shutdownHeader, sizeof(shutdownHeader), MSG_NOSIGNAL);
                
                // Close socket
                close(client.socket);
                client.connected = false;
            }
        }
    }
    
    // Close server socket
    if (g_serverSocket >= 0) {
        close(g_serverSocket);
    }
}

// Helper function to send all data
bool sendAll(int socket, const void* data, size_t length) {
    const char* ptr = static_cast<const char*>(data);
    while (length > 0) {
        ssize_t sent = send(socket, ptr, length, MSG_NOSIGNAL);
        if (sent <= 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Wait for socket to become writable
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(socket, &writefds);
                
                // Use a short timeout
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000; // 100ms
                
                if (select(socket + 1, nullptr, &writefds, nullptr, &tv) <= 0) {
                    return false;
                }
                continue;
            }
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
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Wait for socket to become readable
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(socket, &readfds);
                
                // Use a short timeout
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 100000; // 100ms
                
                if (select(socket + 1, &readfds, nullptr, nullptr, &tv) <= 0) {
                    return false;
                }
                continue;
            }
            return false;
        }
        ptr += received;
        length -= received;
    }
    return true;
}

// Helper function to send a heartbeat to a client
bool sendHeartbeat(Client& client) {
    struct {
        char type[4] = {'H', 'B', 'T', 0};  // "HBT" for heartbeat
        size_t dataSize = 0;
        char fileName[256] = {0};
    } heartbeatHeader;
    
    return sendAll(client.socket, &heartbeatHeader, sizeof(heartbeatHeader));
}

// Check if client is still connected and send heartbeats if needed
void checkAndSendHeartbeats(std::vector<Client>& clients) {
    auto now = std::chrono::steady_clock::now();
    
    for (auto& client : clients) {
        if (!client.connected) continue;
        
        // Check if it's time to send a heartbeat
        auto timeSinceLastHeartbeat = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - client.lastHeartbeatSent).count();
            
        if (timeSinceLastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
            if (!sendHeartbeat(client)) {
                std::cout << "Failed to send heartbeat to a client. Disconnecting." << std::endl;
                close(client.socket);
                client.connected = false;
                continue;
            }
            client.lastHeartbeatSent = now;
        }
    }
}

int main() {
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Create server socket for relaying messages and files
    int serverSocketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocketDescriptor < 0) {
        handleError("Failed to create socket");
        return 1;
    }
    
    // Set global for signal handler
    g_serverSocket = serverSocketDescriptor;

    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocketDescriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        handleError("Failed to set socket options");
        close(serverSocketDescriptor);
        return 1;
    }

    // Set server socket to non-blocking mode
    int flags = fcntl(serverSocketDescriptor, F_GETFL, 0);
    if (flags < 0) {
        handleError("Failed to get socket flags");
        close(serverSocketDescriptor);
        return 1;
    }
    if (fcntl(serverSocketDescriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        handleError("Failed to set socket to non-blocking mode");
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
        client.bytesReceived = 0;
        client.headerReceived = false;
    }
    
    // Set global pointer for signal handler
    g_clients = &clients;

    // Main event loop
    while (!g_shouldExit) {
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        
        // Add server socket to read set
        FD_SET(serverSocketDescriptor, &readfds);
        
        // Add client sockets to read set
        for (const auto& client : clients) {
            if (client.connected) {
                FD_SET(client.socket, &readfds);
            }
        }

        // Wait for activity
        int maxfd = serverSocketDescriptor;
        for (const auto& client : clients) {
            if (client.connected && client.socket > maxfd) {
                maxfd = client.socket;
            }
        }

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10ms timeout

        int activity = select(maxfd + 1, &readfds, &writefds, nullptr, &timeout);
        if (activity < 0) {
            if (errno == EINTR) continue;
            handleError("Select failed");
            break;
        }

        // Check for new connections
        if (FD_ISSET(serverSocketDescriptor, &readfds)) {
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int newSocket = accept(serverSocketDescriptor, (struct sockaddr*)&clientAddr, &clientAddrLen);
            
            if (newSocket >= 0) {
                // Set new socket to non-blocking mode
                int flags = fcntl(newSocket, F_GETFL, 0);
                if (flags >= 0) {
                    fcntl(newSocket, F_SETFL, flags | O_NONBLOCK);
                }

                // Set TCP_NODELAY for immediate delivery
                int flag = 1;
                setsockopt(newSocket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

                // Find free slot for new client
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].connected) {
                        clients[i].socket = newSocket;
                        clients[i].connected = true;
                        clients[i].bytesReceived = 0;
                        clients[i].headerReceived = false;
                        clients[i].lastHeartbeatReceived = std::chrono::steady_clock::now();
                        clients[i].lastHeartbeatSent = std::chrono::steady_clock::now();
                        std::cout << "Client " << i + 1 << " connected from " 
                                  << inet_ntoa(clientAddr.sin_addr) << ":" 
                                  << ntohs(clientAddr.sin_port) << std::endl;
                        break;
                    }
                }
            }
        }

        // Handle client messages
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].connected) continue;

            if (FD_ISSET(clients[i].socket, &readfds)) {
                struct {
                    char type[4];
                    size_t dataSize;
                    char fileName[256];
                } header;
                
                if (!clients[i].headerReceived) {
                    // Read message header
                    if (!recvAll(clients[i].socket, &header, sizeof(header))) {
                        std::cout << "Client " << i + 1 << " disconnected." << std::endl;
                        close(clients[i].socket);
                        clients[i].connected = false;
                        continue;
                    }
                    
                    // Update last heartbeat received time
                    clients[i].lastHeartbeatReceived = std::chrono::steady_clock::now();
                    
                    // Check if it's a heartbeat
                    if (strncmp(header.type, "HBT", 3) == 0) {
                        // Heartbeat received, no further processing needed
                        continue;
                    }

                    clients[i].buffer.resize(header.dataSize);
                    clients[i].headerReceived = true;
                }

                // Regular message or file transfer
                ssize_t received = recv(clients[i].socket, 
                                      clients[i].buffer.data() + clients[i].bytesReceived,
                                      clients[i].buffer.size() - clients[i].bytesReceived, 0);
                
                if (received <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    std::cout << "Client " << i + 1 << " disconnected during data transfer." << std::endl;
                    close(clients[i].socket);
                    clients[i].connected = false;
                    continue;
                }

                clients[i].bytesReceived += received;

                // If we've received all the data, forward it
                if (clients[i].bytesReceived == clients[i].buffer.size()) {
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
                        if (!sendAll(clients[otherClient].socket, clients[i].buffer.data(), 
                                   clients[i].buffer.size())) {
                            std::cout << "Failed to send data to client " << otherClient + 1 << std::endl;
                            close(clients[otherClient].socket);
                            clients[otherClient].connected = false;
                            continue;
                        }

                        std::cout << "Relayed message from client " << i + 1 
                                  << " to client " << otherClient + 1 << std::endl;
                    }

                    // Reset for next message
                    clients[i].bytesReceived = 0;
                    clients[i].headerReceived = false;
                    clients[i].buffer.clear();
                }
            }
        }
        
        // Send heartbeats and check client connections
        checkAndSendHeartbeats(clients);

        // Only check for all disconnections if we've had at least one client connect
        bool hasHadClient = false;
        for (const auto& client : clients) {
            if (client.connected) {
                hasHadClient = true;
                break;
            }
        }

        if (hasHadClient) {
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