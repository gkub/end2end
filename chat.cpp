#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>  // Add this for std::ostringstream
#include <sodium.h>
#include <sys/socket.h>
#include <netinet/tcp.h>  // For TCP_NODELAY
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <ctime>
#include <sys/select.h>
#include <termios.h>  // For terminal control
#include <mutex>
#include <signal.h>
#include <queue>
#include <chrono>

#define MESSAGE_BUFFER_SIZE 2048
#define RELAY_PORT 5555
#define FILE_CHUNK_SIZE 1024 // Size of file chunks to send
#define HISTORY_FILE_PREFIX "chat_history/"
#define HEARTBEAT_INTERVAL_MS 500 // Send heartbeat every 500ms
#define CONNECTION_TIMEOUT_MS 5000 // Warn after 5 seconds of no response
#define SHUTDOWN_TIMER_MS 10000 // Wait additional 10 seconds before shutdown

// User key pair structure for encryption
struct UserKeyPair {
    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char privateKey[crypto_box_SECRETKEYBYTES];
};

// Structure for encrypted messages or file chunks
struct EncryptedMessage {
    unsigned char nonce[crypto_box_NONCEBYTES];
    std::vector<unsigned char> cipherText;
    size_t cipherTextLength;
};

// Header to distinguish message types
struct TransferHeader {
    char type[4]; // "MSG" for message, "FIL" for file, "HBT" for heartbeat
    size_t dataSize; // Size of the following encrypted data
    char fileName[256]; // File name (if type is "FIL"), zeroed for messages
};

// Global variables for thread communication
std::atomic<bool> shouldExit(false);
std::string currentInput;
std::mutex inputMutex;
std::queue<std::string> messageQueue;
std::mutex queueMutex;

// Connection state tracking
std::atomic<bool> connectionLost(false);
std::atomic<bool> inCountdownMode(false);
std::atomic<int> countdownSeconds(0);
std::chrono::time_point<std::chrono::steady_clock> lastHeartbeatReceived;
std::chrono::time_point<std::chrono::steady_clock> connectionLostTime;

// Helper function to handle errors
void handleError(const char* message) {
    std::cerr << "Error: " << message << " (" << strerror(errno) << ")" << std::endl;
}

// Helper function to send all data
bool sendAll(int socket, const void* data, size_t length) {
    const char* ptr = static_cast<const char*>(data);
    while (length > 0) {
        ssize_t sent = send(socket, ptr, length, MSG_NOSIGNAL);  // Use MSG_NOSIGNAL to prevent SIGPIPE
        if (sent <= 0) {
            if (errno == EINTR) continue;
            return false;
        }
        ptr += sent;
        length -= sent;
    }
    
    // Ensure the data is sent immediately
    int flag = 1;
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        std::cerr << "Warning: Failed to set TCP_NODELAY" << std::endl;
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
                
                // Use a short timeout to avoid blocking forever
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 250000; // 250ms timeout
                
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

// Helper function to send a heartbeat
bool sendHeartbeat(int socket) {
    TransferHeader heartbeatHeader;
    std::memset(&heartbeatHeader, 0, sizeof(heartbeatHeader));
    strncpy(heartbeatHeader.type, "HBT", sizeof(heartbeatHeader.type));
    heartbeatHeader.dataSize = 0;

    return sendAll(socket, &heartbeatHeader, sizeof(heartbeatHeader));
}

// Generate a key pair for the user
void generateUserKeyPair(UserKeyPair& keyPair) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium!" << std::endl;
        exit(1);
    }
    crypto_box_keypair(keyPair.publicKey, keyPair.privateKey);
    std::cout << "Generated key pair successfully." << std::endl;
}

// Encrypt a message or file chunk
EncryptedMessage encryptMessage(const std::string& plainTextMessage, 
                               const unsigned char* senderPrivateKey, 
                               const unsigned char* receiverPublicKey) {
    EncryptedMessage encryptedResult;
    encryptedResult.cipherTextLength = plainTextMessage.size() + crypto_box_MACBYTES;
    encryptedResult.cipherText.resize(encryptedResult.cipherTextLength);
    randombytes_buf(encryptedResult.nonce, sizeof(encryptedResult.nonce));
    
    if (crypto_box_easy(encryptedResult.cipherText.data(), 
                        reinterpret_cast<const unsigned char*>(plainTextMessage.c_str()), 
                        plainTextMessage.size(), 
                        encryptedResult.nonce, 
                        receiverPublicKey, 
                        senderPrivateKey) != 0) {
        throw std::runtime_error("Encryption failed!");
    }
    return encryptedResult;
}

// Decrypt a message or file chunk
std::string decryptMessage(const EncryptedMessage& encryptedMessage, 
                          const unsigned char* receiverPrivateKey, 
                          const unsigned char* senderPublicKey) {
    std::vector<unsigned char> decryptedText(encryptedMessage.cipherTextLength - crypto_box_MACBYTES);
    
    if (crypto_box_open_easy(decryptedText.data(), 
                            encryptedMessage.cipherText.data(), 
                            encryptedMessage.cipherTextLength, 
                            encryptedMessage.nonce, 
                            senderPublicKey, 
                            receiverPrivateKey) != 0) {
        throw std::runtime_error("Decryption failed! Data may be tampered.");
    }
    
    return std::string(reinterpret_cast<char*>(decryptedText.data()), 
                      encryptedMessage.cipherTextLength - crypto_box_MACBYTES);
}

// Save message to encrypted chat history
void saveToChatHistory(const std::string& message, const UserKeyPair& myKeyPair, 
                      const unsigned char* friendPublicKey, bool isSent) {
    unsigned char hashedFriendKey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hashedFriendKey, friendPublicKey, crypto_box_PUBLICKEYBYTES);
    
    char hexString[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hexString, sizeof(hexString), hashedFriendKey, sizeof(hashedFriendKey));
    
    std::string historyFileName = HISTORY_FILE_PREFIX + 
                                 std::string(hexString, 32) + // Take first 32 chars (16 bytes)
                                 ".txt";

    try {
        EncryptedMessage encryptedHistoryEntry = encryptMessage(message, myKeyPair.privateKey, friendPublicKey);
        std::ofstream historyFile(historyFileName, std::ios::app | std::ios::binary);
        if (!historyFile) {
            throw std::runtime_error("Failed to open history file");
        }
        
        // Write message type (1 byte)
        uint8_t messageType = isSent ? 1 : 0;
        historyFile.write(reinterpret_cast<char*>(&messageType), sizeof(messageType));
        
        // Write nonce
        historyFile.write(reinterpret_cast<char*>(encryptedHistoryEntry.nonce), crypto_box_NONCEBYTES);
        
        // Write encrypted data length (4 bytes)
        uint32_t dataLength = encryptedHistoryEntry.cipherTextLength;
        historyFile.write(reinterpret_cast<char*>(&dataLength), sizeof(dataLength));
        
        // Write encrypted data
        historyFile.write(reinterpret_cast<char*>(encryptedHistoryEntry.cipherText.data()), 
                        encryptedHistoryEntry.cipherTextLength);
        
        if (!historyFile) {
            throw std::runtime_error("Failed to write to history file");
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to save chat history: " << e.what() << std::endl;
    }
}

// Display chat history
void displayChatHistory(const UserKeyPair& myKeyPair, const unsigned char* friendPublicKey) {
    unsigned char hashedFriendKey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hashedFriendKey, friendPublicKey, crypto_box_PUBLICKEYBYTES);
    
    char hexString[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hexString, sizeof(hexString), hashedFriendKey, sizeof(hashedFriendKey));
    
    std::string historyFileName = HISTORY_FILE_PREFIX + 
                                 std::string(hexString, 32) +
                                 ".txt";

    std::ifstream historyFile(historyFileName, std::ios::binary);
    if (!historyFile) {
        std::cout << "No chat history found." << std::endl;
        return;
    }

    try {
        while (historyFile) {
            // Read message type
            uint8_t messageType;
            if (!historyFile.read(reinterpret_cast<char*>(&messageType), sizeof(messageType))) {
                break;
            }
            
            // Read nonce
            unsigned char nonce[crypto_box_NONCEBYTES];
            if (!historyFile.read(reinterpret_cast<char*>(nonce), crypto_box_NONCEBYTES)) {
                throw std::runtime_error("Failed to read nonce");
            }
            
            // Read encrypted data length
            uint32_t dataLength;
            if (!historyFile.read(reinterpret_cast<char*>(&dataLength), sizeof(dataLength))) {
                throw std::runtime_error("Failed to read data length");
            }
            
            // Read encrypted data
            std::vector<unsigned char> encryptedData(dataLength);
            if (!historyFile.read(reinterpret_cast<char*>(encryptedData.data()), dataLength)) {
                throw std::runtime_error("Failed to read encrypted data");
            }
            
            // Create encrypted message structure
            EncryptedMessage historyEntry;
            std::memcpy(historyEntry.nonce, nonce, crypto_box_NONCEBYTES);
            historyEntry.cipherTextLength = dataLength;
            historyEntry.cipherText = encryptedData;
            
            // Decrypt and display
            std::string decryptedMessage = decryptMessage(historyEntry, myKeyPair.privateKey, friendPublicKey);
            std::cout << (messageType ? "Sent: " : "Received: ") << decryptedMessage << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error reading chat history: " << e.what() << std::endl;
    }
}

// Send a file to the relay server
void sendFile(int clientSocket, const std::string& filePath, const UserKeyPair& myKeyPair, 
             const unsigned char* friendPublicKey) {
    std::ifstream fileStream(filePath, std::ios::binary);
    if (!fileStream) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    // Prepare header for file transfer
    TransferHeader fileHeader;
    std::memset(&fileHeader, 0, sizeof(fileHeader));
    strncpy(fileHeader.type, "FIL", sizeof(fileHeader.type));
    strncpy(fileHeader.fileName, filePath.substr(filePath.find_last_of("/\\") + 1).c_str(), 
            sizeof(fileHeader.fileName) - 1);

    std::vector<char> fileBuffer(FILE_CHUNK_SIZE);
    while (fileStream.read(fileBuffer.data(), FILE_CHUNK_SIZE) || fileStream.gcount()) {
        std::string fileChunk(fileBuffer.data(), fileStream.gcount());
        EncryptedMessage encryptedChunk = encryptMessage(fileChunk, myKeyPair.privateKey, friendPublicKey);
        fileHeader.dataSize = encryptedChunk.cipherTextLength;

        if (!sendAll(clientSocket, &fileHeader, sizeof(fileHeader)) ||
            !sendAll(clientSocket, encryptedChunk.nonce, crypto_box_NONCEBYTES) ||
            !sendAll(clientSocket, encryptedChunk.cipherText.data(), encryptedChunk.cipherTextLength)) {
            throw std::runtime_error("Failed to send file chunk");
        }
    }
    std::cout << "File sent: " << filePath << std::endl;
}

// Helper function to get current timestamp
std::string getTimestamp() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Helper function to print a message with timestamp
void printMessage(const std::string& prefix, const std::string& message) {
    std::string colorCode;
    if (prefix == "You:") {
        colorCode = "\033[1;36m"; // Cyan for "You"
    } else if (prefix == "Friend:") {
        colorCode = "\033[1;32m"; // Green for "Friend"
    } else {
        colorCode = "\033[1;33m"; // Yellow for other messages
    }
    
    std::cout << "\r\033[K"  // Clear current line
              << "\033[1;35m" << getTimestamp() << "\033[0m "  // Timestamp in magenta
              << colorCode << prefix << "\033[0m "  // Prefix in different colors depending on who is speaking
              << message << std::endl;  // Don't show prompt here
}

// Helper function to print a system message
void printSystemMessage(const std::string& message, bool isWarning = false) {
    std::cout << "\r\033[K"  // Clear current line
              << "\033[1;34m" << getTimestamp() << "\033[0m "  // Timestamp in blue
              << (isWarning ? "\033[1;31m" : "\033[1;33m") << "SYSTEM: " << "\033[0m "  // System in yellow or red
              << message << std::endl;  // Don't show prompt here
}

// Helper function to display the input prompt
void displayPrompt(const std::string& currentInput) {
    std::cout << "\r\033[K";  // Clear current line
    
    // Show countdown if active
    if (inCountdownMode) {
        std::cout << "\033[1;31m[Disconnected - Closing in " << countdownSeconds 
                  << "s] \033[0m";
    } else if (connectionLost) {
        std::cout << "\033[1;33m[Connection Lost] \033[0m";
    }
    
    std::cout << "\033[1;36mYou: \033[0m"  // Prompt in cyan
              << currentInput  // Current input
              << std::flush;
}

// Helper function to display available commands
void displayHelp() {
    std::cout << "\n\033[1;36m--- Available Commands ---\033[0m\n";
    std::cout << "\033[1;33m/help\033[0m    - Display this help message\n";
    std::cout << "\033[1;33m/exit\033[0m    - Exit the chat program\n";
    std::cout << "\033[1;33m/history\033[0m - Display encrypted chat history\n";
    std::cout << "\033[1;33m/file <path>\033[0m - Send a file to your chat partner\n";
    std::cout << "\033[1;33m/status\033[0m  - Check connection status with relay server\n";
    std::cout << "\n\033[1;36m--- Connection Status Indicators ---\033[0m\n";
    std::cout << "\033[1;31m[!]\033[0m - Connection warning (no response for 5+ seconds)\n";
    std::cout << "\033[1;31m[X]\033[0m - Connection lost\n";
    std::cout << "\033[1;32m[✓]\033[0m - Connection restored\n\n";
}

// Thread for sending heartbeats and checking connection status
void connectionManager(int clientSocket) {
    // Initialize last heartbeat time to now
    lastHeartbeatReceived = std::chrono::steady_clock::now();
    
    while (!shouldExit) {
        // Send heartbeat every HEARTBEAT_INTERVAL_MS
        if (sendHeartbeat(clientSocket)) {
            // Heartbeat sent successfully
        } else {
            if (!connectionLost) {
                connectionLost = true;
                connectionLostTime = std::chrono::steady_clock::now();
                printSystemMessage("Connection to relay server lost. Waiting for reconnection...", true);
                
                // Lock to update display
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    displayPrompt(currentInput);
                }
            }
        }
        
        // Check if connection is lost and manage countdown
        auto now = std::chrono::steady_clock::now();
        if (connectionLost) {
            auto disconnectedTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - connectionLostTime).count();
                
            if (!inCountdownMode && disconnectedTime > CONNECTION_TIMEOUT_MS) {
                // Start countdown after timeout
                inCountdownMode = true;
                countdownSeconds = SHUTDOWN_TIMER_MS / 1000;
                printSystemMessage("No response from relay server. Chat will close in " + 
                                 std::to_string(countdownSeconds) + " seconds if connection is not restored.", true);
                
                // Lock to update display
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    displayPrompt(currentInput);
                }
            }
            else if (inCountdownMode) {
                // Update countdown every second
                int newSeconds = (CONNECTION_TIMEOUT_MS + SHUTDOWN_TIMER_MS - disconnectedTime) / 1000;
                if (newSeconds < countdownSeconds) {
                    countdownSeconds = newSeconds;
                    
                    // Lock to update display
                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        displayPrompt(currentInput);
                    }
                    
                    // Remind user every 3 seconds
                    if (countdownSeconds % 3 == 0) {
                        printSystemMessage("Connection still lost. Closing in " + 
                                         std::to_string(countdownSeconds) + " seconds...", true);
                    }
                    
                    // Time's up - signal main thread to exit
                    if (countdownSeconds <= 0) {
                        printSystemMessage("Connection timeout. Closing chat client...", true);
                        shouldExit = true;
                        kill(getpid(), SIGUSR1); // Signal main thread
                        break;
                    }
                }
            }
        }
        
        // Check for heartbeat timeout
        auto heartbeatAge = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastHeartbeatReceived).count();
        if (!connectionLost && heartbeatAge > CONNECTION_TIMEOUT_MS) {
            connectionLost = true;
            connectionLostTime = now;
            printSystemMessage("No heartbeat from relay server. Waiting for response...", true);
            
            // Lock to update display
            {
                std::lock_guard<std::mutex> lock(inputMutex);
                displayPrompt(currentInput);
            }
        }
        
        // Sleep before next heartbeat
        std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
    }
}

// Message send thread to handle queued messages
void messageSender(int clientSocket, const UserKeyPair& myKeyPair, const unsigned char* friendPublicKey) {
    while (!shouldExit) {
        std::string message;
        bool hasMessage = false;
        
        // Check for queued messages
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (!messageQueue.empty()) {
                message = messageQueue.front();
                messageQueue.pop();
                hasMessage = true;
            }
        }
        
        if (hasMessage && !connectionLost) {
            try {
                EncryptedMessage encryptedMessage = encryptMessage(message, myKeyPair.privateKey, friendPublicKey);
                TransferHeader header;
                std::memset(&header, 0, sizeof(header));
                strncpy(header.type, "MSG", sizeof(header.type));
                header.dataSize = encryptedMessage.cipherTextLength + crypto_box_NONCEBYTES;

                // Send header first
                if (!sendAll(clientSocket, &header, sizeof(header))) {
                    throw std::runtime_error("Failed to send message header - relay server disconnected");
                }

                // Send nonce
                if (!sendAll(clientSocket, encryptedMessage.nonce, crypto_box_NONCEBYTES)) {
                    throw std::runtime_error("Failed to send message nonce - relay server disconnected");
                }

                // Send encrypted data
                if (!sendAll(clientSocket, encryptedMessage.cipherText.data(), 
                            encryptedMessage.cipherTextLength)) {
                    throw std::runtime_error("Failed to send message data - relay server disconnected");
                }

                saveToChatHistory(message, myKeyPair, friendPublicKey, true);
                printMessage("You:", message);
                
                // Update display prompt
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    displayPrompt(currentInput);
                }
            } catch (const std::exception& e) {
                std::string errorMsg = e.what();
                std::cerr << "\033[1;31mError sending message: " << errorMsg << "\033[0m" << std::endl;
                
                // Requeue the message
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    messageQueue.push(message);
                }
                
                // Message could not be sent
                if (!connectionLost) {
                    connectionLost = true;
                    connectionLostTime = std::chrono::steady_clock::now();
                    printSystemMessage("Failed to send message. Connection to relay server lost.", true);
                    
                    // Lock to update display
                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        displayPrompt(currentInput);
                    }
                }
            }
        }
        
        // Sleep briefly to avoid CPU spinning
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// Receive messages or files in a separate thread
void receiveMessages(int clientSocket, const UserKeyPair& myKeyPair, 
                    const unsigned char* friendPublicKey) {
    while (!shouldExit) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);
        
        // Set short timeout for select
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms
        
        int activity = select(clientSocket + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (!connectionLost) {
                connectionLost = true;
                connectionLostTime = std::chrono::steady_clock::now();
                printSystemMessage("Connection error. Waiting for reconnection...", true);
                
                // Lock to update display
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    displayPrompt(currentInput);
                }
            }
            continue;
        }
        
        if (activity == 0) continue; // No activity, just check again
        
        if (FD_ISSET(clientSocket, &readfds)) {
            TransferHeader receivedHeader;
            if (!recvAll(clientSocket, &receivedHeader, sizeof(receivedHeader))) {
                // Connection lost
                if (!connectionLost) {
                    connectionLost = true;
                    connectionLostTime = std::chrono::steady_clock::now();
                    printSystemMessage("Connection to relay server lost. Waiting for reconnection...", true);
                    
                    // Lock to update display
                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        displayPrompt(currentInput);
                    }
                }
                continue;
            }
            
            // Connection restored if we get here
            if (connectionLost) {
                connectionLost = false;
                inCountdownMode = false;
                printSystemMessage("Connection to relay server restored!");
                
                // Lock to update display
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    displayPrompt(currentInput);
                }
            }
            
            // Update last heartbeat time
            lastHeartbeatReceived = std::chrono::steady_clock::now();
            
            // Check for shutdown message (all zeros in type field)
            if (receivedHeader.type[0] == 0 && receivedHeader.type[1] == 0 && 
                receivedHeader.type[2] == 0 && receivedHeader.type[3] == 0) {
                printSystemMessage("Relay server is shutting down. Chat session ended.", true);
                kill(getpid(), SIGUSR1);
                shouldExit = true;
                break;
            }
            
            // Check for heartbeat
            if (strncmp(receivedHeader.type, "HBT", 3) == 0) {
                // Just update last heartbeat time and continue
                continue;
            }
            
            // Handle regular message or file
            // Read nonce
            unsigned char nonce[crypto_box_NONCEBYTES];
            if (!recvAll(clientSocket, nonce, crypto_box_NONCEBYTES)) {
                if (!connectionLost) {
                    connectionLost = true;
                    connectionLostTime = std::chrono::steady_clock::now();
                    printSystemMessage("Connection lost during message transfer. Waiting for reconnection...", true);
                    
                    // Lock to update display
                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        displayPrompt(currentInput);
                    }
                }
                continue;
            }
            
            // Read encrypted data
            std::vector<unsigned char> receivedBuffer(receivedHeader.dataSize - crypto_box_NONCEBYTES);
            if (!recvAll(clientSocket, receivedBuffer.data(), receivedBuffer.size())) {
                if (!connectionLost) {
                    connectionLost = true;
                    connectionLostTime = std::chrono::steady_clock::now();
                    printSystemMessage("Connection lost during message transfer. Waiting for reconnection...", true);
                    
                    // Lock to update display
                    {
                        std::lock_guard<std::mutex> lock(inputMutex);
                        displayPrompt(currentInput);
                    }
                }
                continue;
            }
            
            try {
                EncryptedMessage receivedData;
                std::memcpy(receivedData.nonce, nonce, crypto_box_NONCEBYTES);
                receivedData.cipherTextLength = receivedBuffer.size();
                receivedData.cipherText = receivedBuffer;
                
                std::string decryptedContent = decryptMessage(receivedData, myKeyPair.privateKey, friendPublicKey);
                
                // Get a copy of the current input text
                std::string inputCopy;
                {
                    std::lock_guard<std::mutex> lock(inputMutex);
                    inputCopy = currentInput;
                }
                
                printMessage("Friend:", decryptedContent);
                
                if (strncmp(receivedHeader.type, "MSG", 3) == 0) {
                    saveToChatHistory(decryptedContent, myKeyPair, friendPublicKey, false);
                } else if (strncmp(receivedHeader.type, "FIL", 3) == 0) {
                    std::string outputFileName = std::string("received_") + receivedHeader.fileName;
                    std::ofstream outputFile(outputFileName, std::ios::app | std::ios::binary);
                    if (!outputFile) {
                        throw std::runtime_error("Failed to open output file");
                    }
                    outputFile.write(decryptedContent.c_str(), decryptedContent.size());
                    printSystemMessage("Received file chunk for: " + outputFileName);
                }
                
                // Re-display prompt with current input text
                displayPrompt(inputCopy);
            } catch (const std::exception& e) {
                std::cerr << "\n\033[1;31mError processing received data: " << e.what() << "\033[0m" << std::endl;
                displayPrompt("");
            }
        }
    }
}

// Helper function to convert public key to hex string
std::string publicKeyToHex(const unsigned char* publicKey) {
    char hexString[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hexString, sizeof(hexString), publicKey, crypto_box_PUBLICKEYBYTES);
    return std::string(hexString);
}

// Signal handler to handle immediate exits
void signalHandler(int signum) {
    (void)signum; // Suppress unused parameter warning
    // Just a wake-up call, no action needed
}

int main() {
    try {
        // Set up signal handler for SIGUSR1
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = signalHandler;
        sigaction(SIGUSR1, &sa, NULL);
        
        // Save original terminal settings
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        
        UserKeyPair myKeyPair;
        generateUserKeyPair(myKeyPair);

        // Display our public key
        std::cout << "\nYour public key (share this with your friend):\n"
                  << publicKeyToHex(myKeyPair.publicKey) << "\n\n"
                  << "Commands:\n"
                  << "  /exit     - Exit the program\n"
                  << "  /history  - Display chat history\n"
                  << "  /file     - Send a file (usage: /file <path>)\n"
                  << "  /status   - Check connection status\n\n"
                  << "Enter friend's public key (as hex, " << crypto_box_PUBLICKEYBYTES << " bytes): ";

        // Input friend's public key
        unsigned char friendPublicKey[crypto_box_PUBLICKEYBYTES];
        std::string hexFriendKey;
        std::getline(std::cin, hexFriendKey);
        if (sodium_hex2bin(friendPublicKey, sizeof(friendPublicKey), hexFriendKey.c_str(), 
                          hexFriendKey.size(), nullptr, nullptr, nullptr) != 0) {
            throw std::runtime_error("Invalid public key format");
        }

        // Connect to relay server
        std::cout << "\nEnter relay server IP: ";
        std::string relayServerIP;
        std::getline(std::cin, relayServerIP);

        int clientSocketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocketDescriptor < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set socket options for immediate delivery
        int flag = 1;
        if (setsockopt(clientSocketDescriptor, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            std::cerr << "Warning: Failed to set TCP_NODELAY" << std::endl;
        }
        
        // Enable TCP keepalive
        if (setsockopt(clientSocketDescriptor, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0) {
            std::cerr << "Warning: Failed to enable TCP keepalive" << std::endl;
        }
        
#ifdef __linux__
        // Linux-specific keepalive settings for faster disconnection detection
        int keepalive_time = 1; // Start sending keepalive probes after 1 second of idle
        if (setsockopt(clientSocketDescriptor, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0) {
            std::cerr << "Warning: Failed to set TCP_KEEPIDLE" << std::endl;
        }
        
        int keepalive_intvl = 1; // Send keepalive probe every 1 second
        if (setsockopt(clientSocketDescriptor, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0) {
            std::cerr << "Warning: Failed to set TCP_KEEPINTVL" << std::endl;
        }
        
        int keepalive_probes = 2; // Drop connection after 2 failed probes
        if (setsockopt(clientSocketDescriptor, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0) {
            std::cerr << "Warning: Failed to set TCP_KEEPCNT" << std::endl;
        }
#endif

#ifdef __APPLE__
        // macOS-specific keepalive settings
        int keepalive_time = 1; // Start sending keepalive probes after 1 second of idle
        if (setsockopt(clientSocketDescriptor, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive_time, sizeof(keepalive_time)) < 0) {
            std::cerr << "Warning: Failed to set TCP_KEEPALIVE" << std::endl;
        }
#endif

        struct sockaddr_in relayServerAddress;
        std::memset(&relayServerAddress, 0, sizeof(relayServerAddress));
        relayServerAddress.sin_family = AF_INET;
        relayServerAddress.sin_port = htons(RELAY_PORT);
        if (inet_pton(AF_INET, relayServerIP.c_str(), &relayServerAddress.sin_addr) <= 0) {
            close(clientSocketDescriptor);
            throw std::runtime_error("Invalid IP address");
        }

        // First connect in blocking mode
        if (connect(clientSocketDescriptor, (struct sockaddr*)&relayServerAddress, 
                   sizeof(relayServerAddress)) < 0) {
            close(clientSocketDescriptor);
            throw std::runtime_error("Failed to connect to relay server");
        }

        // After successful connection, set to non-blocking mode
        int flags = fcntl(clientSocketDescriptor, F_GETFL, 0);
        if (flags < 0) {
            std::cerr << "Warning: Failed to get socket flags" << std::endl;
        } else if (fcntl(clientSocketDescriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
            std::cerr << "Warning: Failed to set socket to non-blocking mode" << std::endl;
        }

        std::cout << "Connected to relay server at " << relayServerIP << ":" << RELAY_PORT << std::endl;
        std::cout << "Type a message and press Enter to send. Type /help to see available commands." << std::endl;

        // Start three threads: message receiver, connection manager, and message sender
        std::thread receiverThread(receiveMessages, clientSocketDescriptor, myKeyPair, friendPublicKey);
        std::thread connectionThread(connectionManager, clientSocketDescriptor);
        std::thread senderThread(messageSender, clientSocketDescriptor, myKeyPair, friendPublicKey);

        // Disable terminal echo - we'll handle all output manually
        newt.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        // Main message loop
        std::string input;
        char c;
        
        // Show initial prompt
        displayPrompt("");
        
        while (!shouldExit) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms timeout to check shouldExit flag more frequently
            
            int activity = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
            
            if (activity < 0) {
                if (errno != EINTR) {
                    std::cerr << "\r\033[K\033[1;31mSelect error: " << strerror(errno) << "\033[0m" << std::endl;
                }
                // Check if we should exit on interrupt (might be our signal)
                if (shouldExit) {
                    break;
                }
                continue;
            }
            
            // No activity, check if we should exit due to relay disconnection
            if (activity == 0) {
                if (shouldExit) {
                    break;
                }
                continue;
            }
            
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                if (read(STDIN_FILENO, &c, 1) > 0) {
                    if (c == '\n') {  // Enter key pressed
                        {
                            std::lock_guard<std::mutex> lock(inputMutex);
                            input = currentInput;
                            currentInput.clear();
                        }
                        
                        // Clear the current line and move to beginning
                        std::cout << "\r\033[K";
                        
                        if (input.empty()) {
                            displayPrompt("");
                            continue;
                        }
                        
                        if (input[0] == '/') {
                            // Handle commands
                            if (input == "/exit") {
                                shouldExit = true;
                                break;
                            } else if (input == "/history") {
                                displayChatHistory(myKeyPair, friendPublicKey);
                                displayPrompt("");
                                continue;
                            } else if (input == "/help") {
                                displayHelp();
                                displayPrompt("");
                                continue;
                            } else if (input.substr(0, 5) == "/file ") {
                                try {
                                    if (connectionLost) {
                                        printSystemMessage("Cannot send file while connection is lost. Try again later.", true);
                                        displayPrompt("");
                                        continue;
                                    }
                                    sendFile(clientSocketDescriptor, input.substr(6), myKeyPair, friendPublicKey);
                                } catch (const std::exception& e) {
                                    std::cerr << "\033[1;31mError sending file: " << e.what() << "\033[0m" << std::endl;
                                }
                                displayPrompt("");
                                continue;
                            } else if (input == "/status") {
                                // Add a status command to check connection
                                if (connectionLost) {
                                    printSystemMessage(inCountdownMode ? 
                                        "Connection lost. Closing in " + std::to_string(countdownSeconds) + " seconds unless restored." :
                                        "Connection lost. Waiting for reconnection.", true);
                                } else {
                                    printSystemMessage("Connected to relay server.");
                                }
                                displayPrompt("");
                                continue;
                            }
                        }

                        // Queue the message for sending
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            messageQueue.push(input);
                        }
                        
                        // If connection is lost, inform the user the message is queued
                        if (connectionLost) {
                            printSystemMessage("Message queued and will be sent when connection is restored.");
                        }
                        
                        displayPrompt("");
                    } 
                    else if (c == 127 || c == '\b') {  // Backspace
                        {
                            std::lock_guard<std::mutex> lock(inputMutex);
                            if (!currentInput.empty()) {
                                currentInput.pop_back();
                                displayPrompt(currentInput);
                            }
                        }
                    } 
                    else {
                        {
                            std::lock_guard<std::mutex> lock(inputMutex);
                            currentInput += c;
                            displayPrompt(currentInput);
                        }
                    }
                }
            }
        }

        std::cout << "\r\033[K\033[1;33mChat session ended. Goodbye!\033[0m" << std::endl;

        // Restore terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

        // Cleanup
        if (receiverThread.joinable()) {
            receiverThread.join();
        }
        if (connectionThread.joinable()) {
            connectionThread.join();
        }
        if (senderThread.joinable()) {
            senderThread.join();
        }
        close(clientSocketDescriptor);

    } catch (const std::exception& e) {
        // Restore terminal settings in case of error
        struct termios oldt;
        tcgetattr(STDIN_FILENO, &oldt);
        oldt.c_lflag |= (ECHO | ECHOE | ECHOK | ECHONL | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        
        std::cerr << "\033[1;31mFatal error: " << e.what() << "\033[0m" << std::endl;
        return 1;
    }

    return 0;
}