#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <sodium.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <errno.h>

#define MESSAGE_BUFFER_SIZE 2048
#define RELAY_PORT 5555
#define FILE_CHUNK_SIZE 1024 // Size of file chunks to send
#define HISTORY_FILE_PREFIX "chat_history_"

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
    char type[4]; // "MSG" for message, "FIL" for file
    size_t dataSize; // Size of the following encrypted data
    char fileName[256]; // File name (if type is "FIL"), zeroed for messages
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
            if (errno == EINTR) continue;
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
            return false;
        }
        ptr += received;
        length -= received;
    }
    return true;
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
    
    // Allocate space for hex string (2 chars per byte + null terminator)
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
        
        historyFile << (isSent ? "Sent: " : "Received: ");
        historyFile.write(reinterpret_cast<char*>(encryptedHistoryEntry.nonce), crypto_box_NONCEBYTES);
        historyFile.write(reinterpret_cast<char*>(encryptedHistoryEntry.cipherText.data()), 
                        encryptedHistoryEntry.cipherTextLength);
        historyFile << std::endl;
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
        std::string line;
        while (std::getline(historyFile, line)) {
            if (line.empty()) continue;
            
            // Extract prefix (Sent: or Received:)
            size_t prefixLength = line.find(": ") + 2;
            if (prefixLength == 1) continue; // Invalid line format
            
            // Read nonce
            unsigned char nonce[crypto_box_NONCEBYTES];
            historyFile.read(reinterpret_cast<char*>(nonce), crypto_box_NONCEBYTES);
            
            // Read encrypted data
            std::vector<unsigned char> encryptedData;
            char byte;
            while (historyFile.get(byte) && byte != '\n') {
                encryptedData.push_back(static_cast<unsigned char>(byte));
            }
            
            if (encryptedData.empty()) continue;
            
            // Create encrypted message structure
            EncryptedMessage historyEntry;
            std::memcpy(historyEntry.nonce, nonce, crypto_box_NONCEBYTES);
            historyEntry.cipherTextLength = encryptedData.size();
            historyEntry.cipherText = encryptedData;
            
            // Decrypt and display
            std::string decryptedMessage = decryptMessage(historyEntry, myKeyPair.privateKey, friendPublicKey);
            std::cout << line.substr(0, prefixLength) << decryptedMessage << std::endl;
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

// Global flag for graceful shutdown
std::atomic<bool> shouldExit(false);

// Receive messages or files in a separate thread
void receiveMessages(int clientSocket, const UserKeyPair& myKeyPair, 
                    const unsigned char* friendPublicKey) {
    while (!shouldExit) {
        TransferHeader receivedHeader;
        if (!recvAll(clientSocket, &receivedHeader, sizeof(receivedHeader))) {
            std::cout << "\nDisconnected from relay server." << std::endl;
            shouldExit = true;
            break;
        }

        std::vector<unsigned char> receivedBuffer(receivedHeader.dataSize);
        if (!recvAll(clientSocket, receivedBuffer.data(), receivedHeader.dataSize)) {
            std::cout << "\nFailed to receive complete message." << std::endl;
            shouldExit = true;
            break;
        }

        try {
            EncryptedMessage receivedData;
            std::memcpy(receivedData.nonce, receivedBuffer.data(), crypto_box_NONCEBYTES);
            receivedData.cipherTextLength = receivedHeader.dataSize - crypto_box_NONCEBYTES;
            receivedData.cipherText.resize(receivedData.cipherTextLength);
            std::memcpy(receivedData.cipherText.data(), 
                       receivedBuffer.data() + crypto_box_NONCEBYTES, 
                       receivedData.cipherTextLength);

            std::string decryptedContent = decryptMessage(receivedData, myKeyPair.privateKey, friendPublicKey);
            
            if (strncmp(receivedHeader.type, "MSG", 3) == 0) {
                std::cout << "\nFriend: " << decryptedContent << std::endl;
                saveToChatHistory(decryptedContent, myKeyPair, friendPublicKey, false);
            } else if (strncmp(receivedHeader.type, "FIL", 3) == 0) {
                std::string outputFileName = std::string("received_") + receivedHeader.fileName;
                std::ofstream outputFile(outputFileName, std::ios::app | std::ios::binary);
                if (!outputFile) {
                    throw std::runtime_error("Failed to open output file");
                }
                outputFile.write(decryptedContent.c_str(), decryptedContent.size());
                std::cout << "\nReceived file chunk for: " << outputFileName << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "\nError processing received data: " << e.what() << std::endl;
        }
        
        std::cout << "You: ";
        std::flush(std::cout);
    }
}

// Helper function to convert public key to hex string
std::string publicKeyToHex(const unsigned char* publicKey) {
    char hexString[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hexString, sizeof(hexString), publicKey, crypto_box_PUBLICKEYBYTES);
    return std::string(hexString);
}

int main() {
    try {
        UserKeyPair myKeyPair;
        generateUserKeyPair(myKeyPair);

        // Display our public key
        std::cout << "\nYour public key (share this with your friend):\n"
                  << publicKeyToHex(myKeyPair.publicKey) << "\n\n"
                  << "Commands:\n"
                  << "  /exit     - Exit the program\n"
                  << "  /history  - Display chat history\n"
                  << "  /file     - Send a file (usage: /file <path>)\n\n"
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

        struct sockaddr_in relayServerAddress;
        std::memset(&relayServerAddress, 0, sizeof(relayServerAddress));
        relayServerAddress.sin_family = AF_INET;
        relayServerAddress.sin_port = htons(RELAY_PORT);
        if (inet_pton(AF_INET, relayServerIP.c_str(), &relayServerAddress.sin_addr) <= 0) {
            close(clientSocketDescriptor);
            throw std::runtime_error("Invalid IP address");
        }

        if (connect(clientSocketDescriptor, (struct sockaddr*)&relayServerAddress, 
                   sizeof(relayServerAddress)) < 0) {
            close(clientSocketDescriptor);
            throw std::runtime_error("Failed to connect to relay server");
        }

        std::cout << "Connected to relay server at " << relayServerIP << ":" << RELAY_PORT << std::endl;

        // Start receiving thread
        std::thread receiverThread(receiveMessages, clientSocketDescriptor, myKeyPair, friendPublicKey);

        // Main message loop
        std::string input;
        while (!shouldExit) {
            std::cout << "You: ";
            std::getline(std::cin, input);
            
            if (input.empty()) continue;
            
            if (input[0] == '/') {
                // Handle commands
                if (input == "/exit") {
                    shouldExit = true;
                    break;
                } else if (input == "/history") {
                    displayChatHistory(myKeyPair, friendPublicKey);
                    continue;
                } else if (input.substr(0, 5) == "/file ") {
                    try {
                        sendFile(clientSocketDescriptor, input.substr(6), myKeyPair, friendPublicKey);
                    } catch (const std::exception& e) {
                        std::cerr << "Error sending file: " << e.what() << std::endl;
                    }
                    continue;
                }
            }

            try {
                EncryptedMessage encryptedMessage = encryptMessage(input, myKeyPair.privateKey, friendPublicKey);
                TransferHeader header;
                std::memset(&header, 0, sizeof(header));
                strncpy(header.type, "MSG", sizeof(header.type));
                header.dataSize = encryptedMessage.cipherTextLength + crypto_box_NONCEBYTES;

                // Send header first
                if (!sendAll(clientSocketDescriptor, &header, sizeof(header))) {
                    throw std::runtime_error("Failed to send message header");
                }

                // Send nonce
                if (!sendAll(clientSocketDescriptor, encryptedMessage.nonce, crypto_box_NONCEBYTES)) {
                    throw std::runtime_error("Failed to send message nonce");
                }

                // Send encrypted data
                if (!sendAll(clientSocketDescriptor, encryptedMessage.cipherText.data(), 
                            encryptedMessage.cipherTextLength)) {
                    throw std::runtime_error("Failed to send message data");
                }

                saveToChatHistory(input, myKeyPair, friendPublicKey, true);
                std::cout << "Message sent successfully." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error sending message: " << e.what() << std::endl;
            }
        }

        // Cleanup
        if (receiverThread.joinable()) {
            receiverThread.join();
        }
        close(clientSocketDescriptor);

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}