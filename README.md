# End-to-End Encrypted Chat/Filesharing Application

Free + open source end-to-end encrypted chat application with secure file sharing capabilities.

## Features

-   End-to-end encryption using libsodium
-   Secure key exchange
-   Real-time file transfer capability
-   Persistent encrypted chat history
-   Interactive command-line interface with color-coded messages
-   Robust connection management with automatic reconnection
-   Connection status monitoring with visual feedback
-   Graceful handling of disconnections and server shutdowns
-   Cross-platform support

## Prerequisites

-   C++ compiler (g++ or clang++)
-   libsodium library
-   Make
-   POSIX-compliant operating system (Linux, macOS, BSD)

### Installing libsodium

On Ubuntu/Debian:

```bash
sudo apt-get install libsodium-dev
```

On macOS:

```bash
brew install libsodium
```

## Building

1. Clone the repository:

```bash
git clone https://github.com/gkub/end2end.git
cd end2end
```

2. Build the project:

```bash
make all
```

This will create two executables:

-   `relay`: The relay server for message forwarding
-   `chat`: The end-to-end encrypted chat client

## Usage

1. Start the relay server:

```bash
./relay
```

2. Start chat clients in separate terminals:

```bash
./chat
```

3. For each chat client:
    - Copy your public key and share it with your chat partner
    - Enter your chat partner's public key when prompted
    - Enter the relay server IP (use 127.0.0.1 for local testing or the server's IP address for remote connections)

## Commands

-   `/help` - Display all available commands
-   `/exit` - Exit the chat program
-   `/history` - Display encrypted chat history
-   `/file <path>` - Send a file to your chat partner
-   `/status` - Check connection status with relay server

### Relay Server Commands

-   `/help` - Display all available commands
-   `/status` - Check connection status of clients
-   `/clients` - Show connected clients with IP addresses
-   `/quit` - Shut down the relay server

## Chat Interface

-   Status indicators appear when connection issues are detected
-   Countdown timer displays when connection is lost
-   Messages are queued during disconnections and sent when connection is restored
-   Timestamps are displayed for all messages

## Connection Management

The application includes a sophisticated connection management system:

-   Heartbeats are exchanged every 500ms between clients and relay server
-   If no heartbeat is received for 5 seconds, the application warns about connection loss
-   After connection loss, a 10-second countdown begins before automatic shutdown
-   If connection is restored during countdown, normal operation resumes automatically
-   Messages typed during disconnection are queued and sent when connection is restored
-   Visual indicators show current connection status in the chat interface

## Security Features

-   End-to-end encryption using libsodium's crypto_box
-   Secure key exchange between clients
-   Encrypted local chat history
-   No message content stored on relay server
-   Forward secrecy (new key pair for each session)
-   Independent verification of key authenticity

## Technical Details

-   Uses TCP sockets with keepalives for reliable connection monitoring
-   Multi-threaded architecture for concurrent sending/receiving
-   Real-time terminal control for interactive UI
-   Signal handling for graceful shutdowns
-   Thread-safe message queuing system
-   Resilient to network disruptions and server failures

## License

[MIT License](LICENSE)

## Contributing

Feel free to fork the repository, no promises I will see/accept contributions but you are welcome to try.
