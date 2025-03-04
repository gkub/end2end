# End-to-End Encrypted Chat/Filesharing Application

Free + open source end-to-end chat app. Don't trust it, it's not done.

## Features

- End-to-end encryption using libsodium
- Secure key exchange
- File transfer capability
- Persistent chat history
- Command-line interface
- Cross-platform support

## Prerequisites

- C++ compiler (g++ or clang++)
- libsodium library
- Make

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
git clone <your-repo-url>
cd end2end
```

2. Build the project:
```bash
make all
```

This will create two executables:
- `relay`: The relay server
- `chat`: The chat client

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
   - Copy your public key and share it with your friend
   - Enter your friend's public key when prompted
   - Enter the relay server IP (usually 127.0.0.1 for local testing)

## Commands

- `/exit` - Exit the program
- `/history` - Display chat history
- `/file <path>` - Send a file to your friend

## Chat History

Chat history is stored in the `chat_history` directory, with each conversation having its own file. The files are encrypted and can only be read by the participants of the conversation.

## Security Features

- End-to-end encryption using libsodium's crypto_box
- Secure key exchange
- Encrypted chat history
- No message storage on the relay server
- Forward secrecy (new key pair for each session)

## Technical Details

- Uses TCP sockets for communication
- Implements reliable message delivery
- Handles partial sends/receives
- Supports file transfer in chunks
- Thread-safe message handling

## License

[Your chosen license]

## Contributing

[Your contribution guidelines] 
