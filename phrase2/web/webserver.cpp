#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using boost::asio::ip::tcp;

// Helper function to send a response to a WebSocket client
std::string createWebSocketResponse(const std::string &message) {
  std::ostringstream response;
  response << (char)0x81; // FIN + TEXT Frame
  size_t len = message.size();
  if (len <= 125) {
    response << (char)len;
  } else if (len <= 65535) {
    response << (char)126 << (char)((len >> 8) & 0xFF) << (char)(len & 0xFF);
  } else {
    response << (char)127;
    for (int i = 56; i >= 0; i -= 8)
      response << (char)((len >> i) & 0xFF);
  }
  response << message;
  return response.str();
}

int clientSock;

void setupClientConnection() {
  // Connect to client.cpp
  clientSock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in clientAddr{};
  clientAddr.sin_family = AF_INET;
  clientAddr.sin_port = htons(8081); // Communication port with client.cpp
  clientAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(clientSock, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) <
      0) {
    std::cerr << "Connection to client.cpp failed" << std::endl;
    exit(1);
  }

  std::cout << "Connected to client.cpp" << std::endl;
}

void handleClient(tcp::socket socket) {
  try {
    char data[1024];
    std::string handshakeResponse = "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: ";

    // Read handshake request
    socket.read_some(boost::asio::buffer(data, 1024));
    std::string receivedData(data);

    // Extract Sec-WebSocket-Key from client handshake
    auto keyPos = receivedData.find("Sec-WebSocket-Key: ");
    if (keyPos == std::string::npos)
      return;
    std::string secWebSocketKey = receivedData.substr(keyPos + 19, 24);

    // Compute the WebSocket accept key
    secWebSocketKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char hash[20];
    SHA1((unsigned char *)secWebSocketKey.c_str(), secWebSocketKey.size(),
         (unsigned char *)hash);
    std::string acceptKey = base64_encode(hash, 20);
    handshakeResponse += acceptKey + "\r\n\r\n";

    // Send handshake response
    boost::asio::write(socket, boost::asio::buffer(handshakeResponse));

    // Start communication
    while (true) {
      char buffer[1024];
      size_t length = socket.read_some(boost::asio::buffer(buffer, 1024));

      // Decode WebSocket frame
      if (length < 2)
        continue;                          // Minimum frame size
      bool fin = (buffer[0] & 0x80) != 0;  // FIN bit
      bool mask = (buffer[1] & 0x80) != 0; // Mask bit
      size_t payloadLength = buffer[1] & 0x7F;
      size_t maskingKeyOffset = 2;

      if (payloadLength == 126) {
        payloadLength = ((buffer[2] << 8) | buffer[3]);
        maskingKeyOffset = 4;
      } else if (payloadLength == 127) {
        payloadLength = 0; // Extended payload length is not handled
        return;
      }

      // Unmask data
      char maskingKey[4] = {0};
      if (mask) {
        memcpy(maskingKey, &buffer[maskingKeyOffset], 4);
        maskingKeyOffset += 4;
      }

      std::string message(&buffer[maskingKeyOffset], payloadLength);
      if (mask) {
        for (size_t i = 0; i < payloadLength; ++i) {
          message[i] ^= maskingKey[i % 4];
        }
      }

      std::cout << "Received message: " << message << std::endl;

      // Forward message to client.cpp
      send(clientSock, message.c_str(), message.size(), 0);

      // Wait for response from client.cpp
      char responseBuffer[1024];
      int bytesRead = read(clientSock, responseBuffer, 1024);
      if (bytesRead > 0) {
        responseBuffer[bytesRead] = '\0';

        // Send response back to WebSocket client
        std::string responseMessage(responseBuffer);
        std::string websocketResponse =
            createWebSocketResponse(responseMessage);
        boost::asio::write(socket, boost::asio::buffer(websocketResponse));
      }
    }
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }
}

int main() {
  setupClientConnection();

  try {
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context,
                           tcp::endpoint(tcp::v4(), 8082)); // WebSocket port

    std::cout << "WebSocket server listening on port 8082" << std::endl;

    while (true) {
      tcp::socket socket(io_context);
      acceptor.accept(socket);
      std::thread(handleClient, std::move(socket)).detach();
    }
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }

  return 0;
}
