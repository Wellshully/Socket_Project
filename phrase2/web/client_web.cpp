#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

void startWebServer() {
  // Start the webserver
  std::system("./webserver &"); // Adjust this to the correct command for
                                // starting your web server
}

void openBrowser() {
  // Open the browser to the front-end URL
  std::system("firefox http://localhost:8081"); // Adjust this for your platform
                                                // (e.g., "open" for macOS)
}

int main() {
  // Start the web server
  startWebServer();

  // Open the browser
  openBrowser();

  // Connect to the server.cpp
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    std::cerr << "Socket creation failed" << std::endl;
    return -1;
  }

  sockaddr_in serverAddr{};
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(8080); // Adjust the port to match your server.cpp
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    std::cerr << "Connection to server failed" << std::endl;
    return -1;
  }

  std::cout << "Connected to server" << std::endl;

  // Set up communication with webserver.cpp
  int websock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in webServerAddr{};
  webServerAddr.sin_family = AF_INET;
  webServerAddr.sin_port = htons(8082); // Webserver communication port
  webServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(websock, (struct sockaddr *)&webServerAddr,
              sizeof(webServerAddr)) < 0) {
    std::cerr << "Connection to web server failed" << std::endl;
    return -1;
  }

  std::thread([&]() {
    char buffer[1024];
    while (true) {
      int bytesRead = read(websock, buffer, 1024);
      if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        std::cout << "Received from webserver: " << buffer << std::endl;

        // Forward message to server
        send(sock, buffer, bytesRead, 0);

        // Receive response from server
        char serverResponse[1024];
        int serverBytes = read(sock, serverResponse, 1024);
        if (serverBytes > 0) {
          serverResponse[serverBytes] = '\0';

          // Forward response back to webserver
          send(websock, serverResponse, serverBytes, 0);
        }
      }
    }
  }).detach();

  // Keep client running
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  close(sock);
  close(websock);

  return 0;
}
