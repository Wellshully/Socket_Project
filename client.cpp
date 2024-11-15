#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

int main() {
  int sock = 0;
  struct sockaddr_in serv_addr;
  char buffer[BUFFER_SIZE] = {0};

  string status = "[Not logged in]"; // Initialize status as "Not logged in"

  // Create socket
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    cout << "Socket creation error\n";
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  // Connect to server
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
    cout << "Invalid address / Address not supported\n";
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    cout << "Connection Failed\n";
    return -1;
  }

  cout << "Connected to the server.\n";

  while (true) {
    // Show prompt with current status
    cout << "------------------------------------------------------------------"
            "---------------\n"
         << status
         << " Enter command (1: Sign In, 2: Login, 3: Logout, 4: Exit, 5: "
            "Message): ";
    string command;
    getline(cin, command);

    if (command == "1") {
      // Sign In
      send(sock, command.c_str(), command.size(), 0);
      string username, password;

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive username prompt
      cout << buffer;
      getline(cin, username);
      send(sock, username.c_str(), username.size(), 0); // Send username

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive password prompt
      cout << buffer;
      getline(cin, password);
      send(sock, password.c_str(), password.size(), 0); // Send password

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive sign-in response
      cout << buffer << endl;

    } else if (command == "2") {
      // Login
      send(sock, command.c_str(), command.size(), 0);
      string username, password;

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive username prompt
      cout << buffer;
      getline(cin, username);
      send(sock, username.c_str(), username.size(), 0); // Send username

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive password prompt
      cout << buffer;
      getline(cin, password);
      send(sock, password.c_str(), password.size(), 0); // Send password

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive login response
      cout << buffer << endl;

      // Update status if login successful
      if (strstr(buffer, "Login successful") != nullptr) {
        status =
            "[" + username + "]"; // Update status to show logged-in username
      }

    } else if (command == "3") {
      // Logout
      send(sock, command.c_str(), command.size(), 0);

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive logout response
      cout << buffer << endl;

      // Reset status to "Not logged in" on logout
      status = "[Not logged in]";

    } else if (command == "4") {
      // Exit
      send(sock, command.c_str(), command.size(), 0);
      cout << "Exiting...\n";
      break;

    } else if (command == "5") {
      // Send Message
      send(sock, command.c_str(), command.size(), 0);
      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Check if user is logged in

      if (strcmp(buffer, "NO") == 0) {
        cout << "Need log in\n";
        continue;
      }

      // Sending message if logged in
      string message;
      cout << "You (send message): ";
      getline(cin, message);
      send(sock, message.c_str(), message.size(), 0);

      memset(buffer, 0, BUFFER_SIZE);
      int bytes_read =
          read(sock, buffer, BUFFER_SIZE); // Receive server response
      if (bytes_read > 0) {
        cout << buffer << endl;
      }

    } else {
      cout << "No such command\n";
    }
  }

  close(sock);
  return 0;
}
