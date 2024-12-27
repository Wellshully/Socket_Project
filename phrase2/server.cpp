#include <algorithm>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define NUM_THREADS 10

using namespace std;

struct ClientInfo {
  bool is_logged_in = false;
  string username;
  string ip;
  int port;
};

unordered_map<int, ClientInfo> client_info;
queue<int> task_queue;
pthread_mutex_t client_info_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

void *worker_thread(void *arg);
void handle_client_command(int client_socket);
void handle_sign_in(int client_socket);
void handle_login(int client_socket);
void handle_logout(int client_socket);
void handle_chatroom(int client_socket);

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Create the server socket
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Socket failed");
    exit(EXIT_FAILURE);
  }

  // Set socket options
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  // Bind the socket to the network address and port
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // Listen for incoming connections
  if (listen(server_fd, MAX_CLIENTS) < 0) {
    perror("Listen failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  cout << "Server is listening on port " << PORT << "...\n";
  char port_buf[BUFFER_SIZE] = {0};
  // Initialize thread pool
  pthread_t threads[NUM_THREADS];
  for (int i = 0; i < NUM_THREADS; ++i) {
    pthread_create(&threads[i], NULL, worker_thread, NULL);
  }

  // Main server loop to accept connections
  while (true) {
    new_socket =
        accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (new_socket < 0) {
      perror("Accept failed");
      continue;
    }

    cout << "New connection, socket fd is " << new_socket << ", IP is "
         << inet_ntoa(address.sin_addr) << ", port: " << ntohs(address.sin_port)
         << "\n";

    pthread_mutex_lock(&client_info_mutex);
    client_info[new_socket] = ClientInfo();
    client_info[new_socket].ip = inet_ntoa(address.sin_addr);
    send(new_socket, "PORT\n", BUFFER_SIZE, 0);
    read(new_socket, port_buf, BUFFER_SIZE);
    client_info[new_socket].port = stoi(port_buf);
    cout << "client listen on port: " << client_info[new_socket].port << "\n";
    send(new_socket, "OK\n", BUFFER_SIZE, 0);
    pthread_mutex_unlock(&client_info_mutex);

    // Add new client socket to task queue
    pthread_mutex_lock(&queue_mutex);
    task_queue.push(new_socket);
    pthread_cond_signal(&condition_var); // Wake up a worker thread
    pthread_mutex_unlock(&queue_mutex);
  }

  close(server_fd);
  return 0;
}

void *worker_thread(void *arg) {
  while (true) {
    int client_socket;

    // Wait for a task in the queue
    pthread_mutex_lock(&queue_mutex);
    while (task_queue.empty()) {
      pthread_cond_wait(&condition_var, &queue_mutex);
    }

    // Retrieve client socket from the queue
    client_socket = task_queue.front();
    task_queue.pop();
    pthread_mutex_unlock(&queue_mutex);

    // Handle client commands
    handle_client_command(client_socket);

    // Check if the client is still connected and add back to the queue if
    // necessary
    pthread_mutex_lock(&client_info_mutex);
    if (client_info.count(client_socket) >
        0) { // Only re-add if client is still connected
      pthread_mutex_lock(&queue_mutex);
      task_queue.push(
          client_socket); // Re-add the client socket to the task queue
      pthread_cond_signal(&condition_var);
      pthread_mutex_unlock(&queue_mutex);
    }
    pthread_mutex_unlock(&client_info_mutex);
  }
}

void handle_client_command(int client_socket) {
  char buffer[BUFFER_SIZE];
  int valread = read(client_socket, buffer, BUFFER_SIZE);

  if (valread <= 0) {
    // Client disconnected
    cout << "Client on socket " << client_socket << " disconnected.\n";
    close(client_socket);
    pthread_mutex_lock(&client_info_mutex);
    client_info.erase(client_socket); // Remove client from tracking
    pthread_mutex_unlock(&client_info_mutex);
    return;
  }

  buffer[valread] = '\0';
  string command = buffer;
  cout << "Command received from client " << client_socket << ": " << command
       << "\n";

  if (command == "1") {
    handle_sign_in(client_socket);
  } else if (command == "2") {
    handle_login(client_socket);
  } else if (command == "3") {
    handle_logout(client_socket);
  } else if (command == "4") {
    // Disconnect command
    cout << "Client on socket " << client_socket << " is disconnecting.\n";
    close(client_socket);
    pthread_mutex_lock(&client_info_mutex);
    client_info.erase(client_socket); // Remove client from tracking
    pthread_mutex_unlock(&client_info_mutex);
  } else if (command == "5") {
    handle_chatroom(client_socket);
  }
}

void handle_sign_in(int client_socket) {
  char username_buffer[BUFFER_SIZE] = {0};
  char password_buffer[BUFFER_SIZE] = {0};

  send(client_socket, "Enter username: ", 16, 0);
  read(client_socket, username_buffer, BUFFER_SIZE);

  send(client_socket, "Enter password: ", 16, 0);
  read(client_socket, password_buffer, BUFFER_SIZE);

  username_buffer[strcspn(username_buffer, "\n")] = 0;
  password_buffer[strcspn(password_buffer, "\n")] = 0;

  ifstream user_file("users.txt");
  string stored_username, stored_password;
  bool username_exists = false;

  while (user_file >> stored_username >> stored_password) {
    if (stored_username == username_buffer) {
      username_exists = true;
      break;
    }
  }
  user_file.close();

  if (username_exists) {
    send(client_socket, "Username already taken.\n", 24, 0);
    return;
  }

  ofstream user_file_signin("users.txt", ios::app);
  user_file_signin << username_buffer << " " << password_buffer << endl;
  user_file_signin.close();

  send(client_socket, "Sign In successful!\n", 21, 0);
}

void handle_login(int client_socket) {
  char username_buffer[BUFFER_SIZE] = {0};
  char password_buffer[BUFFER_SIZE] = {0};
  send(client_socket, "Enter username: ", 16, 0);
  read(client_socket, username_buffer, BUFFER_SIZE);
  send(client_socket, "Enter password: ", 16, 0);
  read(client_socket, password_buffer, BUFFER_SIZE);
  string username = string(username_buffer);
  string password = string(password_buffer);
  for (auto &client : client_info) {
    if (client.second.is_logged_in && client.second.username == username) {
      send(client_socket, "This account is already online\n", 32, 0);
      return;
    }
  }
  username.erase(remove(username.begin(), username.end(), '\n'),
                 username.end());
  password.erase(remove(password.begin(), password.end(), '\n'),
                 password.end());

  ifstream user_file("users.txt");
  string stored_username, stored_password;
  bool user_found = false;

  while (user_file >> stored_username >> stored_password) {
    if (stored_username == username && stored_password == password) {
      user_found = true;
      pthread_mutex_lock(&client_info_mutex);
      client_info[client_socket].is_logged_in = true;
      client_info[client_socket].username = username;
      pthread_mutex_unlock(&client_info_mutex);

      send(client_socket, "Login successful!\n", 19, 0);
      cout << "User login: " << username << "\n";
      break;
    }
  }

  if (!user_found) {
    send(client_socket, "Invalid credentials.\n", 22, 0);
  }
}

void handle_logout(int client_socket) {
  pthread_mutex_lock(&client_info_mutex);
  client_info[client_socket].is_logged_in = false;
  client_info[client_socket].username.clear();
  pthread_mutex_unlock(&client_info_mutex);

  send(client_socket, "You have been logged out.\n", 26, 0);
}

void handle_chatroom(int client_socket) {
  char buffer[BUFFER_SIZE] = {0};
  pthread_mutex_lock(&client_info_mutex);
  if (client_info[client_socket].is_logged_in) {
    string online_users = "Online users:\n";
    for (const auto &client : client_info) {
      if (client.second.is_logged_in && client.first != client_socket) {
        online_users += client.second.username + "\n";
      }
    }
    send(client_socket, online_users.c_str(), BUFFER_SIZE, 0);
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE);
    buffer[bytes_read - 1] = '\0';
    string targetName(buffer);
    cout << "Find" << targetName << "\n";
    bool foundTarget = false;
    int targetSocket = -1;

    for (auto &entry : client_info) {
      cout << "log: " << entry.second.is_logged_in
           << "name: " << entry.second.username << "\n";
      if (entry.second.is_logged_in && entry.second.username == targetName) {
        targetSocket = entry.first;
        foundTarget = true;
        break;
      }
    }
    if (!foundTarget) {
      // Target user not found or not logged in
      pthread_mutex_unlock(&client_info_mutex);
      send(client_socket, "NO_SUCH_USER\n", BUFFER_SIZE, 0);
      return;
    }
    string targetIP = client_info[targetSocket].ip;
    int targetPort = client_info[targetSocket].port;

    pthread_mutex_unlock(&client_info_mutex);

    send(client_socket, "OK", 2, 0);
    memset(&buffer, 0, BUFFER_SIZE);
    read(client_socket, buffer, BUFFER_SIZE);
    send(client_socket, targetIP.c_str(), BUFFER_SIZE, 0);
    memset(&buffer, 0, BUFFER_SIZE);
    read(client_socket, buffer, BUFFER_SIZE);
    send(client_socket, to_string(targetPort).c_str(), BUFFER_SIZE, 0);

  } else {
    pthread_mutex_unlock(&client_info_mutex);
    send(client_socket, "NO", 2, 0);
  }
}
