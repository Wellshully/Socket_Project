#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/imgutils.h>
#include <libswscale/swscale.h>
}
#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define NUM_THREADS 10

using namespace std;

struct ClientInfo {
  bool is_logged_in = false;
  string username;
  SSL *ssl;
  string ip;
  int port;
};

unordered_map<int, ClientInfo> client_info;
queue<int> task_queue;
pthread_mutex_t client_info_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

void *worker_thread(void *arg);
void handle_client_command_tls(SSL *ssl, int client_socket);
void handle_sign_in(SSL *ssl);
void handle_login(SSL *ssl, int client_socket);
void handle_logout(SSL *ssl, int client_socket);
void handle_chatroom(SSL *ssl, int client_socket);
void handle_file_upload(SSL *ssl, int client_socket);
void handle_file_download(SSL *ssl, int client_socket);
void handle_client_exit(SSL *ssl, int client_socket);
void video_streaming(SSL *ssl, string &filePath);
void init_openssl();

SSL_CTX *create_server_context();
void cleanup_openssl();
bool configure_server_context(SSL_CTX *ctx, const char *certFile,
                              const char *keyFile);
int main() {
  // SSL setup
  init_openssl();
  SSL_CTX *ctx = create_server_context();
  if (!ctx) {
    return 1;
  }
  if (!configure_server_context(ctx, "server.crt", "server.key")) {
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 1;
  }
  //////////////////////////
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

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

  // accept connections
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
    client_info[new_socket].ssl = SSL_new(ctx);
    SSL_set_fd(client_info[new_socket].ssl, new_socket);
    if (SSL_accept(client_info[new_socket].ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(new_socket);
      SSL_free(client_info[new_socket].ssl);
      continue;
    }

    SSL_write(client_info[new_socket].ssl, "PORT\n", BUFFER_SIZE);
    SSL_read(client_info[new_socket].ssl, port_buf, BUFFER_SIZE);
    client_info[new_socket].port = stoi(port_buf);
    cout << "client listen on port: " << client_info[new_socket].port << "\n";
    SSL_write(client_info[new_socket].ssl, "OK\n", BUFFER_SIZE);
    pthread_mutex_unlock(&client_info_mutex);

    // Add new client socket to task queue
    pthread_mutex_lock(&queue_mutex);
    task_queue.push(new_socket);
    pthread_cond_signal(&condition_var);
    pthread_mutex_unlock(&queue_mutex);
  }
  close(server_fd);
  SSL_CTX_free(ctx);
  cleanup_openssl();
  return 0;
}
void init_openssl() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
}

void cleanup_openssl() { EVP_cleanup(); }

SSL_CTX *create_server_context() {
  SSL_CTX *ct = SSL_CTX_new(TLS_server_method());
  if (!ct) {
    cerr << "Unable to create SSL context\n";
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  // TLS1.2
  SSL_CTX_set_min_proto_version(ct, TLS1_2_VERSION);
  return ct;
}
bool configure_server_context(SSL_CTX *ctx, const char *certFile,
                              const char *keyFile) {
  if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    cerr << "Private key does not match the certificate public key\n";
    return false;
  }

  return true;
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
    SSL *ssl = client_info[client_socket].ssl;
    handle_client_command_tls(ssl, client_socket);

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

void handle_client_command_tls(SSL *ssl, int client_socket) {
  char buffer[BUFFER_SIZE];
  int valread = SSL_read(ssl, buffer, BUFFER_SIZE);

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
    handle_sign_in(ssl);
  } else if (command == "2") {
    handle_login(ssl, client_socket);
  } else if (command == "3") {
    handle_logout(ssl, client_socket);
  } else if (command == "4") {
    handle_client_exit(ssl, client_socket);
  } else if (command == "5") {
    handle_chatroom(ssl, client_socket);
  } else if (command == "6") {
    handle_file_upload(ssl, client_socket);
  } else if (command == "7") {
    handle_file_download(ssl, client_socket);
  }
}
void handle_client_exit(SSL *ssl, int client_socket) {
  cout << "Client on socket " << client_socket << " is disconnecting.\n";
  ////
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(client_socket);
  ////
  pthread_mutex_lock(&client_info_mutex);
  client_info.erase(client_socket); // Remove client from tracking
  pthread_mutex_unlock(&client_info_mutex);
}

void handle_sign_in(SSL *ssl) {
  char username_buffer[BUFFER_SIZE] = {0};
  char password_buffer[BUFFER_SIZE] = {0};

  SSL_write(ssl, "Enter username: ", 16);
  SSL_read(ssl, username_buffer, BUFFER_SIZE);
  SSL_write(ssl, "Enter password: ", 16);
  SSL_read(ssl, password_buffer, BUFFER_SIZE);
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
    SSL_write(ssl, "Username already taken.\n", 24);
    return;
  }

  ofstream user_file_signin("users.txt", ios::app);
  user_file_signin << username_buffer << " " << password_buffer << endl;
  user_file_signin.close();

  SSL_write(ssl, "Sign In successful!\n", 21);
}

void handle_login(SSL *ssl, int client_socket) {
  char username_buffer[BUFFER_SIZE] = {0};
  char password_buffer[BUFFER_SIZE] = {0};
  SSL_write(ssl, "Enter username: ", 16);
  SSL_read(ssl, username_buffer, BUFFER_SIZE);
  SSL_write(ssl, "Enter password: ", 16);
  SSL_read(ssl, password_buffer, BUFFER_SIZE);
  string username = string(username_buffer);
  string password = string(password_buffer);
  for (auto &client : client_info) {
    if (client.second.is_logged_in && client.second.username == username) {
      SSL_write(ssl, "This account is already online\n", 32);
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

      SSL_write(ssl, "Login successful!\n", 19);
      cout << "User login: " << username << "\n";
      break;
    }
  }

  if (!user_found) {
    SSL_write(ssl, "Invalid credentials.\n", 22);
  }
}

void handle_logout(SSL *ssl, int client_socket) {
  pthread_mutex_lock(&client_info_mutex);
  client_info[client_socket].is_logged_in = false;
  client_info[client_socket].username.clear();
  pthread_mutex_unlock(&client_info_mutex);
  SSL_write(ssl, "You have been logged out.\n", 26);
}

void handle_chatroom(SSL *ssl, int client_socket) {
  char buffer[BUFFER_SIZE] = {0};
  pthread_mutex_lock(&client_info_mutex);
  if (client_info[client_socket].is_logged_in) {
    string online_users;
    for (const auto &client : client_info) {
      if (client.second.is_logged_in && client.first != client_socket) {
        online_users += client.second.username + "\n";
      }
    }
    SSL_write(ssl, online_users.c_str(), BUFFER_SIZE);
    int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);
    buffer[bytes_read - 1] = '\0';
    string targetName(buffer);
    bool foundTarget = false;
    int targetSocket = -1;

    for (auto &entry : client_info) {
      if (entry.second.is_logged_in && entry.second.username == targetName) {
        targetSocket = entry.first;
        foundTarget = true;
        break;
      }
    }
    if (!foundTarget) {
      // Target user not found or not logged in
      pthread_mutex_unlock(&client_info_mutex);
      SSL_write(ssl, "NO_SUCH_USER\n", BUFFER_SIZE);
      return;
    }
    string targetIP = client_info[targetSocket].ip;
    int targetPort = client_info[targetSocket].port;

    pthread_mutex_unlock(&client_info_mutex);

    SSL_write(ssl, "OK", 2);
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    SSL_write(ssl, targetIP.c_str(), BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    SSL_write(ssl, to_string(targetPort).c_str(), BUFFER_SIZE);

  } else {
    pthread_mutex_unlock(&client_info_mutex);
    SSL_write(ssl, "NO", 2);
  }
}
void handle_file_upload(SSL *ssl, int client_socket) {
  if (!client_info[client_socket].is_logged_in) {
    SSL_write(ssl, "NO", 2);
    return;
  }
  SSL_write(ssl, "YES", 3);
  char buffer[BUFFER_SIZE] = {0};
  SSL_read(ssl, buffer, BUFFER_SIZE);
  string filename(buffer);

  if (filename.empty()) {
    SSL_write(ssl, "ERROR: No filename provided\n", 29);
    return;
  }
  string fullPath = "SHARED_FILES/" + filename;
  ofstream outfile(fullPath, ios::binary);
  if (!outfile) {
    SSL_write(ssl, "err", 3);
    return;
  }
  SSL_write(ssl, "Start", 5);
  cout << client_info[client_socket].username << " is uploading...\n";
  while (true) {
    memset(buffer, 0, BUFFER_SIZE);
    int bytesRead = SSL_read(ssl, buffer, BUFFER_SIZE);
    if (bytesRead > 0 && string(buffer, bytesRead) == "EOF") {
      break;
    }
    if (bytesRead <= 0)
      break;
    outfile.write(buffer, bytesRead);
  }
  outfile.close();
  cout << "[" << filename << "] uploaded from "
       << client_info[client_socket].username << "\n";
  SSL_write(ssl, "File uploaded successfully\n", 27);
}
void handle_file_download(SSL *ssl, int client_socket) {
  if (!client_info[client_socket].is_logged_in) {
    SSL_write(ssl, "NO", 2);
    return;
  }
  char buffer[BUFFER_SIZE] = {0};
  vector<string> fileNames;
  string fileList = "Available files:\n";
  int index = 0;
  for (const auto &entry :
       std::filesystem::directory_iterator("SHARED_FILES/")) {
    string fileName = entry.path().filename().string();
    fileList += to_string(index) + ": " + fileName + "\n";
    fileNames.push_back(fileName);
    ++index;
  }
  SSL_write(ssl, fileList.c_str(), fileList.size());
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  int fileIndex = stoi(string(buffer));
  if (fileIndex < 0 || fileIndex >= fileNames.size()) {
    SSL_write(ssl, "NO", 2);
    return;
  }
  string requestedFile = "SHARED_FILES/" + fileNames[fileIndex];
  ifstream infile(requestedFile, ios::binary);
  if (!infile) {
    SSL_write(ssl, "NO", 2);
    return;
  }
  SSL_write(ssl, fileNames[fileIndex].c_str(), fileNames[fileIndex].size());
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "Start") != 0) {
    cout << "client_error\n";
    return;
  }
  memset(buffer, 0, BUFFER_SIZE);
  cout << "client uploading\n";
  while (infile) {
    infile.read(buffer, BUFFER_SIZE);
    SSL_write(ssl, buffer, infile.gcount());
  }
  infile.close();
  SSL_write(ssl, "EOF", 3);
}
