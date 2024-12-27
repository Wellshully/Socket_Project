#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

pthread_mutex_t inviteMutex = PTHREAD_MUTEX_INITIALIZER;
bool hasInvitation = false;
int incomingSockfd = -1;
int assignedPort = -1;
SSL *chatroom_server_ssl = nullptr;
// colorHelper
string colorText(const string &text, const string &colorCode) {
  return colorCode + text + "\033[0m";
}

const string RED = "\033[31m";
const string GREEN = "\033[32m";
const string YELLOW = "\033[33m";
const string BLUE = "\033[34m";
const string MAGENTA = "\033[35m";
const string CYAN = "\033[36m";
const string WHITE = "\033[37m";
const string BOLD = "\033[1m";
//////////////////////////////
void init_openssl();
SSL_CTX *create_client_context();
void messageHelper(deque<string> &chatRecord, const string &newMessage);
void chatRoom(SSL *ssl);
int create_listenSock();
void *listenThread(void *arg);
void check_invitation();
string select_file();
void upload_file(SSL *ssl);
void download_file(SSL *ssl);
void sign_in(SSL *ssl);
string log_in(SSL *ssl, string status);
string log_out(SSL *ssl, string status);
void initiate_chat(SSL *ssl);
char buffer[BUFFER_SIZE] = {0};
string user;
int main() {
  system("clear");
  string username, password;
  int sock = 0;
  struct sockaddr_in serv_addr;

  string status = "[Not logged in]"; // Initialize status as "Not logged in"
  init_openssl();
  SSL_CTX *ctx = create_client_context();
  if (!ctx) {
    EVP_cleanup();
    return 1;
  }
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
    cout << colorText("Connection Failed\n", RED);
    return -1;
  }

  cout << colorText("Connected to the server.\n", GREEN);
  // SSL setup
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 1;
  }
  //////////////////////////
  int listenSock = create_listenSock();
  pthread_t tid;
  int *pListensock = new int(listenSock);
  if (pthread_create(&tid, nullptr, listenThread, pListensock) != 0) {
    cerr << "Faild to create listening thread\n";
    close(listenSock);
    close(sock);
    return 1;
  }
  pthread_detach(tid);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  string port_str = to_string(assignedPort);
  SSL_write(ssl, port_str.c_str(), BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);

  while (true) {
    // check invitation
    check_invitation();
    // talk to server
    cout << "----------------------------------------------------------------"
            "--"
            "---------------\n"
         << status
         << " Enter command (1: Sign In, 2: Login, 3: Logout, 4: Exit, 5: "
            "Chatroom, 6: upload, 7: download): ";
    string command;
    getline(cin, command);

    if (command == "1") {
      SSL_write(ssl, command.c_str(), command.size());

      sign_in(ssl);
    } else if (command == "2") {
      SSL_write(ssl, command.c_str(), command.size());

      status = log_in(ssl, status);
    } else if (command == "3") {
      check_invitation();
      SSL_write(ssl, command.c_str(), command.size());

      status = log_out(ssl, status);
    } else if (command == "4") {
      // Exit
      check_invitation();
      SSL_write(ssl, command.c_str(), command.size());
      cout << "Exiting...\n";
      break;
    } else if (command == "5") {
      check_invitation();
      SSL_write(ssl, command.c_str(), command.size());
      initiate_chat(ssl);
    } else if (command == "6") {
      check_invitation();
      SSL_write(ssl, command.c_str(), command.size());
      upload_file(ssl);
    } else if (command == "7") {
      check_invitation();
      SSL_write(ssl, command.c_str(), command.size());
      download_file(ssl);
    }
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}
void init_openssl() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
}

SSL_CTX *create_client_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    std::cerr << "Unable to create SSL context\n";
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

  return ctx;
}
void sign_in(SSL *ssl) {
  // Sign In
  string username, password;

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive username prompt
  cout << colorText(buffer, YELLOW);
  getline(cin, username);
  while (username.empty()) {
    cout << colorText("Username cannot be empty\n", RED);
    cout << colorText("Enter username: ", YELLOW + BOLD);
    getline(cin, username);
  }

  SSL_write(ssl, username.c_str(), username.size()); // Send username

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive password prompt
  cout << colorText(buffer, YELLOW);
  getline(cin, password);
  while (password.empty()) {
    cout << colorText("Password cannot be empty\n", RED);
    cout << colorText("Enter password: ", YELLOW + BOLD);
    getline(cin, password);
  }

  SSL_write(ssl, password.c_str(), password.size()); // Send password

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive sign-in response
  cout << buffer << "\n";
}
string log_in(SSL *ssl, string status) {
  // Login
  string username, password;
  if (status != "[Not logged in]") {
    cout << colorText("You are logged in\n", RED);
    return status;
  }

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive username prompt
  cout << colorText(buffer, YELLOW);
  getline(cin, username);
  while (username.empty()) {
    cout << colorText("Username cannot be empty\n", RED);
    cout << colorText("Enter username: ", YELLOW);
    getline(cin, username);
  }
  SSL_write(ssl, username.c_str(), BUFFER_SIZE); // Send username

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive password prompt
  cout << colorText(buffer, YELLOW + BOLD);
  getline(cin, password);
  while (password.empty()) {
    cout << colorText("Password cannot be empty\n", RED);
    cout << colorText("Enter password: ", YELLOW);
    getline(cin, password);
  }
  SSL_write(ssl, password.c_str(), BUFFER_SIZE); // Send password

  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive login response
  if (strstr(buffer, "Login successful") != nullptr) {
    status = "[" + username + "]";
    status = colorText(status, GREEN);
    cout << colorText(buffer, GREEN) << "\n";
  } else {
    cout << colorText(buffer, RED) << "\n";
  }
  user = username;
  return status;
}
string log_out(SSL *ssl, string status) {
  // Logout
  if (status == "[Not logged in]") {
    cout << colorText("You have to log in first\n", RED);
    return status;
  }
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Receive logout response

  // Reset status to "Not logged in" on logout
  status = "[Not logged in]";
  cout << colorText("Logged out\n", GREEN);
  user = nullptr;
  return status;
}
void initiate_chat(SSL *ssl) {
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE); // Check if user is logged in

  if (strcmp(buffer, "NO") == 0) {
    cout << colorText("Need log in\n", RED);
    return;
  }
  cout << colorText("---| ", YELLOW) << colorText(buffer, GREEN);
  // online user

  string peer;
  cout << "Chat with: ";
  getline(cin, peer);
  if (peer == user) {
    cout << colorText("Cannot chat with yourself\n", RED);
    return;
  }
  string peer_ = peer + "\n";
  cout << colorText("Waiting for the response......\n", YELLOW);
  SSL_write(ssl, peer_.c_str(), peer_.size());
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "OK") == 0) {
    SSL_write(ssl, "IP", 2);
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    string chatIP = buffer;
    SSL_write(ssl, "PORT", 4);
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    string chatPort = buffer;
    // Now this client(inviter) serve as a chatroom-client, and the
    // invited one is the server
    SSL_CTX *tlsClientCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(tlsClientCtx, SSL_VERIFY_NONE, nullptr);
    int chatsock = 0;
    struct sockaddr_in char_addr;
    if ((chatsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      cout << "Chatrooom socket creation error\n";
      return;
    }
    char_addr.sin_family = AF_INET;
    char_addr.sin_port = htons(stoi(chatPort));
    if (inet_pton(AF_INET, chatIP.c_str(), &char_addr.sin_addr) <= 0) {
      cout << "Invalid chatroom address\n";
      return;
    }
    if (connect(chatsock, (struct sockaddr *)&char_addr, sizeof(char_addr)) <
        0) {
      cout << "Chatrooom connection failed\n";
      return;
    }

    SSL *chatroom_ssl = SSL_new(tlsClientCtx);
    SSL_set_fd(chatroom_ssl, chatsock);
    if (SSL_connect(chatroom_ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(chatsock);
      SSL_free(chatroom_ssl);
    }
    memset(buffer, 0, BUFFER_SIZE);
    SSL_read(chatroom_ssl, buffer, BUFFER_SIZE);
    if (strcmp(buffer, "OK") == 0) {
      cout << "Entering the chatroom with [" << colorText(peer, MAGENTA)
           << "]\n";
      chatRoom(chatroom_ssl);
    } else {
      cout << colorText("The invitation is rejected\n", RED);
    }
    SSL_shutdown(chatroom_ssl);
    SSL_free(chatroom_ssl);
    close(chatsock);
  } else {
    cout << colorText(buffer, RED) << "\n";
  }
}
void messageHelper(deque<string> &chatRecord, const string &newMessage) {
  if (!newMessage.empty()) {
    chatRecord.push_back(newMessage);
  }

  while (chatRecord.size() > 30) {
    chatRecord.pop_front();
  }
  system("clear");
  for (auto &line : chatRecord) {
    cout << line << "\n";
  }
  int blankLines = 30 - chatRecord.size();
  for (int i = 0; i < blankLines; i++) {
    cout << "\n";
  }
  cout << "----------------(Enter message or exit_chatroom)----------------\n";
  cout << "[Me]: ";
  cout.flush();
}

void chatRoom(SSL *ssl) {
  deque<string> chatRecord;
  messageHelper(chatRecord, "");
  bool running = true;
  auto recvThreadFunc = [&](SSL *s) {
    char buffer[BUFFER_SIZE];
    while (running) {
      memset(buffer, 0, BUFFER_SIZE);
      int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);
      if (bytes_read <= 0) {
        cout << colorText("Peer disconneted\n", RED);
        running = false;
        break;
      }
      string msg(buffer);
      if (msg == "exit_chatroom") {
        cout << colorText("\nPeer left the chatroom, press enter to exit\n",
                          RED);
        running = false;
        SSL_write(ssl, msg.c_str(), msg.size());
        break;
      }
      messageHelper(chatRecord,
                    colorText("[Peer]: ", MAGENTA) + colorText(msg, YELLOW));
    }
  };
  thread recvThread(recvThreadFunc, ssl);
  while (running) {
    string userMsg;
    if (!getline(cin, userMsg)) {
      // cin breaks
      running = false;
      break;
    }
    if (!running) {
      break;
    }
    if (userMsg == "exit_chatroom") {
      SSL_write(ssl, userMsg.c_str(), userMsg.size());
      running = false;
      break;
    } else {
      messageHelper(chatRecord,
                    colorText("[Me]: ", CYAN) + colorText(userMsg, YELLOW));
      SSL_write(ssl, userMsg.c_str(), userMsg.size());
    }
  }
  system("clear");
  recvThread.join();
}
int create_listenSock() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    cerr << "Error creating socket\n";
    return -1;
  }
  int opt = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0; // any available
  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    cerr << "Bind failed\n";
    close(sockfd);
    return -1;
  }
  if (listen(sockfd, 5) < 0) {
    cerr << "Listen failed\n";
    close(sockfd);
    return -1;
  }
  socklen_t len = sizeof(addr);
  if (getsockname(sockfd, (struct sockaddr *)&addr, &len) == 0) {
    assignedPort = ntohs(addr.sin_port);
    cout << "Listen sock port: " << assignedPort << "\n";
  } else {
    cerr << "getsockname() faild\n";
  }
  return sockfd;
}
void *listenThread(void *arg) {
  // serve as a server(for p2p chatroom)
  int listenSock = *(int *)arg;
  delete (int *)arg;
  SSL_CTX *tlsServerCtx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate_file(tlsServerCtx, "client.crt", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(tlsServerCtx, "client.key", SSL_FILETYPE_PEM);

  while (true) {
    sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    int newSock =
        accept(listenSock, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (newSock < 0) {
      cerr << "accept error\n";
      continue;
    }
    pthread_mutex_lock(&inviteMutex);
    chatroom_server_ssl = SSL_new(tlsServerCtx);
    SSL_set_fd(chatroom_server_ssl, newSock);
    if (SSL_accept(chatroom_server_ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(newSock);
      SSL_free(chatroom_server_ssl);
    }
    if (hasInvitation == true) {
      SSL_write(chatroom_server_ssl, "No", 2);
      close(newSock);
      pthread_mutex_unlock(&inviteMutex);
      return nullptr;
    }
    hasInvitation = true;
    incomingSockfd = newSock;
    pthread_mutex_unlock(&inviteMutex);
  }
  return nullptr;
}
void check_invitation() {
  pthread_mutex_lock(&inviteMutex);
  bool localhasInvitation = hasInvitation;
  int localincomingSockfd = incomingSockfd;
  pthread_mutex_unlock(&inviteMutex);
  if (localhasInvitation) {
    cout << colorText("Incoming chat initation! Accept? (y/n): ", CYAN);
    string answer;
    cin >> answer;
    if (answer == "y" || answer == "Y") {
      SSL_write(chatroom_server_ssl, "OK", 2);
      cout << "Entering chatroom...\n";
      chatRoom(chatroom_server_ssl);
      close(localincomingSockfd);
      cout << "Exited chatroom\n";
    } else {
      SSL_write(chatroom_server_ssl, "NO", 2);
      close(localincomingSockfd);
    }
    pthread_mutex_lock(&inviteMutex);
    SSL_shutdown(chatroom_server_ssl);
    SSL_free(chatroom_server_ssl);
    hasInvitation = false;
    incomingSockfd = -1;
    pthread_mutex_unlock(&inviteMutex);
  }
}
string select_file() {
  const char *zenityCommand =
      "zenity --file-selection --title=\"Select a file to upload\" 2>/dev/null";
  char buffer[512];
  string filePath;
  cout << "select\n";
  FILE *pipe = popen(zenityCommand, "r");
  if (!pipe) {
    cerr << "Failed to open Zenity file selection dialog.\n";
    return "";
  }

  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    filePath += buffer;
  }
  pclose(pipe);
  filePath.erase(filePath.find_last_not_of(" \n\r\t") + 1);
  return filePath;
}
void upload_file(SSL *ssl) {
  char buffer[BUFFER_SIZE] = {0};
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "NO") == 0) {
    cout << colorText("Need log in\n", RED);
    return;
  }
  cout << "log check\n";
  string filePath = select_file();
  if (filePath.empty()) {
    cout << "No file selected.\n";
    return;
  }
  ifstream infile(filePath, ios::binary);
  if (!infile) {
    cout << "ERROR: File not found or cannot be opened.\n";
    return;
  }
  size_t pos = filePath.find_last_of("/\\");
  string filename = filePath.substr(pos + 1);
  SSL_write(ssl, filename.c_str(), filename.size());
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "Start") != 0) {
    cout << colorText("Cannot upload now\n", RED);
    return;
  }
  memset(buffer, 0, BUFFER_SIZE);
  cout << colorText("Uploading...\n", YELLOW);
  while (infile) {
    infile.read(buffer, BUFFER_SIZE);
    SSL_write(ssl, buffer, infile.gcount());
  }
  infile.close();
  SSL_write(ssl, "EOF", 3);
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  cout << colorText(buffer, GREEN) << "\n";
}
void download_file(SSL *ssl) {
  char buffer[BUFFER_SIZE] = {0};
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "NO") == 0) {
    cout << colorText("Need log in\n", RED);
    return;
  }
  cout << colorText("------------------------\n", MAGENTA);
  cout << colorText(buffer, CYAN);
  cout << colorText("------------------------\n", MAGENTA);
  cout << colorText("Choose a file(index): ", YELLOW);
  string fileIndex;
  getline(cin, fileIndex);
  SSL_write(ssl, fileIndex.c_str(), fileIndex.size());
  memset(buffer, 0, BUFFER_SIZE);
  SSL_read(ssl, buffer, BUFFER_SIZE);
  if (strcmp(buffer, "NO") == 0) {
    cout << colorText("Invalid index\n", RED);
    return;
  }
  string download_file(buffer);
  ofstream outfile(download_file, ios::binary);
  if (!outfile) {
    SSL_write(ssl, "err", 3);
    return;
  }
  cout << colorText("[" + download_file + "]", CYAN)
       << colorText(" is Downloading......\n", YELLOW);
  SSL_write(ssl, "Start", 5);
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
  cout << colorText("File downloaded successfully\n", GREEN);
}
