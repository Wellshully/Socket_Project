#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <cstring>
#include <deque>
#include <iostream>
#include <netinet/in.h>
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
  cout << "-----------------------------------------------------------------\n";
  cout << "[Me]: ";
  cout.flush();
}

void chatRoom(int chatsock) {
  deque<string> chatRecord;
  messageHelper(chatRecord, "");
  bool running = true;
  auto recvThreadFunc = [&](int s) {
    char buffer[BUFFER_SIZE];
    while (running) {
      memset(buffer, 0, BUFFER_SIZE);
      int bytes_read = read(chatsock, buffer, BUFFER_SIZE);
      if (bytes_read <= 0) {
        cout << "Peer disconneted\n";
        running = false;
        break;
      }
      string msg(buffer);
      if (msg == "exit_chatroom") {
        cout << "Peer left the chatroom, press enter to exit\n";
        running = false;
        send(chatsock, msg.c_str(), msg.size(), 0);
        break;
      }
      messageHelper(chatRecord, "[Peer]: " + msg);
    }
  };
  thread recvThread(recvThreadFunc, chatsock);
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
      send(chatsock, userMsg.c_str(), userMsg.size(), 0);
      running = false;
      break;
    } else {
      messageHelper(chatRecord, "[Me]: " + userMsg);
      send(chatsock, userMsg.c_str(), userMsg.size(), 0);
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
  int listenSock = *(int *)arg;
  delete (int *)arg;
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
    cout << "Incoming chat initation! Accept? (y/n): ";
    string answer;
    cin >> answer;
    if (answer == "y" || answer == "Y") {
      send(localincomingSockfd, "OK", 2, 0);
      cout << "Entering chatroom...\n";
      chatRoom(localincomingSockfd);
      close(localincomingSockfd);
      cout << "Exited chatroom\n";
    } else {
      send(localincomingSockfd, "NO", 2, 0);
      close(localincomingSockfd);
    }
    pthread_mutex_lock(&inviteMutex);
    hasInvitation = false;
    incomingSockfd = -1;
    pthread_mutex_unlock(&inviteMutex);
  }
}
int main() {
  system("clear");
  string username, password;
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
  read(sock, buffer, BUFFER_SIZE);
  string port_str = to_string(assignedPort);
  send(sock, port_str.c_str(), BUFFER_SIZE, 0);
  read(sock, buffer, BUFFER_SIZE);

  while (true) {
    // check invitation
    check_invitation();
    // talk to server
    cout << "------------------------------------------------------------------"
            "---------------\n"
         << status
         << " Enter command (1: Sign In, 2: Login, 3: Logout, 4: Exit, 5: "
            "Chatroom): ";
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
      while (username.empty()) {
        cout << "Username cannot be empty\nEnter username: ";
        getline(cin, username);
      }

      send(sock, username.c_str(), username.size(), 0); // Send username

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive password prompt
      cout << buffer;
      getline(cin, password);
      while (password.empty()) {
        cout << "Password cannot be empty\nEnter password: ";
        getline(cin, password);
      }
      send(sock, password.c_str(), password.size(), 0); // Send password

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive sign-in response
      cout << buffer << endl;

    } else if (command == "2") {
      // Login
      if (status != "[Not logged in]") {
        cout << "You are logged in\n";
        continue;
      }
      send(sock, command.c_str(), command.size(), 0);

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive username prompt
      cout << buffer;
      getline(cin, username);
      while (username.empty()) {
        cout << "Username cannot be empty\nEnter username: ";
        getline(cin, username);
      }
      send(sock, username.c_str(), username.size(), 0); // Send username

      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive password prompt
      cout << buffer;
      getline(cin, password);
      while (password.empty()) {
        cout << "Password cannot be empty\nEnter password: ";
        getline(cin, password);
      }
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
      if (status == "[Not logged in]") {
        cout << "You have to log in first\n";
        continue;
      }
      check_invitation();
      send(sock, command.c_str(), command.size(), 0);
      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Receive logout response
      cout << buffer << endl;

      // Reset status to "Not logged in" on logout
      status = "[Not logged in]";

    } else if (command == "4") {
      // Exit
      check_invitation();
      send(sock, command.c_str(), command.size(), 0);
      cout << "Exiting...\n";
      break;

    } else if (command == "5") {
      check_invitation();
      send(sock, command.c_str(), command.size(), 0);
      memset(buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE); // Check if user is logged in

      if (strcmp(buffer, "NO") == 0) {
        cout << "Need log in\n";
        continue;
      }
      cout << buffer; // online user
      string peer;
      cout << "Chat with: ";
      getline(cin, peer);
      if (peer == username) {
        cout << "Cannot chat with yourself\n";
        continue;
      }
      string peer_ = peer + "\n";
      send(sock, peer_.c_str(), peer_.size(), 0);
      memset(&buffer, 0, BUFFER_SIZE);
      read(sock, buffer, BUFFER_SIZE);
      if (strcmp(buffer, "OK") == 0) {
        send(sock, "IP", 2, 0);
        memset(&buffer, 0, BUFFER_SIZE);
        read(sock, buffer, BUFFER_SIZE);
        string chatIP = buffer;
        send(sock, "PORT", 4, 0);
        memset(&buffer, 0, BUFFER_SIZE);
        read(sock, buffer, BUFFER_SIZE);
        string chatPort = buffer;
        int chatsock = 0;
        struct sockaddr_in char_addr;
        if ((chatsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
          cout << "Chatrooom socket creation error\n";
          continue;
        }
        char_addr.sin_family = AF_INET;
        char_addr.sin_port = htons(stoi(chatPort));
        if (inet_pton(AF_INET, chatIP.c_str(), &char_addr.sin_addr) <= 0) {
          cout << "Invalid chatroom address\n";
          continue;
        }
        if (connect(chatsock, (struct sockaddr *)&char_addr,
                    sizeof(char_addr)) < 0) {
          cout << "Chatrooom connection failed\n";
          continue;
        }
        memset(&buffer, 0, BUFFER_SIZE);
        read(chatsock, buffer, BUFFER_SIZE);
        if (strcmp(buffer, "OK") == 0) {
          cout << "Entering the chatroom with [" << peer << "]\n";
          chatRoom(chatsock);
        } else {
          cout << "The invitation is rejected\n";
        }
      } else {
        cout << buffer << "\n";
      }
    }
  }

  close(sock);
  return 0;
}
