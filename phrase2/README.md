# Socket Programming Project - Pharse2

- **Ip address:** Note that the client assumes the server is listening on the 127.0.0.1(localhost) for a easier testing. For the real-world usage, I may change it to asking for a certain Ip.

## Multithread server

- **Idea:** This functionality is actually implemented in pharse1, and I'm using a thread pool to serve each client connection. In the server code, the function `worker_thread()` keep popping the client socket fds from the queue and serve them. After finish a command, the worker thread would check the client is still connected(not exit), and pop the client socket fd back to the queue.

## Chatroom(Direct Mode)

- **server:**
  - **handle_chatroom():** The server would first offer the online-user list to the client, and then the client would tell the server who he/she want to chat with. Next, the server would tell the client(the chat initiator) the IP and Port of the other(the invited client).
- **client:**
  - **initiate_chat():** The client would first ask the server that he/she want to initiate a chatroom, and then receive the online-user list from the server. Next, the initiator would select one client who he/she wants to chat with and gets the IP and Port from the server. In the end, the initiator would try to used the address to build a connection with the invited client.
  - **listenThread():** The client process would create a listening thread to wait for a invitation. If there is a incomming socket, the listening thread would change the "hasInvitation" variable to be true. Also, before processing each command, `check_invitation()` would be called.
  - **check_invitaiton():** If `hasInvitation` is true, the client would ask whether to accept the chatroom invitation.
  - **chatRoom():** If the invited client accepts the invitation from the initiator, both of them would enter this function. This function has a receive thread in side, and it would handle the message sent from the peer.
  - **messageHelper():** It has a deque that stores the chat record. If the record length is exceed the deque length, the oldest message would be poped. This way the message is printed in a fixed length.

## Message Encryption with OpenSSL

- **server-client interaction:**

  - TLS Setup: The server initializes OpenSSL by calling `init_openssl()` and creates an SSL context using `create_server_context()`. This context is configured with a server certificate (server.crt) and private key (server.key) for authentication and encryption.

  - TLS Connection: When a client connects, an SSL object is created (SSL_new) and associated with the socket file descriptor (SSL_set_fd). The server then accepts the SSL/TLS handshake (SSL_accept) to establish a secure encrypted channel.

  - Encrypted Communication: All communication between the client and server is encrypted. Data sent or received uses SSL functions like SSL_write and SSL_read. This ensures that sensitive data (e.g., usernames, passwords, and file contents) is protected from eavesdropping or tampering.

  - Protocol: The server enforces a minimum TLS version (TLS 1.2) for enhanced security (SSL_CTX_set_min_proto_version).

- **client-client interaction:** Actually, the listening client just serves as a little server, which means that it will do the procedure like what the server do. After the chatroom initiator know the address of this listening client, they would build a TLS connection. Note that the listening client also need a certificate to authenticate itself.

## Transfer files

- **Server Upload:** In the function `handle_file_upload()`, the server prompts the client for the filename, and the client sends the filename, which the server receives and processes.Next, the server creates a file with the received name in the `SHARED_FILES/` directory,and then sends a "Start" signal to indicate readiness for the file transfer. After that, the server reads file chunks sent by the client over the SSL/TLS connection and writes them to the file on the server side. In the end, the server receives "EOF" (End of File) from the client, it closes the file and ends the transfer.

- **Server Download:** The server scans the `SHARED_FILES/ `directory to list all available files. It sends the list of files to the client, with each file assigned an index, and then it opens the requested file in binary mode and sent chunks to the client over the SSL/TLS connection.

- **Client:** In fact, the upload function is just like what the server do in the download function and so does the download function. Because the upload and download are symmetry, the difference is just the role of sender and receiver. However, the significant difference of the client is that the upload function selects the file with the file manager(gui) so that the user can upload the files more easily.

## Future Work

- **Video streaming**: I spent a bunch of time to get this feature work. I tried to send the video frame by frame and play them by the `ffmpeg` library. However, I never figure out how decode the format of the video(and also the usage of the library), and thus I end up failing to play a video with my code.
- **Blocked Invitation:** Since the client is always waiting for user to enter a command, the `check_invitation()` function cannot activated once the listening thread receives the invitation. Though it's not implement here, I think a better way is to interrupt(signal) the current input and enter the `check_invitaion()` immediately
- **GUI interface**: After I finish all the functionalities above, I find that it's too hard for me to migrate them to a gui version. I tried to do it with `qt` or just use the browser as the front-end, but I'm so unfamiliar with them to get them work. However, I still tried to make the terminal interface as cool as possible, as you can see my chatroom layout is beautiful (and my desktop environment) **:)**

## Server.cpp

- Usage:

  - compile:

    ```shell
    g++ server_ssl.cpp -lpthread -o server -lssl -lcrypto
    ```

  - execute:

    ```shell
    ./server
    ```

## Client.cpp

- Usage:

  - compile:

    ```shell
    g++ client_ssl.cpp -lpthread -o client -lssl -lcrypto
    ```

  - execute:

    ```shell
    ./client
    ```

## Environment

- OS: `Arch Linux x86_64`
- Compiler:` g++ 14.2.1`
