# Socket Programming Project - Pharse1

## Server.cpp

- Usage: 

  - compile:  

    ```shell
    g++ server.cpp -lpthread -o server
    
    ```

  - execute:

    ```shell
    ./server
    ```

- **Idea of implementation** : I create a server socket on the localhost with 8080 port, and create threads to handle the commands from the clients. Though the multithread server is not required in pharse1, I think I can reduce the future modification if I implement it from the start. My server provide 5 commands now. **1** is **sign in**, **2**  is **login**, **3** is **logout**, **5** is **send message** and **4** is **exit**. The communication is achieved by **send()** and **read()** functions.

- **handle_sign_in()**: The server would receive username and password from the client, and check if  the username is used. If credential is legal, save it in **user.txt**.
- **handle_login()**: The server would track **client_info** for each client connection(by client fd). For this function, the server first receive username and password from the client, and if the credential is valid, change to the **client_info** to login status.
- **handle_logout()**: Opposite to login, if this command is received, the server would clear **client_info**(logout status)
- **handle_send_message()**: This function is a simple demonstration for showing that the client can send messages to the server and the server can also response the the client. Additionally, this command is only available when the client is logged in.
- **worker_thread()**: Each time the server accepts a new client socket, a client socket fd is pushed in the **task_queue()**. The worker threads would keep popping the client socket fds from the queue and serve them. After finish a command, the worker thread would check the client is still connected(not exit), and pop the client socket fd back to the queue.

# Client.cpp
- Usage: 

  - compile:  

    ```shell
    g++ client.cpp -lpthread -o client
    
    ```

  - execute:

    ```shell
    ./client
    ```

- **Idea of implementation**: All the command is actually explained in the server section. The client would connect to the server, send commands and receive the correspond response. The only special thing I have to mention is that the client would keep printing the "status" + "prompt" which looks like below:

  - **Not logged in**

    ```
    [Not logged in] Enter command (1: Sign In, ...)
    ```

  - **Log in as b11902149** 

    ```
    [b11902149] Enter command (1: Sign In, ...)
    ```

## Environment

- OS: `Arch Linux x86_64`
- Compiler:` g++ 14.2.1`
