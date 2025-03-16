#include <iostream>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <termios.h>
#include <fcntl.h>
#include <string.h>

#define PORT 8090
#define BUFFER_SIZE 4096

void encrypt_decrypt(char* data, size_t len, const std::string& key, unsigned long long& counter)
{
    for (size_t i = 0; i < len; i++) 
    {
        data[i] = data[i] ^ key[(counter++) % key.length()];
    }
}

int main(int argc, char* argv[]) 
{
    bool interactive_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--interactive-mode") {
            interactive_mode = true;
            break;
        }
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Socket creation error\n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) 
    {
        perror("Invalid address\n");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("Connection Failed\n");
        exit(EXIT_FAILURE);
    }

    std::string username, password;
    unsigned long long encrypt_counter = 0;
    unsigned long long decrypt_counter = 0;
    
    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) 
    {
        perror("Connection closed by server");
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::cout << buffer << std::flush;
    
    std::getline(std::cin, username);
    send(sock, username.c_str(), username.length(), 0);
    
    bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read <= 0)
    {
        perror("Connection closed by server");
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::cout << buffer << std::flush;
    
    std::getline(std::cin, password);
    send(sock, password.c_str(), password.length(), 0);
    
    bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) 
    {
        perror("Authentication failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    if (strncmp(buffer, "Authentication failed\n", 22) == 0)
    {
        std::cout << "Authentication failed\n";
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct termios orig_termios;
    tcgetattr(STDIN_FILENO, &orig_termios);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);
    raw.c_iflag &= ~(IXON | ICRNL);
    if (interactive_mode) raw.c_oflag &= ~(OPOST); // Raw output for interactive mode
    else raw.c_oflag |= (ONLCR | OPOST);  // Enable output processing and NL->CRNL for non-interactive mode
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);

    fd_set readfds;
    char input_char;

    while (true) 
    {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        select(sock + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(STDIN_FILENO, &readfds)) 
        {
            if (interactive_mode)
            {
                if (read(STDIN_FILENO, &input_char, 1) > 0)
                {
                    encrypt_decrypt(&input_char, 1, password, encrypt_counter);
                    send(sock, &input_char, 1, 0);
                }
            }
            else 
            {
                std::string command;
                size_t cursor_pos = 0; 
                char c;
                while (read(STDIN_FILENO, &c, 1) > 0) 
                {
                    if (c == '\r') break;

                    if (c == 127) { // Backspace
                        if (cursor_pos > 0) {
                            command.erase(cursor_pos - 1, 1);
                            cursor_pos--;   
                            write(STDOUT_FILENO, "\b \b", 3);
                        }
                    }
                    else if (c == '\x1b') { // Escape sequence start
                        char seq[2];
                        if (read(STDIN_FILENO, seq, 2) == 2) {  // Read next 2 bytes
                            if (seq[0] == '[') {
                                if (seq[1] == 'D') {  // Left arrow
                                    if (cursor_pos > 0) {
                                        cursor_pos--;
                                        write(STDOUT_FILENO, "\b", 1);
                                    }
                                }
                                else if (seq[1] == 'C') {  // Right arrow
                                    if (cursor_pos < command.length()) {
                                        cursor_pos++;
                                        write(STDOUT_FILENO, "\x1b[C", 3);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        command.insert(cursor_pos, 1, c);
                        cursor_pos++;   
                        write(STDOUT_FILENO, &c, 1);
                        if (cursor_pos < command.length()) {
                            // Write rest of string
                            write(STDOUT_FILENO, command.c_str() + cursor_pos, command.length() - cursor_pos);
                            // Move cursor back to insertion point
                            for (size_t i = 0; i < command.length() - cursor_pos; i++) {
                                write(STDOUT_FILENO, "\b", 1);
                            }
                        }
                    }
                }
                c = '\n';
                write(STDOUT_FILENO, &c, 1);

                // Encrypt and send the whole command at once
                char* encrypted_cmd = new char[command.length()];
                memcpy(encrypted_cmd, command.c_str(), command.length());
                encrypt_decrypt(encrypted_cmd, command.length(), password, encrypt_counter);
                send(sock, encrypted_cmd, command.length(), 0);
                delete[] encrypted_cmd;
            }
        }

        if (FD_ISSET(sock, &readfds)) 
        {
            int bytes_read = read(sock, buffer, BUFFER_SIZE);
            if (bytes_read <= 0) break;

            encrypt_decrypt(buffer, bytes_read, password, decrypt_counter);
            write(STDOUT_FILENO, buffer, bytes_read);
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
    close(sock);
    return 0;
}