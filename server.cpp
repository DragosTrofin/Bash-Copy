#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <map>
#include "shell.hpp"

#define PORT 8090
#define BUFFER_SIZE 4096

void encrypt_decrypt(char* data, size_t len, const std::string& key, unsigned long long& counter) 
{
    for (size_t i = 0; i < len; i++) 
    {
        data[i] = data[i] ^ key[(counter++) % key.length()];
    }
}


struct User 
{
    std::string username;
    std::string password;
};

class JsonParser {
private:
    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\n\r\"");
        size_t last = str.find_last_not_of(" \t\n\r\"");
        if (first == std::string::npos || last == std::string::npos) return "";
        return str.substr(first, last - first + 1);
    }

    static void parseUserObject(const std::string& line, std::vector<User>& users) {
        size_t usernamePos = line.find("\"username\":");
        size_t passwordPos = line.find("\"password\":");
        
        if (usernamePos == std::string::npos || passwordPos == std::string::npos) return;

        // Find the value after "username":
        size_t usernameStart = line.find(':', usernamePos) + 1;
        size_t usernameEnd = line.find(',', usernameStart);
        
        // Find the value after "password":
        size_t passwordStart = line.find(':', passwordPos) + 1;
        size_t passwordEnd = line.find('}', passwordStart);

        if (usernameStart == std::string::npos || passwordStart == std::string::npos) return;

        std::string username = trim(line.substr(usernameStart, usernameEnd - usernameStart));
        std::string password = trim(line.substr(passwordStart, passwordEnd - passwordStart));

        User user;
        user.username = username;
        user.password = password;
        users.push_back(user);
    }

public:
    static std::vector<User> parseUsersFile(const std::string& filename) {
        std::vector<User> users;
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return users;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Skip empty lines and standalone brackets
            if (line.find_first_not_of(" \t\n\r{}[]") == std::string::npos) continue;
            
            // If line contains both username and password
            if (line.find('{') != std::string::npos && line.find('}') != std::string::npos) {
                parseUserObject(line, users);
            }
        }

        return users;
    }
};

bool authenticateUser(const std::vector<User>& users, const std::string& username, const std::string& password) 
{
    for (const auto& user : users) 
    {
        if (user.username == username && user.password == password) return true;
    }
    return false;
}



bool authenticate(int client_socket, std::string& password, std::string& username) 
{
    char buffer[BUFFER_SIZE];

    std::string prompt = "Username: ";
    send(client_socket, prompt.c_str(), prompt.length(), 0);
    
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) return false;
    username = std::string(buffer, bytes_read);

    prompt = "Password: ";
    send(client_socket, prompt.c_str(), prompt.length(), 0);
    
    bytes_read = read(client_socket, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) return false;
    password = std::string(buffer, bytes_read);
    
    std::vector<User> users = JsonParser::parseUsersFile("users.json");

    if (authenticateUser(users, username, password))
    {
        std::string success_msg = "Authentication success\n";
        send(client_socket, success_msg.c_str(), success_msg.length(), 0);
        return true;
    } 
    else 
    {
        std::string error_msg = "Authentication failed\n";
        send(client_socket, error_msg.c_str(), error_msg.length(), 0);
        return false;
    }
}

void handle_client(int client_socket, bool interactive_mode) 
{
    std::string password, username;
    if(!authenticate(client_socket, password, username)) 
    {
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
        return;
    }

    if (interactive_mode) 
    {
        auto shell = createShell(true, client_socket, username, password);
        shell->run();
    }
    else
    {
        auto shell = createShell(false, client_socket, username, password);
        shell->run();
    }

    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
}

int main(int argc, char* argv[]) 
{
    bool interactive_mode = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        if (std::string(argv[i]) == "--interactive-mode") 
        {
            interactive_mode = true;
            break;
        }
    }

    int server_fd;
    struct sockaddr_in address;
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) 
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) 
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is listening on port " << PORT << std::endl;
    if (interactive_mode) std::cout << "Running in interactive mode" << std::endl;
    else std::cout << "Running in non-interactive mode" << std::endl;

    while (true) 
    {
        int new_socket = accept(server_fd, NULL, NULL);
        if (new_socket < 0)
        {
            perror("Accept failed");
            continue;
        }

        std::thread(handle_client, new_socket, interactive_mode).detach();
    }

    close(server_fd);
    return 0;
}