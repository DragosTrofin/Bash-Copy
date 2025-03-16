#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <sys/socket.h>
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>

void encrypt_decrypt(char* data, size_t len, const std::string& key, unsigned long long& counter);

class Shell
{
protected:
    int client_socket;
    std::string username;
    std::string password;
    std::unordered_map<std::string, std::string> env_vars;
    unsigned long long encrypt_counter;
    unsigned long long decrypt_counter;

public:
    Shell(int socket, const std::string& user, const std::string& pass) 
        : client_socket(socket), username(user), password(pass), encrypt_counter(0), decrypt_counter(0)
    {
        setupEnvironment();
    }
    
    virtual ~Shell() = default;
    virtual void run() = 0;

protected:
    virtual void setupEnvironment() 
    {
        env_vars["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        env_vars["HOME"] = "/home";

        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != nullptr) env_vars["PWD"] = cwd;
        else env_vars["PWD"] = "/"; // Fallback if getcwd fails
    }

    virtual void sendPrompt() 
    {
        std::string cwd = env_vars["PWD"];
        std::string prompt = "\033[1;36m[MySSH]\033[1;33m" + username + ":" + cwd + "\033[0m$ ";
        char* encrypted_prompt = new char[prompt.length()];
        memcpy(encrypted_prompt, prompt.c_str(), prompt.length());
        encrypt_decrypt(encrypted_prompt, prompt.length(), password, encrypt_counter);
        send(client_socket, encrypted_prompt, prompt.length(), 0);
        delete[] encrypted_prompt;
    }

    void sendEncryptedMessage(const std::string& message) 
    {
        char* encrypted_msg = new char[message.length()];
        memcpy(encrypted_msg, message.c_str(), message.length());
        encrypt_decrypt(encrypted_msg, message.length(), password, encrypt_counter);
        send(client_socket, encrypted_msg, message.length(), 0);
        delete[] encrypted_msg;
    }
};

class PTYShell : public Shell 
{
private:
    int master_fd;

public:
    PTYShell(int socket, const std::string& user, const std::string& pass) 
        : Shell(socket, user, pass) {}
    void run() override;
};

struct Command 
{
    std::vector<std::string> args;
    std::string input_file;
    std::string output_file;
    std::string error_file;
    bool append_output = false;
    bool run_in_background = false;
};

struct Pipeline 
{
    std::vector<Command> commands;
    bool run_in_background = false;
};

class CommandShell : public Shell 
{
private:
    std::vector<Pipeline> parseInput(const std::string& input);
    void executePipeline(const Pipeline& pipeline);
    void executeCommand(const Command& cmd, int input_fd, int output_fd);
    void captureAndSendOutput(int pipe_fd);

public:
    CommandShell(int socket, const std::string& user, const std::string& pass) 
        : Shell(socket, user, pass) {}
    void run() override;
};

std::unique_ptr<Shell> createShell(bool interactive_mode, int socket, const std::string &username, const std::string &password);