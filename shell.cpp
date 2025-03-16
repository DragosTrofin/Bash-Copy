#include "shell.hpp"
#include <sstream>
#include <sys/wait.h>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <pty.h>
#include <linux/limits.h>
#include <thread>
#include <chrono>

// Utility function to split string while preserving quoted sections
std::vector<std::string> tokenize(const std::string& input) 
{
    std::vector<std::string> tokens;
    std::string token;
    bool in_quotes = false;
    char quote_char = 0;
    
    for (size_t i = 0; i < input.length(); ++i) 
    {
        char c = input[i];
        
        if ((c == '"' || c == '\'') && (i == 0 || input[i-1] != '\\')) 
        {
            if (!in_quotes) 
            {
                in_quotes = true;
                quote_char = c;
            } 
            else if (c == quote_char) 
            {
                in_quotes = false;
                quote_char = 0;
            } 
            else token += c;
        }
        else if (!in_quotes && (c == ' ' || c == '\t')) 
        {
            if (!token.empty()) 
            {
                tokens.push_back(token);
                token.clear();
            }
        } 
        else token += c;
    }
    
    if (!token.empty()) tokens.push_back(token);
    
    return tokens;
}

std::unique_ptr<Shell> createShell(bool interactive_mode, int socket, const std::string& username, const std::string& password) 
{
    if (interactive_mode) return std::make_unique<PTYShell>(socket, username, password);
    else return std::make_unique<CommandShell>(socket, username, password);
}

std::vector<Pipeline> CommandShell::parseInput(const std::string& input) 
{
    std::vector<Pipeline> pipelines;
    std::vector<std::string> pipeline_tokens;
    std::istringstream iss(input);
    std::string token;
    
    // Split into pipeline tokens first (commands separated by &&, ||)
    std::string curr_pipeline;
    bool in_quotes = false;
    char quote_char = 0;
    
    for (char c : input) 
    {
        if ((c == '"' || c == '\'') && (curr_pipeline.empty() || curr_pipeline.back() != '\\')) 
        {
            if (!in_quotes) 
            {
                in_quotes = true;
                quote_char = c;
            } 
            else if (c == quote_char) 
            {
                in_quotes = false;
                quote_char = 0;
            }
        }
        
        if (!in_quotes && c == '&' && !curr_pipeline.empty() && curr_pipeline.back() == '&') 
        {
            curr_pipeline.pop_back();
            if (!curr_pipeline.empty()) 
            {
                pipeline_tokens.push_back(curr_pipeline);
            }
            curr_pipeline.clear();
        } 
        else curr_pipeline += c;
    }
    
    if (!curr_pipeline.empty()) pipeline_tokens.push_back(curr_pipeline);

    // Process each pipeline
    for (const auto& pipeline_str : pipeline_tokens) 
    {
        Pipeline pipeline;
        std::vector<std::string> commands;
        std::string current_command;
        
        // Split commands by pipe
        for (size_t i = 0; i < pipeline_str.length(); ++i) 
        {
            if (pipeline_str[i] == '|' && (i == 0 || pipeline_str[i-1] != '\\')) 
            {
                if (!current_command.empty()) 
                {
                    commands.push_back(current_command);
                    current_command.clear();
                }
            } 
            else current_command += pipeline_str[i];
        }
        if (!current_command.empty()) commands.push_back(current_command);

        // Process each command in the pipeline
        for (const auto& cmd_str : commands) 
        {
            Command cmd;
            auto tokens = tokenize(cmd_str);
            
            for (size_t i = 0; i < tokens.size(); ++i) 
            {
                if (tokens[i] == "<") 
                {
                    if (i + 1 < tokens.size()) cmd.input_file = tokens[++i];
                } 
                else if (tokens[i] == ">") 
                {
                    if (i + 1 < tokens.size()) 
                    {
                        cmd.output_file = tokens[++i];
                        cmd.append_output = false;
                    }
                } 
                else if (tokens[i] == ">>") 
                {
                    if (i + 1 < tokens.size()) 
                    {
                        cmd.output_file = tokens[++i];
                        cmd.append_output = true;
                    }
                }
                else if (tokens[i] == "&" && i == tokens.size() - 1) cmd.run_in_background = true;
                else cmd.args.push_back(tokens[i]);
            }
            
            if (!cmd.args.empty()) pipeline.commands.push_back(cmd);
        }

        if (!pipeline.commands.empty()) pipelines.push_back(pipeline);
    }
    
    return pipelines;
}

void CommandShell::captureAndSendOutput(int pipe_fd) 
{
    char buffer[4096];
    int bytes_read;
    
    while ((bytes_read = read(pipe_fd, buffer, sizeof(buffer))) > 0) 
    {
        encrypt_decrypt(buffer, bytes_read, password, encrypt_counter);
        send(client_socket, buffer, bytes_read, 0);
    }
}

void CommandShell::executeCommand(const Command& cmd, int input_fd, int output_fd) 
{
     // Special handling for cd command
    if (!cmd.args.empty() && cmd.args[0] == "cd") {
        std::string new_path = cmd.args.size() > 1 ? cmd.args[1] : env_vars["HOME"];
        if (chdir(new_path.c_str()) == 0) {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                env_vars["PWD"] = cwd;
            } else {
                sendEncryptedMessage("Error getting current directory\n");
            }
        } else {
            sendEncryptedMessage("cd: No such file or directory\n");
        }
        return;
    }
    
    int stdout_pipe[2];
    if (pipe(stdout_pipe) == -1) 
    {
        sendEncryptedMessage("Error: Failed to create pipe\n");
        return;
    }

    pid_t pid = fork();
    if (pid == -1) 
    {
        sendEncryptedMessage("Error: Fork failed\n");
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        return;
    }
    
    if (pid == 0) 
    {
        close(stdout_pipe[0]);

        // Setup input redirection
        if (input_fd != STDIN_FILENO) 
        {
            dup2(input_fd, STDIN_FILENO);
            close(input_fd);
        } 
        else if (!cmd.input_file.empty()) 
        {
            int fd = open(cmd.input_file.c_str(), O_RDONLY);
            if (fd == -1) 
            {
                perror("open input file failed");
                exit(1);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        
        // Setup output redirection
        if (output_fd != STDOUT_FILENO) 
        {
            dup2(output_fd, STDOUT_FILENO);
            close(output_fd);
        }
        else if (!cmd.output_file.empty()) 
        {
            int flags = O_WRONLY | O_CREAT;
            flags |= cmd.append_output ? O_APPEND : O_TRUNC;
            int fd = open(cmd.output_file.c_str(), flags, 0644);
            if (fd == -1) 
            {
                perror("open output file failed");
                exit(1);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
        else dup2(stdout_pipe[1], STDOUT_FILENO);
        
        close(stdout_pipe[1]);

        std::vector<char*> args;
        for (const auto& arg : cmd.args) 
        {
            args.push_back(const_cast<char*>(arg.c_str()));
        }
        args.push_back(nullptr);
        
        for (const auto& [key, value] : env_vars) 
        {
            setenv(key.c_str(), value.c_str(), 1);
        }
        
        execvp(args[0], args.data());
        
        // If we get here, execvp failed
        std::string error = "Error: Command '" + cmd.args[0] + "' failed to execute\n";
        write(stdout_pipe[1], error.c_str(), error.length());
        exit(1);
    }
    
    // Parent process
    close(stdout_pipe[1]);
    
    if (!cmd.run_in_background)
    {
        captureAndSendOutput(stdout_pipe[0]);
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) 
        {
            std::string error = "Command exited with status " + std::to_string(WEXITSTATUS(status)) + "\n";
            sendEncryptedMessage(error);
        }
    }
    else close(stdout_pipe[0]);
}

void CommandShell::executePipeline(const Pipeline& pipeline) 
{
    int input_fd = STDIN_FILENO;
    
    for (size_t i = 0; i < pipeline.commands.size(); ++i) 
    {
        int pipe_fds[2] = {-1, -1};
        
        // Create pipe for all but the last command
        if (i < pipeline.commands.size() - 1) 
        {
            if (pipe(pipe_fds) == -1) 
            {
                perror("pipe failed");
                return;
            }
        }
        
        executeCommand(pipeline.commands[i], input_fd, pipe_fds[1] != -1 ? pipe_fds[1] : STDOUT_FILENO);
        
        // Close used file descriptors
        if (input_fd != STDIN_FILENO) close(input_fd);
        if (pipe_fds[1] != -1) close(pipe_fds[1]);
        
        // Set up input for next command
        input_fd = pipe_fds[0];
    }
}

void CommandShell::run() 
{
    char buffer[4096];
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    while (true)
    {
        sendPrompt();
        
        int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) break;
        
        encrypt_decrypt(buffer, bytes_read, password, decrypt_counter);
        buffer[bytes_read] = '\0';
        std::string input(buffer);
        if(input == "exit") break;
    
        if (input.empty() || input == "\n") continue;
        
        try 
        {
            auto pipelines = parseInput(input);
            for (const auto& pipeline : pipelines) 
            {
                executePipeline(pipeline);
            }
        }
        catch (const std::exception& e) 
        {
            std::string error = "Error parsing command: " + std::string(e.what()) + "\n";
            sendEncryptedMessage(error);
        }
    }
}

void PTYShell::run()
{
    int master_fd;
    pid_t pid = forkpty(&master_fd, nullptr, nullptr, nullptr);
    if (pid == -1)
    {
        perror("forkpty failed");
        return;
    }
    
    if (pid == 0) 
    {
        clearenv();
        
        setenv("TERM", "xterm-256color", 1);
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("HOME", "/home", 1);
        std::string ps1 = "\\[\\033[1;36m\\][MySSH]\\[\\033[1;33m\\]" + username + ":\\w\\[\\033[0m\\]$ ";
        setenv("PS1", ps1.c_str(), 1);
        setenv("LS_OPTIONS", "--color=auto", 1);
        setenv("CLICOLOR", "1", 1);
        
        execl("/bin/bash", "bash", "--norc", nullptr);
        perror("execl failed");
        exit(1);
    }

    char buffer[4096];
    fd_set readfds;

    while (true) 
    {
        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);
        FD_SET(master_fd, &readfds);

        if (select(std::max(client_socket, master_fd) + 1, &readfds, nullptr, nullptr, nullptr) < 0) break;

        if (FD_ISSET(client_socket, &readfds)) 
        {
            int bytes_read = read(client_socket, buffer, sizeof(buffer));
            if (bytes_read <= 0) break;

            encrypt_decrypt(buffer, bytes_read, password, decrypt_counter);
            write(master_fd, buffer, bytes_read);
        }

        if (FD_ISSET(master_fd, &readfds)) 
        {
            int bytes_read = read(master_fd, buffer, sizeof(buffer));
            if (bytes_read <= 0) break;

            encrypt_decrypt(buffer, bytes_read, password, encrypt_counter);
            send(client_socket, buffer, bytes_read, 0);
        }
    }

    close(master_fd);
}