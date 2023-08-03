#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 9000
#define BUFFER_SIZE 1024
#define FILE_NAME "/var/tmp/aesdsocketdata"


static volatile sig_atomic_t running = true;
static void sig_handler (int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");
    running = false;
}

void m_exit(const char* msg) {
        perror(msg);
        syslog(LOG_ERR, msg);
        exit(-1);
}


int main(int argc, char *argv[]) {
    // Set up logger
    openlog(NULL, 0, LOG_USER);

    // Register SIGINT handler
    struct sigaction sigint;
    memset(&sigint, 0, sizeof(struct sigaction));
    sigint.sa_handler = sig_handler;
    sigaction(SIGINT, &sigint, NULL);
    sigaction(SIGTERM, &sigint, NULL);


    int fd, cli_fd, s_fd;
    int ret, buffer_ret;
    struct sockaddr_in serv_addr, cli_addr;
    char buffer[BUFFER_SIZE];
    int cli_len = sizeof(cli_addr);


    // Create sever socket
    s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_fd < 0)
        m_exit("Failed to create socket");

    // Set server socket options (reuse addr)
    int opt = 1;
    ret = setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (ret < 0)
        m_exit("Failed to set socket options");
    
    // Bind serverr socket
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY; // Figure this out

    ret = bind(s_fd, (struct sockaddr*)& serv_addr, sizeof(struct sockaddr_in));
    if (ret < 0)
        m_exit("Failed to bind socket");

    // Kick off as daemon if specified
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        if(daemon(0,1) < 0)
            m_exit("Failed to create daemon");
    }

    
    // main loop
    while (running) {

        // Listen for connection
        listen(s_fd, 3);

        // Accept incoming connection
        cli_fd = accept(s_fd, (struct sockaddr*)& cli_addr, &cli_len);

        // Likely that we will be blocking on accept when signal occurs
        if (!running)
            break;

        if (cli_fd < 0)
            m_exit("Failed to accept connection");

        syslog(LOG_INFO, "Accepted connection from %u", cli_addr.sin_addr.s_addr);

        
        // Open file for appending
        fd = open(FILE_NAME, O_RDWR | O_CREAT | O_APPEND, 0664);
        if (fd < 0)
            m_exit("Failed to open file");

        // Read until we find a newline
        bool reading = true;
        while (running && reading) {
            // Clear the buffer for reading
            memset(buffer, 0, BUFFER_SIZE);
            buffer_ret = recv(cli_fd, &buffer, BUFFER_SIZE, 0);
            if (buffer_ret < 0)
                m_exit("Failed reading message from socket");
            
            // Write what we received to the file
            if (write(fd, buffer, buffer_ret) < 0)
                m_exit("Failed writing message to file");

            // Break if we've hit a newline (end of packet)
            if (buffer[buffer_ret - 1] == '\n')
                reading = false;
        }

        if (!running)
            break;

        // Reset fd to beginning of file
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
            m_exit("Failed to set fd to beginning of file");

        // Return the contents of the file
        memset(buffer, 0, BUFFER_SIZE);
        while (running && (ret = read(fd, buffer, BUFFER_SIZE)) != 0) {
            if (ret == -1)
                m_exit("Failed reading file to send back to client");

            send(cli_fd, buffer, ret, 0);
            memset(buffer, 0, BUFFER_SIZE);
            syslog(LOG_INFO, "sent some stuff");
        }

        if (!running)
            break;

        // Close the file and client socket
        if (close(fd) < 0)
            m_exit("Faild to closing file after reading");

        if (close(cli_fd) < 0)
            m_exit("Failed to close client socket");

        syslog(LOG_INFO, "Closed connection from %u", cli_addr.sin_addr.s_addr);
    }

    remove(FILE_NAME);
    closelog();
    close(fd);
    close(cli_fd);
    shutdown(s_fd, SHUT_RDWR);

    return 0;
}