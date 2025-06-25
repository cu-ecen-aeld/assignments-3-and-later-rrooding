#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <time.h>

#define PORT "9000"
#define BACKLOG 10
#define READ_BUFFER_SIZE 4096
#define OUTPUT_FILE "/var/tmp/aesdsocketdata"

volatile sig_atomic_t shutdown_flag = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

struct connection_data {
    int client_fd;
    char client_ip[INET_ADDRSTRLEN];
};

struct thread_node {
    pthread_t thread_id;
    struct thread_node *next;
};

void signal_handler(int signum) {
    shutdown_flag = 1;
}

void setup_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction SIGINT failed");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction SIGTERM failed");
        exit(EXIT_FAILURE);
    }
}

int daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return -1;
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        perror("setsid failed");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("second fork failed");
        return -1;
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (chdir("/") < 0) {
        perror("chdir failed");
        return -1;
    }

    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        perror("open /dev/null failed");
        return -1;
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) {
        close(fd);
    }

    umask (0);
    return 0;
}

int setup_server(int daemon_mode) {
    int server_fd;
    
    struct addrinfo hints;
    struct addrinfo *servinfo;
    
    // b. Opens a stream socket bound to port 9000, failing and returning -1 if any of the socket connection steps fail.
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, PORT, &hints, &servinfo) != 0) {
        perror("getaddrinfo failed");
        exit(EXIT_FAILURE);
    }

    if (bind(server_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (daemon_mode) {
        if (daemonize() < 0) {
            perror("daemonize failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
    }

    // c. Listens for and accepts a connection
    if (listen(server_fd, BACKLOG) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Free server info
    freeaddrinfo(servinfo);

    return server_fd;
}

int send_file_contents(int client_fd) {
    char buffer[READ_BUFFER_SIZE];
    FILE *file = fopen(OUTPUT_FILE, "r");
    if (!file) {
        perror("fopen for reading failed");
        return -1;
    }

    while(1) {
        size_t bytes_read = fread(buffer, 1, READ_BUFFER_SIZE, file);
        if (bytes_read == 0) {
            if (feof(file)) {
                break;
            }
            perror("fread failed");
            fclose(file);
            return -1;
        }

        size_t bytes_sent = 0;
        while(bytes_sent < bytes_read) {
            ssize_t sent = send(client_fd, buffer + bytes_sent, bytes_read - bytes_sent, 0);
            if (sent < 0) {
                if (errno == EINTR) continue;
                perror("send failed");
                fclose(file);
                return -1;
            }
            bytes_sent += sent;
        }
    }

    if (fclose(file) != 0) {
        perror("fclose failed");
        return -1;
    }

    return 0;
}

int write_buffer_to_file(const char *buffer, size_t buffer_size) {
    pthread_mutex_lock(&file_mutex);

    FILE *file = fopen(OUTPUT_FILE, "a+");
    if (!file) {
        perror("fopen failed");
        pthread_mutex_unlock(&file_mutex);

        return -1;
    }

    if (fwrite(buffer, 1, buffer_size, file) != buffer_size) {
        perror("fwrite failed");
        fclose(file);
        pthread_mutex_unlock(&file_mutex);

        return -1;
    }

    if (fclose(file) != 0) {
        perror("fclose failed");
        pthread_mutex_unlock(&file_mutex);

        return -1;
    }

    pthread_mutex_unlock(&file_mutex);
    return 0;
}

void *write_time_marker(void *arg) {
    char timestamp[128];
    struct timespec sleep_time = { .tv_sec = 10, .tv_nsec = 0 };

    while (!shutdown_flag) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S\n", tm_info);
        if (write_buffer_to_file(timestamp, strlen(timestamp)) != 0) {
            syslog(LOG_ERR, "failed to write timestmap to file");
        }
        while(nanosleep(&sleep_time, &sleep_time) < 0 && errno == EINTR && !shutdown_flag);
    }

    return NULL;
}

void *handle_connection(void *arg) {
    struct connection_data *data = (struct connection_data *)arg;
    int client_fd = data->client_fd;
    char *client_ip = data->client_ip;
    
    printf("Accepted connection from %s\n", client_ip);
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    size_t buffer_size = 0;
    size_t buffer_capacity = 1024;
    char *buffer = malloc(buffer_capacity);
    if (!buffer) {
        perror("malloc failed");
        syslog(LOG_INFO, "Closed connection from %s", client_ip);
        close(client_fd);
        free(data);
        return NULL;
    }
        
    buffer[0] = '\0';

    // receive data until newline
    while (1) {
        if (buffer_size + 1 >= buffer_capacity) {
            buffer_capacity *= 2;
            char *new_buffer = realloc(buffer, buffer_capacity);
            if (!new_buffer) {
                fprintf(stderr, "realloc failed: possible packet too large\n");
                syslog(LOG_INFO, "Closed connection from %s", client_ip);
                free(buffer);
                close(client_fd);
                free(data);
                return NULL;
            }

            buffer = new_buffer;
        }

        ssize_t bytes_received = recv(client_fd, buffer + buffer_size, 1, 0);
        if (bytes_received < 0) {
            if (errno == EINTR) continue;
            perror("recv failed");
            syslog(LOG_INFO, "Closed connection from %s", client_ip);
            free(buffer);
            close(client_fd);
            free(data);
            return NULL;
        }
        if (bytes_received == 0) {
            if (buffer_size > 0) {
                buffer[buffer_size] = '\0';
            }
            free(buffer);
            close(client_fd);
            free(data);
            return NULL;
        }

        buffer_size += bytes_received;
        buffer[buffer_size] = '\0';

        if (buffer[buffer_size - 1] == '\n') {
            if (write_buffer_to_file(buffer, buffer_size) == -1) {
                fprintf(stderr, "failed to write file contents\n");
                syslog(LOG_INFO, "Closed connection from %s", client_ip);
                free(buffer);
                close(client_fd);
                free(data);
                return NULL;
            }

            // send back
            if (send_file_contents(client_fd) == -1) {
                fprintf(stderr, "failed to send file contents\n");
                syslog(LOG_INFO, "Closed connection from %s", client_ip);
                free(buffer);
                close(client_fd);
                free(data);
                return NULL;
            }

            buffer_size = 0;
            buffer[0] = '\0';
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    int daemon_mode = 0;
    int opt;
    struct thread_node *thread_list = NULL;
    pthread_t timestamp_thread;


    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);
    setup_signal_handlers();

    sigset_t sigmask, oldmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);

    int server_fd = setup_server(daemon_mode);

    if (pthread_create(&timestamp_thread, NULL, write_time_marker, NULL) != 0) {
        perror("pthread_create for timestamp thread failed");
        closelog();
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // c. accept connections
    while (!shutdown_flag) {
        if (sigprocmask(SIG_UNBLOCK, &sigmask, &oldmask) < 0) {
            perror("sigprocmask unblock failed");
            break;
        }

        struct sockaddr_storage client_addr;
        socklen_t addr_size = sizeof client_addr;

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);

        if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
            perror("sigprocmask restore failed");
            break;
        }

        if (client_fd < 0) {
            if (errno == EINTR && shutdown_flag) {
                break; // Interrupted by signal, proceed to shutdown
            }

            perror("accept failed");
            continue;
        }

        // d. Logs message to the syslog "Accepted connection from xxx" where XXXX is the IP address of the connected client. 
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(((struct sockaddr_in *)&client_addr)->sin_addr), client_ip, INET_ADDRSTRLEN);
  
        struct connection_data *data = malloc(sizeof(struct connection_data));
        if (!data) {
            perror("malloc failed");
            close(client_fd);
            continue;
        }
        data->client_fd = client_fd;
        strcpy(data->client_ip, client_ip);

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_connection, data) != 0) {
            perror("pthread_create failed");
            free(data);
            close(client_fd);
            continue;
        }

        pthread_mutex_lock(&thread_list_mutex);
        struct thread_node *new_node = malloc(sizeof(struct thread_node));
        if (new_node) {
            new_node->thread_id = thread_id;
            new_node->next = thread_list;
            thread_list = new_node;
        } else {
            fprintf(stderr, "malloc failed for thread_node\n");
        }
        pthread_mutex_unlock(&thread_list_mutex);
    }

    // Cleanup
    if (shutdown_flag) {
        syslog(LOG_INFO, "Caught signal, exiting");
    }

    pthread_mutex_lock(&thread_list_mutex);
    struct thread_node *current = thread_list;
    while (current) {
        pthread_join(current->thread_id, NULL);
        struct thread_node *temp = current;
        current = current->next;
        free(temp);
    }
    pthread_mutex_unlock(&thread_list_mutex);

    pthread_join(timestamp_thread, NULL);

    if (server_fd >= 0) {
        close(server_fd);
    }
    if (unlink(OUTPUT_FILE) < 0 && errno != ENOENT) {
        perror("unlink failed");
    }
    
    closelog();

    return EXIT_SUCCESS;
}