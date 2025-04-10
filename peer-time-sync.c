#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <stdint.h> // int types
#include <inttypes.h>
#include <stdbool.h> // bool type
#include <limits.h> // limits macros
#include <string.h> // memset
#include <fcntl.h> // non-blocking socket
#include <time.h> // clock_gettime, struct timespec
#include <signal.h> // signal handling for CTRL+C

#include <sys/types.h> // skopiowane straigh z labow (moze cos stad warto usunac?)
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "err.h" // error handling

#define HELLO 1
#define MAX_MSG_SIZE 1024

static volatile sig_atomic_t keepRunning = 1;

void handle_sigint(int signo) {
    keepRunning = 0;  // Set flag to stop the loop
}

static uint64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    // Konwersja seconds -> ms & nanoseconds -> ms
    uint64_t ms = (uint64_t)ts.tv_sec * 1000
                + (uint64_t)(ts.tv_nsec / 1000000);
    return ms;
}

static uint16_t read_port(char const *string) {
    char *endptr;
    errno = 0;
    unsigned long port = strtoul(string, &endptr, 10);
    if (errno != 0 || *endptr != 0 || port == 0 || port > UINT16_MAX) {
        fatal("%s is not a valid port number", string);
    }
    return (uint16_t) port;
}

int main(int argc, char *argv[]) {
    // Add SIGINT handler
    if (signal(SIGINT, handle_sigint) == SIG_ERR) {
        fprintf(stderr, "ERROR: cannot set signal handler\n");
    }

    // Start measuring time
    uint64_t start_time_ms = current_time_ms();

    uint8_t synchronized = 255; // Set default synchronization level
    char message[MAX_MSG_SIZE]; // Create buffer for messages
    memset(message, 0, sizeof(message)); 
    ssize_t message_size = 0;

    // set bind address
    struct sockaddr_in bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET; // IPv4
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces
    bind_address.sin_port = htons(0); // Listening on any port by default
    
    // set peer address
    struct sockaddr_in peer_address;
    memset(&peer_address, 0, sizeof(peer_address));
    peer_address.sin_family = AF_INET;   // IPv4

    // Load program args.
    int opt;
    bool a_appeared = false;
    bool r_appeared = false;

    while ((opt = getopt(argc, argv, "b:p:a:r:")) != -1) {
        switch(opt) {
            case 'b': // Bind adress
                printf("Option b with argument: %s\n", optarg);

                if (inet_pton(AF_INET, optarg, &bind_address.sin_addr) != 1) {
                    fprintf(stderr, "ERROR: invalid IP address: %s\n", optarg);
                    exit(1);
                }

                break;
            case 'p': // Bind port 
                printf("Option p with argument: %s\n", optarg);
                bind_address.sin_port = htons(read_port(optarg));
                break;
            case 'a': // Peer address
                printf("Option a with argument: %s\n", optarg);
                
                struct addrinfo hints;
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_INET; // IPv4
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
            
                struct addrinfo *address_result;
                int errcode = getaddrinfo(optarg, NULL, &hints, &address_result);
                if (errcode != 0) {
                    fatal("getaddrinfo: %s", gai_strerror(errcode));
                }
            
                peer_address.sin_addr.s_addr =       // IP address
                        ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr;
            
                freeaddrinfo(address_result);

                a_appeared = true;
                break;
            case 'r': // Peer port
                printf("Option r with argument: %s\n", optarg);
                peer_address.sin_port = htons(read_port(optarg));
                r_appeared = true;
                break;
        }
    }

    // Check if -a and -r come in pairs
    if (a_appeared && !r_appeared) {
        fatal("ERROR: -a option requires -r option");
    } else if (!a_appeared && r_appeared) {
        fatal("ERROR: -r option requires -a option\n");
    } 

    // Create a socket
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        syserr("cannot create a socket");
    }

    fcntl(socket_fd, F_SETFL, O_NONBLOCK); // Set non-blocking mode

    // Bind socket to concrete address
    if (bind(socket_fd, (struct sockaddr *) &bind_address, (socklen_t) sizeof(bind_address)) < 0) {
        syserr("cannot bind socket");
    }


    if (a_appeared && r_appeared) { // Send HELLO to peer
        message[message_size++] = HELLO;

        ssize_t bytes_sent = sendto(socket_fd, message, message_size,
                0, (struct sockaddr *) &peer_address, sizeof(peer_address));

        if (bytes_sent < 0) {
            syserr("sendto");
        } else if (bytes_sent != message_size) {
            fatal("incomplete sending");
        }

        message_size--; // Remove HELLO from message buffer

        char peer_ip_str[INET_ADDRSTRLEN];
        char bind_ip_str[INET_ADDRSTRLEN];
        
        // Print control information
        inet_ntop(AF_INET, &peer_address.sin_addr, peer_ip_str, sizeof(peer_ip_str));
        uint16_t peer_port = ntohs(peer_address.sin_port);
        inet_ntop(AF_INET, &bind_address.sin_addr, bind_ip_str, sizeof(bind_ip_str));
        uint16_t bind_port = ntohs(bind_address.sin_port);

        printf("[%s:%" PRIu16 "] Sent HELLO to %s:%" PRIu16 "\n", 
            bind_ip_str, bind_port, peer_ip_str, peer_port);
    }

    // Start receiving messages
    while (keepRunning) {

    }

    if (close(socket_fd) < 0) {
        syserr("cannot close socket");
    }
    printf("Connection socket closed.\n");

    return 0;
}