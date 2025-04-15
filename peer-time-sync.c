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
#include "known-peer.h" // peer list handling

#define HELLO 1 // define message types
#define HELLO_REPLY 2
#define CONNECT 3
#define ACK_CONNECT 4
#define SYNC_START 11
#define DELAY_REQUEST 12
#define DELAY_RESPONSE 13
#define LEADER 21
#define GET_TIME 31
#define TIME 32

#define MAX_MSG_SIZE 1024
#define ERR_MSG_SIZE 11
#define PEER_COUNT_BYTE_SIZE 2
#define PORT_BYTE_SIZE 2

static volatile sig_atomic_t keepRunning = 1;

void handle_sigint(int signo) {
    (void) signo; // Avoid unused parameter warning
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

static uint64_t time_since_ms(uint64_t start_time_ms) {
    return current_time_ms() - start_time_ms;
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

void send_check(ssize_t bytes_sent, ssize_t message_size) {
    if (bytes_sent < 0) {
        syserr("sendto");
    } else if (bytes_sent != message_size) {
        fatal("incomplete sending");
    }
}

void control_message(uint8_t message_type, struct sockaddr_in *sender_address, struct sockaddr_in *reciever_address) {
    char sender_ip_str[INET_ADDRSTRLEN];
    char reciever_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(*sender_address).sin_addr, sender_ip_str, sizeof(sender_ip_str));
    uint16_t sender_port = ntohs((*sender_address).sin_port);
    inet_ntop(AF_INET, &(*reciever_address).sin_addr, reciever_ip_str, sizeof(reciever_ip_str));
    uint16_t reciever_port = ntohs((*reciever_address).sin_port);

    printf("[%s:%" PRIu16 "] Sent %" PRIu8 " to %s:%" PRIu16 "\n", 
        sender_ip_str, sender_port, message_type, reciever_ip_str, reciever_port);
}

int main(int argc, char *argv[]) {
    // Add SIGINT handler
    if (signal(SIGINT, handle_sigint) == SIG_ERR) {
        fprintf(stderr, "ERROR: cannot set signal handler\n");
    }

    uint64_t start_time_ms = current_time_ms(); // Start measuring time

    struct known_peer *peer_list = known_peer_list_init(); // Initialize peer list

    uint8_t synchronized = 255; // Set default synchronization level

    char message[MAX_MSG_SIZE]; // Create buffer for messages
    memset(message, 0, sizeof(message)); 
    ssize_t message_size = 0;

    char hello_reply_msg[MAX_MSG_SIZE]; // Separate buffer for HELLO handling
    uint16_t count = 0; // Number of known peers
    ssize_t hello_reply_size = 0;

    memset(hello_reply_msg, 0, sizeof(hello_reply_msg));
    hello_reply_msg[hello_reply_size++] = HELLO_REPLY; // Set message type
    memcpy(hello_reply_msg + hello_reply_size, &count, sizeof(count)); // Set number of known peers to zero
    hello_reply_size += sizeof(count); // Update message size

    // Set bind address
    struct sockaddr_in bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET; // IPv4
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces
    bind_address.sin_port = htons(0); // Listening on any port by default
    
    // Set peer address
    struct sockaddr_in peer_address;
    memset(&peer_address, 0, sizeof(peer_address));
    peer_address.sin_family = AF_INET;   // IPv4

    // Load program args
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
                
                // Load IP / hostname of a peer
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

    // Check if -a and -r come in pair
    if (a_appeared && !r_appeared) {
        fatal("-a option requires -r option");
    } else if (!a_appeared && r_appeared) {
        fatal("-r option requires -a option\n");
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

        known_peer_list_add(&peer_list, peer_address.sin_addr.s_addr,
                peer_address.sin_port); // add peer to list (do not confirm connection yet)

        control_message(HELLO, &bind_address, &peer_address);
    }

    struct known_peer *peer;
    struct known_peer *sync_peer;
    ssize_t sent;
    uint64_t leader_start_timestamp = 0;
    uint64_t sync_start_loop_timestamp = 0;
    uint64_t offset = 0;
    bool leader_privilage = false;
    // Start receiving messages
    while (keepRunning) {
        struct sockaddr_in sender_address;
        socklen_t sender_address_len = (socklen_t) sizeof(sender_address);
        ssize_t bytes_received = recvfrom(socket_fd, message, sizeof(message),
                0, (struct sockaddr *) &sender_address, &sender_address_len);

        if (bytes_received == -1) {
            continue;
        } else if (bytes_received == 0) {
            printf("recieved empty message\n");        
        }

        ssize_t bytes_red = 0;
        uint8_t message_type = (uint8_t) message[bytes_red++];
        message_size = 0;

        switch (message_type) {
            case GET_TIME:
                // prepare message
                message[message_size++] = TIME;
                message[message_size++] = synchronized;
                uint64_t net_time = htobe64(time_since_ms(start_time_ms) - offset);
                memcpy(message + message_size, &net_time, sizeof(net_time));
                message_size += sizeof(net_time);

                sent = sendto(socket_fd, message, message_size, 0, 
                    (struct sockaddr*) &sender_address, sender_address_len);

                send_check(sent, message_size);
                
                control_message(TIME, &bind_address, &sender_address);
                break;
            case HELLO:
                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);

                if (peer == NULL) {
                    sent = sendto(socket_fd, hello_reply_msg, hello_reply_size, 0, 
                        (struct sockaddr*) &sender_address, sender_address_len);
    
                    send_check(sent, hello_reply_size);
    
                    control_message(HELLO_REPLY, &bind_address, &sender_address);

                    known_peer_mark_conn_ack(known_peer_list_add(&peer_list, sender_address.sin_addr.s_addr,
                        sender_address.sin_port), hello_reply_msg, &hello_reply_size, &count); // confirm connection
                } else {
                    printf("HELLO from already connected peer");
                    break;
                }

                break;
            case HELLO_REPLY:
                // check if we sent HELLO to this peer
                if (a_appeared && r_appeared && peer_address.sin_addr.s_addr == sender_address.sin_addr.s_addr &&
                    peer_address.sin_port == sender_address.sin_port) {

                    // check if peer was already connected
                    peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);
                    
                    if (peer->connection_confirmed) {
                        printf("Peer already connected by HELLO_REPLY\n");
                        break;
                    } else {
                        known_peer_mark_conn_ack(peer, hello_reply_msg, &hello_reply_size, &count); // confirm connection
                    }
                } else {
                    printf("HELLO_REPLY from unexpected peer\n");
                    break;
                }

                // 1. read peers count
                uint16_t peers_count;
                memcpy(&peers_count, message + bytes_red, PEER_COUNT_BYTE_SIZE);
                bytes_red += PEER_COUNT_BYTE_SIZE;
                peers_count = ntohs(peers_count);

                // 2. read peers (assume data is correct)
                for (int i = 0; i < peers_count; ++i) {
                    uint8_t new_peer_address_length;
                    memcpy(&new_peer_address_length, message + bytes_red, PEER_ADDRESS_LENGTH_SIZE);
                    bytes_red += PEER_ADDRESS_LENGTH_SIZE;

                    in_addr_t new_peer_ip;
                    memcpy(&new_peer_ip, message + bytes_red, new_peer_address_length);
                    bytes_red += new_peer_address_length;

                    uint16_t new_peer_port;
                    memcpy(&new_peer_port, message + bytes_red, PORT_BYTE_SIZE);
                    bytes_red += PORT_BYTE_SIZE;

                    // add peer to the list (do not confirm connection yet)
                    known_peer_list_add(&peer_list, new_peer_ip, new_peer_port);

                    // prepare CONNECT message
                    char short_message[1];
                    short_message[0] = CONNECT;
                    sender_address.sin_addr.s_addr = new_peer_ip;
                    sender_address.sin_port = new_peer_port;

                    sent = sendto(socket_fd, short_message, sizeof(short_message), 0, 
                        (struct sockaddr*) &sender_address, sender_address_len);

                    send_check(sent, sizeof(short_message));

                    control_message(CONNECT, &bind_address, &sender_address);
                }
                break;
            case CONNECT:
                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);
                
                // TODO: co jesli dostaniemy CONNECT od osoby do ktorej wyslalismy CONNECT
                if (peer == NULL) {
                    known_peer_mark_conn_ack(known_peer_list_add(&peer_list, sender_address.sin_addr.s_addr,
                        sender_address.sin_port), hello_reply_msg, &hello_reply_size, &count); // confirm connection

                    // prepare ACK_CONNECT message
                    message[message_size++] = ACK_CONNECT;

                    sent = sendto(socket_fd, message, message_size, 0, 
                        (struct sockaddr*) &sender_address, sender_address_len);

                    send_check(sent, message_size);
                    
                    control_message(ACK_CONNECT, &bind_address, &sender_address);
                } else {
                    printf("CONNECT from already connected peer\n");
                    break;
                }
                
                break;
            case ACK_CONNECT:
                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);

                if (peer != NULL) {
                    if (peer->connection_confirmed) {
                        printf("ACK_CONNECT from already connected peer\n");
                    } else {
                        known_peer_mark_conn_ack(peer, hello_reply_msg, &hello_reply_size, &count);
                    }
                } else {
                    msg_error("ACK_CONNECT from unexpected peer");
                }
                break;
            case LEADER:
                uint8_t sync = (uint8_t) message[bytes_red++]; 

                if (sync == 0) {
                    synchronized = 0;
                    leader_start_timestamp = current_time_ms();
                    leader_privilage = true;
                } else if (sync == 255) {
                    if (synchronized == 0) {
                        synchronized = 255;
                    } else {
                        printf("already not a LEADER\n");
                    }
                } else {
                    printf("unknown 'synchronized' in LEADER message\n");
                }

                break;
            case SYNC_START:
                break;
            case DELAY_REQUEST:
                break;
            case DELAY_RESPONSE:
                break;
        }

        // start synchronization if our level is under 254
        if ((synchronized == 0 && leader_privilage && time_since_ms(leader_start_timestamp) >= 2000) || 
            (synchronized < 254 && time_since_ms(sync_start_loop_timestamp) >= 5000)) {
            
            // prepare SYNC_START message
            message_size = 0;
            message[message_size++] = SYNC_START;
            message[message_size++] = synchronized;

            peer = peer_list;
            while (peer != NULL) {
                if (peer->connection_confirmed) {
                    uint64_t net_time = htobe64(time_since_ms(start_time_ms) - offset);
                    memcpy(message + message_size, &net_time, sizeof(net_time));
                    message_size += sizeof(net_time);

                    sent = sendto(socket_fd, message, message_size, 0, 
                        (struct sockaddr*) &peer->address, sizeof(peer->address));
                        
                    send_check(sent, message_size);
                    
                    peer->last_message_timestamp_ms = current_time_ms(); // update timestamp
                    peer->delay_response_token = true; // give delay response token
                    
                    message_size -= sizeof(net_time); // remove timestamp from message
                    control_message(SYNC_START, &bind_address, &peer->address);
                }
            }
        }
    }

    if (close(socket_fd) < 0) {
        syserr("cannot close socket");
    }
    printf("Connection socket closed.\n");

    known_peer_list_free(&peer_list);
    if (peer_list == NULL) {
        printf("Peer list freed.\n");
    } else {
        printf("cannot free peer list\n");
    }

    return 0;
}