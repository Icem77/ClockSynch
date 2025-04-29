#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <stdint.h> // int types
#include <inttypes.h>
#include <stdbool.h> // bool type
#include <limits.h> // limits macros
#include <string.h> // memset
#include <fcntl.h> // non-blocking socket
#include <signal.h> // signal handling for CTRL+C

#include <sys/types.h> // skopiowane straigh z labow (moze cos stad warto usunac?)
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "err.h" // error handling
#include "known-peer.h" // peer list handling
#include "time.h"

// message types
#define HELLO 1 
#define HELLO_REPLY 2
#define CONNECT 3
#define ACK_CONNECT 4
#define SYNC_START 11
#define DELAY_REQUEST 12
#define DELAY_RESPONSE 13
#define LEADER 21
#define GET_TIME 31
#define TIME 32

// message lengths
#define HELLO_LENGTH 1
#define CONNECT_LENGTH 1
#define ACK_CONNECT_LENGTH 1
#define SYNC_START_LENGTH 10
#define DELAY_REQUEST_LENGTH 1
#define DELAY_RESPONSE_LENGTH 10
#define LEADER_LENGTH 2
#define GET_TIME_LENGTH 1

// sizes
#define MAX_MSG_SIZE 65507
#define PEER_COUNT_BYTE_SIZE 2
#define PORT_BYTE_SIZE 2

static volatile sig_atomic_t keepRunning = 1;
char incoming_message[MAX_MSG_SIZE];
char out_message[MAX_MSG_SIZE];

void handle_sigint(int signo) {
    (void) signo; // Avoid unused parameter warning
    keepRunning = 0;  // Set flag to stop the loop
}

static uint16_t read_port(char const *string) {
    char *endptr;
    errno = 0;
    unsigned long port = strtoul(string, &endptr, 10);
    if (errno != 0 || *endptr != 0 || port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "ERROR: %s is not a valid port number\n", string);
        exit(1);
    }
    return (uint16_t) port;
}

void time_msg_load(ssize_t *out_message_size, uint8_t synchronized, uint64_t start_time_ms, int64_t offset) {
    out_message[(*out_message_size)++] = TIME;
    out_message[(*out_message_size)++] = synchronized;
    uint64_t net_time = htobe64(time_since_ms(start_time_ms) - offset);
    memcpy(out_message + (*out_message_size), &net_time, sizeof(net_time));
    (*out_message_size) += sizeof(net_time);
}

void hello_reply_msg_load(ssize_t *out_message_size, struct known_peer *peer_list, uint16_t count, in_addr_t sender_addr, in_port_t sender_port) {
    out_message[(*out_message_size)++] = HELLO_REPLY;

    uint16_t net_count = htons(count - 1); // exclude peer we send to
    memcpy(out_message + (*out_message_size), &net_count, PEER_COUNT_BYTE_SIZE);
    (*out_message_size) += PEER_COUNT_BYTE_SIZE;
    
    for (struct known_peer *peer = peer_list; peer != NULL; peer = peer->next) {
        if (peer->connection_confirmed && (peer->address.sin_addr.s_addr != sender_addr
            || peer->address.sin_port != sender_port)) {
            
            out_message[(*out_message_size)++] = PEER_ADDRESS_LENGTH;

            memcpy(out_message + (*out_message_size), &peer->address.sin_addr.s_addr,
                PEER_ADDRESS_LENGTH);
            (*out_message_size) += PEER_ADDRESS_LENGTH;

            memcpy(out_message + (*out_message_size), &peer->address.sin_port, PORT_BYTE_SIZE);
            (*out_message_size) += PORT_BYTE_SIZE;
        }
    }
}

void delay_response_msg_load(ssize_t *out_message_size, uint8_t synchronized, uint64_t start_time_ms, int64_t offset) {
    // prepare DELAY_RESPONSE message
    out_message[(*out_message_size)++] = DELAY_RESPONSE;
    out_message[(*out_message_size)++] = synchronized;
    uint64_t nett_time = htobe64(time_since_ms(start_time_ms) - offset);
    memcpy(out_message + (*out_message_size), &nett_time, sizeof(nett_time));
    (*out_message_size) += sizeof(nett_time);
}

bool hello_reply_msg_check(ssize_t bytes_received, in_addr_t sender_addr, in_port_t sender_port, in_addr_t my_addr, in_port_t my_port) {
    ssize_t bytes_red = 1; // already red message type

    // read peers count
    uint16_t peers_count;
    memcpy(&peers_count, incoming_message + bytes_red, PEER_COUNT_BYTE_SIZE);
    bytes_red += PEER_COUNT_BYTE_SIZE;
    peers_count = ntohs(peers_count);

    // check if message has expected length (assuming all peers have 4 byte address)
    if (bytes_received - 3 != peers_count * 7) {
        //printf("BYTES RECEIVED: %ld expected: , %d", bytes_received, 3 + peers_count * 7);
        //printf("HELLO_REPLY message length is not correct\n");
        return false;
    }

    for (int i = 0; i < peers_count; ++i) {
        uint8_t peer_address_length;
        memcpy(&peer_address_length, incoming_message + bytes_red, PEER_ADDRESS_LENGTH_SIZE);
        bytes_red += PEER_ADDRESS_LENGTH_SIZE;

        in_addr_t peer_ip;
        memcpy(&peer_ip, incoming_message + bytes_red, peer_address_length);
        bytes_red += peer_address_length;

        uint16_t peer_port;
        memcpy(&peer_port, incoming_message + bytes_red, PORT_BYTE_SIZE);
        bytes_red += PORT_BYTE_SIZE;

        // check if IP is IPv4 and port is correct
        if (peer_address_length != 4 || peer_port == 0) {
           return false;
        }

        // reply should not contain sender and reciver
        if ((peer_ip == sender_addr && peer_port == sender_port) || 
            (peer_ip == my_addr && peer_port == my_port))
        {
            return false;
        }
    }

    return true;
}

bool send_check(ssize_t bytes_sent, ssize_t message_size) {
    if (bytes_sent < 0) {
        syserr("sendto");
        return false;
    } else if (bytes_sent != message_size) {
        syserr("incomplete sending");
        return false;
    }

    return true;
}

bool length_check(ssize_t bytes_received, ssize_t bytes_expected) {
    if (bytes_received == bytes_expected) {
        return true;
    } else {
        error_msg(incoming_message, bytes_received);
        return false;
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
        syserr("could not set signal handler");
    }

    uint64_t start_time_ms = current_time_ms(); // Start measuring time

    struct known_peer *peer_list = NULL; // Initialize peer list

    uint8_t synchronized = 255; // Set default synchronization level
    uint16_t count = 0; // Number of connected peers (stored in HOST byte order)

    ssize_t out_message_size = 0; 

    // Set bind address
    struct sockaddr_in bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET; // IPv4
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces by default
    bind_address.sin_port = htons(0); // Listening on any port by default
    
    // Set peer address
    struct sockaddr_in hello_peer_address;
    memset(&hello_peer_address, 0, sizeof(hello_peer_address));
    hello_peer_address.sin_family = AF_INET; // IPv4

    // Load program args
    int opt;
    bool a_appeared = false;
    bool r_appeared = false;

    while ((opt = getopt(argc, argv, "b:p:a:r:")) != -1) {
        switch(opt) {
            case 'b': // Bind adress
                //printf("Option b with argument: %s\n", optarg);

                if (inet_pton(AF_INET, optarg, &bind_address.sin_addr) != 1) {
                    fprintf(stderr, "ERROR: invalid IP address: %s\n", optarg);
                    exit(1);
                }

                break;
            case 'p': // Bind port 
                //printf("Option p with argument: %s\n", optarg);
                bind_address.sin_port = htons(read_port(optarg));
                break;
            case 'a': // Hello Peer address
                //printf("Option a with argument: %s\n", optarg);
                
                // Load IP / hostname of a hello peer
                struct addrinfo hints;
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_INET; // IPv4
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
            
                struct addrinfo *address_result;
                int errcode = getaddrinfo(optarg, NULL, &hints, &address_result);
                if (errcode != 0) {
                    syserr("getaddrinfo");
                    exit(1);
                }
            
                hello_peer_address.sin_addr.s_addr =       // IP address
                        ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr;
            
                freeaddrinfo(address_result);

                a_appeared = true;
                break;
            case 'r': // Hello Peer port
                //printf("Option r with argument: %s\n", optarg);
                hello_peer_address.sin_port = htons(read_port(optarg));
                r_appeared = true;
                break;
        }
    }

    // Check if -a and -r come in pair
    if (a_appeared && !r_appeared) {
        fprintf(stderr, "ERROR: -a option requires -r option");
        exit(1);
    } else if (!a_appeared && r_appeared) {
        fprintf(stderr, "ERROR: -r option requires -a option\n");
        exit(1);
    } 

    // Create a socket
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        syserr("could not create a socket");
        exit(1);
    }

    fcntl(socket_fd, F_SETFL, O_NONBLOCK); // Set non-blocking mode

    // Bind socket to address
    if (bind(socket_fd, (struct sockaddr *) &bind_address, (socklen_t) sizeof(bind_address)) < 0) {
        syserr("could not bind socket");
        exit(1);
    }

    if (a_appeared && r_appeared) { // Send HELLO to peer
        out_message[out_message_size++] = HELLO;

        ssize_t bytes_sent = sendto(socket_fd, out_message, out_message_size,
                0, (struct sockaddr *) &hello_peer_address, sizeof(hello_peer_address));

        if (send_check(bytes_sent, out_message_size)) {
            known_peer_list_add(&peer_list, hello_peer_address.sin_addr.s_addr,
                    hello_peer_address.sin_port); // add peer to list (do not confirm connection yet)
                    
            control_message(HELLO, &bind_address, &hello_peer_address);
        }        
    }

    struct sockaddr_in sync_peer;
    memset(&sync_peer, 0, sizeof(sync_peer));
    sync_peer.sin_family = AF_INET; // IPv4

    uint64_t last_sync_timestamp = 0; // last time we calculated offset

    struct sockaddr_in sync_peer_candidate;
    memset(&sync_peer_candidate, 0, sizeof(sync_peer_candidate));
    sync_peer_candidate.sin_family = AF_INET; // IPv4

    struct known_peer *peer = NULL;
    ssize_t sent;
    uint64_t leader_start_timestamp = 0; // moment of becoming a leader
    uint64_t sync_start_loop_timestamp = 0; // moment of starting SYNC_START loop
    int64_t offset = 0;
    uint64_t T1 = 0, T2 = 0, T3 = 0, T4 = 0;
    bool sync_peer_found = false;
    bool during_sync = false;
    bool leader_start_privilege = false;
    uint8_t sync_peer_synchronized = 255;

    // Main loop
    while (keepRunning) {
        // start synchronization if level is under 254
        if ((leader_start_privilege && time_since_ms(leader_start_timestamp) >= LEADER_PRIVILEGE_SYNC_START_MS) || 
            (synchronized < 254 && time_since_ms(sync_start_loop_timestamp) >= SYNC_START_INTERVAL_MS)) {

            leader_start_privilege = false;
            
            // prepare SYNC_START message
            out_message_size = 0;
            out_message[out_message_size++] = SYNC_START;
            out_message[out_message_size++] = synchronized;
            
            sync_start_loop_timestamp = current_time_ms(); // update timestamp

            for (peer = peer_list; peer != NULL; peer = peer->next) {
                if (peer->connection_confirmed) {
                    uint64_t net_time = htobe64(time_since_ms(start_time_ms) - offset);
                    memcpy(out_message + out_message_size, &net_time, sizeof(net_time));
                    out_message_size += sizeof(net_time);

                    sent = sendto(socket_fd, out_message, out_message_size, 0, 
                        (struct sockaddr*) &peer->address, sizeof(peer->address));
                        
                    if (send_check(sent, out_message_size)) {
                        peer->last_message_timestamp_ms = current_time_ms(); // update timestamp
                        peer->delay_response_token = true; // give token for delay response
                    }
                    
                    out_message_size -= sizeof(net_time); // remove timestamp from message
                    control_message(SYNC_START, &bind_address, &peer->address);
                }
            }
        }

        // if we are during sync check how much time passed since SYNC_START message
        if (during_sync && time_since_ms(start_time_ms) - T2 >= DELAY_RESPONSE_TIMEOUT_MS) {
            during_sync = false; // stop synchronizing
            //printf("DELAY_RESPONSE timeout\n");
        }

        if (sync_peer_found && time_since_ms(last_sync_timestamp) >= SYNC_PEER_TIMEOUT_MS) {
            sync_peer_found = false; // not in sync anymore
            offset = 0; // reset offset
            synchronized = 255;
            //printf("Lost connection with sync_peer\n");
        }

        struct sockaddr_in sender_address;
        socklen_t sender_address_len = (socklen_t) sizeof(sender_address);
        ssize_t bytes_received = recvfrom(socket_fd, incoming_message, MAX_MSG_SIZE,
                0, (struct sockaddr *) &sender_address, &sender_address_len);

        if (bytes_received == -1) {
            continue;
        } else if (bytes_received == 0) {
            error_msg(incoming_message, bytes_received);
            //printf("Received 0 bytes\n");
            continue;  
        }

        ssize_t bytes_red = 0;
        uint8_t message_type = (uint8_t) incoming_message[bytes_red++];
        out_message_size = 0;

        switch (message_type) {
            case GET_TIME:
                if (!length_check(bytes_received, GET_TIME_LENGTH)) break;

                time_msg_load(&out_message_size, synchronized, start_time_ms, offset);

                sent = sendto(socket_fd, out_message, out_message_size, 0, 
                    (struct sockaddr*) &sender_address, sender_address_len);

                send_check(sent, out_message_size);
                
                control_message(TIME, &bind_address, &sender_address);
                break;
            case HELLO:
                if (!length_check(bytes_received, HELLO_LENGTH)) break;

                peer = known_peer_list_find(peer_list,
                    sender_address.sin_addr.s_addr, sender_address.sin_port);
                
                // check if we can accept new connection
                if (count < UINT16_MAX) {
                    if (peer == NULL) {
                        peer = known_peer_list_add(&peer_list, sender_address.sin_addr.s_addr,
                            sender_address.sin_port); // add peer to list (do not confirm connection yet)
                    }

                    if (peer != NULL && !peer->connection_confirmed) {
                        known_peer_mark_conn_ack(peer, &count); // confirm connection
                    }        
                }

                // Reply if peer was just added or already known
                if (peer != NULL && peer->connection_confirmed) {
                    hello_reply_msg_load(&out_message_size, peer_list, count, sender_address.sin_addr.s_addr, sender_address.sin_port);

                    sent = sendto(socket_fd, out_message, out_message_size, 0, 
                        (struct sockaddr*) &sender_address, sender_address_len);
                    
                    send_check(sent, out_message_size);

                    control_message(HELLO_REPLY, &bind_address, &sender_address);
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("could not accept new connection\n");
                    break;
                }

                break;
            case HELLO_REPLY:
                // check if we sent HELLO to this peer and if we already received correct HELLO_REPLY
                if (a_appeared && r_appeared && 
                    hello_peer_address.sin_addr.s_addr == sender_address.sin_addr.s_addr &&
                    hello_peer_address.sin_port == sender_address.sin_port) 
                {

                    // check if peer was already connected
                    peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);
                    
                    if (!peer->connection_confirmed) {
                        known_peer_mark_conn_ack(peer, &count); // confirm connection
                    }

                    if (!hello_reply_msg_check(bytes_received, sender_address.sin_addr.s_addr,
                        sender_address.sin_port, bind_address.sin_addr.s_addr, bind_address.sin_port)) 
                    {
                        error_msg(incoming_message, bytes_received);
                        break;
                    }

                    uint16_t peers_count;
                    memcpy(&peers_count, incoming_message + bytes_red, PEER_COUNT_BYTE_SIZE);
                    bytes_red += PEER_COUNT_BYTE_SIZE;
                    peers_count = ntohs(peers_count);

                    out_message[out_message_size++] = CONNECT;

                    // read peers (data is correct)
                    for (int i = 0; i < peers_count; ++i) {
                        uint8_t new_peer_address_length;
                        memcpy(&new_peer_address_length, incoming_message + bytes_red, PEER_ADDRESS_LENGTH_SIZE);
                        bytes_red += PEER_ADDRESS_LENGTH_SIZE;

                        in_addr_t new_peer_ip;
                        memcpy(&new_peer_ip, incoming_message + bytes_red, new_peer_address_length);
                        bytes_red += new_peer_address_length;

                        uint16_t new_peer_port;
                        memcpy(&new_peer_port, incoming_message + bytes_red, PORT_BYTE_SIZE);
                        bytes_red += PORT_BYTE_SIZE;

                        peer = known_peer_list_find(peer_list, new_peer_ip, new_peer_port);

                        // use sender address to send CONNECT message
                        sender_address.sin_addr.s_addr = new_peer_ip;
                        sender_address.sin_port = new_peer_port;

                        sent = sendto(socket_fd, out_message, out_message_size, 0, 
                            (struct sockaddr*) &sender_address, sender_address_len);

                        if (peer == NULL && send_check(sent,out_message_size)) {
                            peer = known_peer_list_add(&peer_list, new_peer_ip, new_peer_port);
                            if (peer == NULL) continue; // could not add peer to list because of malloc problems
                        }

                        if (send_check(sent,out_message_size)) {
                            peer->ack_connect_token = true; // give ACK_CONNECT token
                        }

                        control_message(CONNECT, &bind_address, &sender_address);
                    }

                    a_appeared = false; // accept only one correct HELLO_REPLY 
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("HELLO_REPLY from unexpected peer\n");
                }

                break;
            case CONNECT:
                if (!length_check(bytes_received, CONNECT_LENGTH)) break;

                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);
                
                if (count < UINT16_MAX) {
                    if (peer == NULL) {
                        peer = known_peer_list_add(&peer_list, sender_address.sin_addr.s_addr,
                            sender_address.sin_port); // add peer to list (do not confirm connection yet)
                    }

                    if (peer != NULL && !peer->connection_confirmed) {
                        known_peer_mark_conn_ack(peer, &count); // confirm connection
                    }
                }

                if (peer != NULL && peer->connection_confirmed) {
                    out_message[out_message_size++] = ACK_CONNECT;

                    sent = sendto(socket_fd, out_message, out_message_size, 0, 
                        (struct sockaddr*) &sender_address, sender_address_len);

                    send_check(sent, out_message_size);

                    control_message(ACK_CONNECT, &bind_address, &sender_address);
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("could not accept more connections\n");
                }
                
                break;
            case ACK_CONNECT:
                if (!length_check(bytes_received, ACK_CONNECT_LENGTH)) break;

                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);

                if (peer == NULL || !peer->ack_connect_token) {
                    error_msg(incoming_message, bytes_received);
                    //printf("ACK_CONNECT from unexpected peer\n");
                    break;
                } 
                
                if (!peer->connection_confirmed) {
                    known_peer_mark_conn_ack(peer, &count); // confirm connection
                }

                peer->ack_connect_token = false; // remove ACK_CONNECT token
                
                break;
            case LEADER:
                if (!length_check(bytes_received, LEADER_LENGTH)) break;

                uint8_t sync_in_leader_msg = (uint8_t) incoming_message[bytes_red++]; 

                if (sync_in_leader_msg == 0) {
                    synchronized = 0;
                    leader_start_privilege = true; // permission to start sync after 2s
                    leader_start_timestamp = current_time_ms();
                    sync_start_loop_timestamp = current_time_ms(); 
                    sync_peer_found = false;
                    during_sync = false; // stop synchronizing to avoid decrease of sync level
                    //printf("BECOMING LEADER\n");
                } else if (sync_in_leader_msg == 255 && synchronized == 0) {
                    synchronized = 255;
                    leader_start_privilege = false;
                    sync_peer_found = false;
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("unknown 'synchronized' in LEADER message\n");
                }

                break;
            case SYNC_START:
                if (!length_check(bytes_received, SYNC_START_LENGTH)) break;

                if (during_sync) {
                    error_msg(incoming_message, bytes_received);
                    //printf("SYNC_START while already in sync\n");
                    break;
                }

                T2 = time_since_ms(start_time_ms); // get timestamp of receiving SYNC_START

                peer = known_peer_list_find(peer_list, sender_address.sin_addr.s_addr, sender_address.sin_port);

                sync_peer_synchronized = (uint8_t) incoming_message[bytes_red++]; // read synch of peer
                memcpy(&T1, incoming_message + bytes_red, sizeof(T1)); // get T1 timestamp (time of sending SYNC_START)
                bytes_red += sizeof(T1);
                T1 = be64toh(T1); // convert to host byte order

                // set synchronized to 255 if our sync peer has sync not lower than ours
                if (sync_peer_found && sync_peer.sin_addr.s_addr == sender_address.sin_addr.s_addr &&
                    sync_peer.sin_port == sender_address.sin_port && sync_peer_synchronized >= synchronized)
                {
                    sync_peer_found = false;
                    synchronized = 255;
                    break; // quit SYNC_START handling
                }

                // check if we know this peer
                if (peer != NULL && peer->connection_confirmed && sync_peer_synchronized < 254 && 
                    ((int)synchronized - (int)sync_peer_synchronized >= 2 || 
                        (sync_peer_found && sync_peer.sin_addr.s_addr == sender_address.sin_addr.s_addr &&
                        sync_peer.sin_port == sender_address.sin_port && sync_peer_synchronized < synchronized)))
                    {   
                        //printf("SYNCING (mine: %d, incoming: %d)\n", synchronized, sync_peer_synchronized);

                        sync_peer_candidate.sin_addr.s_addr = sender_address.sin_addr.s_addr;
                        sync_peer_candidate.sin_port = sender_address.sin_port;

                        out_message[out_message_size++] = DELAY_REQUEST;

                        sent = sendto(socket_fd, out_message, out_message_size, 0, 
                            (struct sockaddr*) &sender_address, sender_address_len);

                        T3 = time_since_ms(start_time_ms); // get T3 timestamp (moment of sending DELAY_REQUEST)

                        if (send_check(sent, out_message_size)) {
                            during_sync = true; // we are synchronizing
                        }

                        control_message(DELAY_REQUEST, &bind_address, &sender_address);
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("SYNC_START from unknown peer OR not enough synchronized\n");
                }

                break;
            case DELAY_REQUEST:
                if (!length_check(bytes_received, DELAY_REQUEST_LENGTH)) break;

                peer = known_peer_list_find(peer_list,
                        sender_address.sin_addr.s_addr, sender_address.sin_port);
                
                // if we do not know this peer or response was already sent we ignore the message
                if (peer == NULL || !peer->connection_confirmed || !peer->delay_response_token || 
                    time_since_ms(peer->last_message_timestamp_ms) >= DELAY_REQUEST_TIMEOUT_MS)
                {

                    error_msg(incoming_message, bytes_received);
                    //printf("DELAY_REQUEST will not be handled\n");
                    break;
                }

                peer->delay_response_token = false; // remove delay response token

                delay_response_msg_load(&out_message_size, synchronized, start_time_ms, offset);

                sent = sendto(socket_fd, out_message, out_message_size, 0, 
                    (struct sockaddr*) &sender_address, sender_address_len);
                
                send_check(sent, out_message_size);

                control_message(DELAY_RESPONSE, &bind_address, &sender_address);

                break;
            case DELAY_RESPONSE:
                if (!length_check(bytes_received, DELAY_RESPONSE_LENGTH)) break;

                if (during_sync && sender_address.sin_addr.s_addr == sync_peer_candidate.sin_addr.s_addr && 
                    sender_address.sin_port == sync_peer_candidate.sin_port) {

                    during_sync = false; // finish synchronizing

                    uint8_t peer_sync_again = (uint8_t) incoming_message[bytes_red++]; // read synch of peer

                    if (peer_sync_again != sync_peer_synchronized) {
                        error_msg(incoming_message, bytes_received);
                        //printf("sync_peer_synchronized in DELAY_RESPONSE is different than in SYNC_START (START: %d, NOW: %d)\n", sync_peer_synchronized, peer_sync_again);
                        during_sync = false;
                        break;
                    }

                    memcpy(&T4, incoming_message + bytes_red, sizeof(T4)); // get T4 timestamp (time of sending DELAY_RESPONSE)
                    bytes_red += sizeof(T4);
                    T4 = be64toh(T4); // convert to host byte order

                    if (T4 < T1) {
                        error_msg(incoming_message, bytes_received);
                        //printf("T4 < T1\n");
                        break;
                    }

                    offset = ((int64_t) T2 - (int64_t) T1 + (int64_t) T3 - (int64_t) T4) / 2; // update offset
                    //printf("new offset: %" PRId64 "\n", offset);

                    sync_peer.sin_addr.s_addr = sync_peer_candidate.sin_addr.s_addr;
                    sync_peer.sin_port = sync_peer_candidate.sin_port;
                    sync_peer_found = true; // we found sync peer

                    synchronized = sync_peer_synchronized + 1; // set new synchronization level

                    last_sync_timestamp = current_time_ms(); // update timestamp
                } else {
                    error_msg(incoming_message, bytes_received);
                    //printf("DELAY_RESPONSE from unexpected peer or timed out\n");
                }

                break;
        }
    }

    if (close(socket_fd) < 0) {
        syserr("could not close socket");
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