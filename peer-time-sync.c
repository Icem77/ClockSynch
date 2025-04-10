#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <stdint.h> // int types
#include <inttypes.h>
#include <stdbool.h> // bool type
#include <limits.h> // limits macros
#include <string.h> // memset

#include <sys/types.h> // skopiowane straigh z labow (moze cos stad warto usunac?)
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "err.h" // error handling

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
    // set synchronization level
    uint8_t synchronized = 255;

    // set bind address
    struct sockaddr_in bind_address;
    bind_address.sin_family = AF_INET; // IPv4
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces.
    bind_address.sin_port = htons(0); // Listening on any port by default.
    
    struct sockaddr_in peer_address;
    peer_address.sin_family = AF_INET;   // IPv4

    // load program args
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
                bind_address.sin_port = read_port(optarg);
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
            case 'r':
                printf("Option r with argument: %s\n", optarg);

                peer_address.sin_port = read_port(optarg);

                r_appeared = true;
                break;
        }
    }

    // check if -a and -r come in pairs
    if (a_appeared && !r_appeared) {
        fprintf(stderr, "ERROR: -a option requires -r option\n");
        exit(1);
    } else if (!a_appeared && r_appeared) {
        fprintf(stderr, "ERROR: -r option requires -a option\n");
        exit(1);
    } else {
        printf("Option a and r are paired\n");
    }
}