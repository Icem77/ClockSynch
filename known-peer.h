#ifndef KNOWN_PEER_H
#define KNOWN_PEER_H

#include <stdbool.h>       // for bool type
#include <stdint.h>        // for uint16_t type
#include <sys/types.h>     // for ssize_t type
#include <netinet/in.h>    // for struct sockaddr_in and in_addr_t

#define PEER_ADDRESS_LENGTH 4
#define PEER_ADDRESS_LENGTH_SIZE 1

struct known_peer {
    struct sockaddr_in address;
    uint64_t last_message_timestamp_ms;
    bool ack_connect_token;
    bool connection_confirmed;
    bool delay_response_token;

    struct known_peer *next;
};

struct known_peer* known_peer_list_init();

bool known_peer_equals(struct known_peer *p, in_addr_t ip, uint16_t port);

void known_peer_mark_conn_ack(struct known_peer *peer, uint16_t *count);

struct known_peer* known_peer_list_add(struct known_peer **head, in_addr_t ip, uint16_t port);

struct known_peer* known_peer_list_find(struct known_peer *head, in_addr_t ip, uint16_t port);

void known_peer_list_free(struct known_peer **head);

#endif