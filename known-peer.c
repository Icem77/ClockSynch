#include <stdlib.h>      // malloc, free, exit
#include <string.h>      // memset, memcpy
#include <stdint.h>      // uint16_t, uint8_t, etc.
#include <stdbool.h>     // bool, true, false
#include <stdio.h>       // printf, fprintf, etc.
#include <arpa/inet.h>   // htons, ntohs, inet_pton, inet_ntoa, etc.
#include <netinet/in.h>  // struct sockaddr_in, in_addr_t
#include <sys/types.h>   // ssize_t, etc.

#include "known-peer.h"
#include "err.h"

struct known_peer* known_peer_list_init() {
    struct known_peer *head = NULL;
    return head;
}

bool known_peer_equals(struct known_peer *p, in_addr_t ip, uint16_t port) {
    return (p->address.sin_addr.s_addr == ip && p->address.sin_port == port);
}

void known_peer_mark_conn_ack(struct known_peer *peer, char *hello_reply_msg, 
    ssize_t *hello_reply_size, uint16_t *count) {

    peer->connection_confirmed = true;

    // Add peer to the HELLO_REPLY message
    *count = ntohs(*count);
    (*count)++;
    *count = htons(*count);
    memcpy(hello_reply_msg + 1, count, sizeof(*count)); // Update number of known peers

    uint8_t peer_address_length = PEER_ADDRESS_LENGTH;
    memcpy(hello_reply_msg + *hello_reply_size, &peer_address_length, PEER_ADDRESS_LENGTH_SIZE); // Add new address length
    (*hello_reply_size) += PEER_ADDRESS_LENGTH_SIZE;

    memcpy(hello_reply_msg + *hello_reply_size, &peer->address.sin_addr.s_addr, sizeof(peer->address.sin_addr.s_addr)); // Add new address
    (*hello_reply_size) += sizeof(peer->address.sin_addr.s_addr);

    memcpy(hello_reply_msg + *hello_reply_size, &peer->address.sin_port, sizeof(peer->address.sin_port)); // Add new port
    (*hello_reply_size) += sizeof(peer->address.sin_port);
}

struct known_peer* known_peer_list_add(struct known_peer **head, in_addr_t ip, uint16_t port) {
    struct known_peer *new_peer = malloc(sizeof(struct known_peer));
    if (new_peer == NULL) {
        syserr("malloc");
    }

    memset(new_peer, 0, sizeof(*new_peer));
    new_peer->address.sin_family = AF_INET; // IPv4
    new_peer->address.sin_addr.s_addr = ip;
    new_peer->address.sin_port = port;

    new_peer->connection_confirmed = false;
    new_peer->next = *head;

    *head = new_peer;

    return new_peer;
}

struct known_peer* known_peer_list_find(struct known_peer *head, in_addr_t ip, uint16_t port) {
    struct known_peer *curr = head;
    while (curr != NULL && !known_peer_equals(curr, ip, port)) {
        curr = curr->next;
    }

    return curr;
}

void known_peer_list_free(struct known_peer **head) {
    while (*head != NULL) {
        struct known_peer *tmp = (*head)->next;
        free(*head);
        *head = tmp;
    }
}