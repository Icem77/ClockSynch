#include <stdlib.h>      
#include <string.h>      
#include <stdint.h>      
#include <stdbool.h>     
#include <stdio.h>       
#include <arpa/inet.h>   
#include <netinet/in.h>  
#include <sys/types.h>   

#include "known-peer.h"
#include "err.h"

bool known_peer_equals(struct known_peer *p, in_addr_t ip, uint16_t port) {
    return (p->address.sin_addr.s_addr == ip && p->address.sin_port == port);
}

void known_peer_mark_conn_ack(struct known_peer *peer, uint16_t *count) {
    peer->connection_confirmed = true;
    (*count)++;
}

struct known_peer* known_peer_list_add(struct known_peer **head, in_addr_t ip, uint16_t port) {
    struct known_peer *new_peer = malloc(sizeof(struct known_peer));
    if (new_peer == NULL) {
        syserr("malloc");
        return NULL;
    }

    memset(new_peer, 0, sizeof(*new_peer));
    new_peer->address.sin_family = AF_INET; // IPv4
    new_peer->address.sin_addr.s_addr = ip;
    new_peer->address.sin_port = port;

    new_peer->connection_confirmed = false;
    new_peer->ack_connect_token = false;
    new_peer->delay_response_token = false;
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