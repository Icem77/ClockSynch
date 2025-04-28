#ifndef TIME_H
#define TIME_H

#include <stdint.h>

#define SYNC_START_INTERVAL_MS 5000
#define SYNC_PEER_TIMEOUT_MS 20000
#define DELAY_RESPONSE_TIMEOUT_MS 5000
#define DELAY_REQUEST_TIMEOUT_MS 5000
#define LEADER_PRIVILEGE_SYNC_START_MS 2000

uint64_t current_time_ms(void);

uint64_t time_since_ms(uint64_t start_time_ms);

#endif