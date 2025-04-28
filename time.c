#include <time.h> 
#include <stdint.h>

#include "time.h"

uint64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    // Konwersja seconds -> ms & nanoseconds -> ms
    uint64_t ms = (uint64_t)ts.tv_sec * 1000
                + (uint64_t)(ts.tv_nsec / 1000000);
    return ms;
}

uint64_t time_since_ms(uint64_t start_time_ms) {
    return current_time_ms() - start_time_ms;
}