#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "err.h"

void syserr(const char* fmt, ...) {
    va_list fmt_args;
    int org_errno = errno;

    fprintf(stderr, "\tERROR: ");

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    fprintf(stderr, " (%d; %s)\n", org_errno, strerror(org_errno));
}

void error_msg(char *buf, ssize_t len) {
    ssize_t count = len < 10 ? len : 10;
    fprintf(stderr, "ERROR MSG: ");
    for (ssize_t i = 0; i < count; i++) {
        fprintf(stderr, "%02x", (unsigned char)buf[i]);
    }
    fprintf(stderr, "\n");   // teraz też stderr
}
