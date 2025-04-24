#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "err.h"

noreturn void syserr(const char* fmt, ...) {
    va_list fmt_args;
    int org_errno = errno;

    fprintf(stderr, "\tERROR: ");

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    fprintf(stderr, " (%d; %s)\n", org_errno, strerror(org_errno));
    exit(1);
}

noreturn void fatal(const char* fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "\tERROR: ");

    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);

    fprintf(stderr, "\n");
    exit(1);
}

void error_msg(char *buf, ssize_t len) {
    ssize_t count = len < 10 ? len : 10;
    // TODO: wypisywanie na standardowe wyjscie diagnostyczne
    printf("ERROR MSG: ");
    for (ssize_t i = 0; i < count; i++) {
        // print each byte as exactly two hex digits
        printf("%02x", buf[i]);
    }
    printf("\n");
}
