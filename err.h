#ifndef MIM_ERR_H
#define MIM_ERR_H

// Print information about a system error and quits.
void syserr(const char* fmt, ...);

void error_msg(char *buf, ssize_t len);

#endif
