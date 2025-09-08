#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

#define pr_err(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) fprintf(stdout, "[INF] " fmt "\n", ##__VA_ARGS__)
#define pr_info_raw(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, "[WRN] " fmt "\n", ##__VA_ARGS__)

#if DEBUG
#define pr_debug(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) \
	do {               \
	} while (0)
#endif

#endif