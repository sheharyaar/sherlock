/*
 * Irene - Library call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_CALL "\033[1;32m"

#define pr_library_call(func, arg1, arg2, arg3, arg4)                          \
	fprintf(stdout,                                                        \
	    COLOR_CALL "%s" COLOR_RESET "(%#llx, %#llx, %#llx, %#llx)\n",      \
	    func, arg1, arg2, arg3, arg4)
#define pr_err(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) fprintf(stdout, "[INF] " fmt "\n", ##__VA_ARGS__)
#define pr_info_raw(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, "[WRN] " fmt "\n", ##__VA_ARGS__)

#if DEBUG
#define pr_debug(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...)                                                     \
	do {                                                                   \
	} while (0)
#endif

#endif