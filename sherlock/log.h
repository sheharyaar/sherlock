/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

#ifdef NOCOLORS
#define COLOR_ERR ""
#define COLOR_INF ""
#define COLOR_DEBUG ""
#define COLOR_RESET ""
#define COLOR_WARN ""
#else
#define COLOR_ERR "\033[1;31m"
#define COLOR_WARN "\033[1;38;5;208m"
#define COLOR_INF "\033[1;32m"
#define COLOR_DEBUG "\033[1;36m"
#define COLOR_RESET "\033[0m"
#endif

#define PREFIX_ERR COLOR_ERR "[ERR]" COLOR_RESET " "
#define PREFIX_WARN COLOR_WARN "[WARN]" COLOR_RESET " "
#define PREFIX_INF COLOR_INF "[INF]" COLOR_RESET " "
#define PREFIX_DEBUG COLOR_DEBUG "[DEBUG]" COLOR_RESET " "

#define pr_err(fmt, ...) fprintf(stderr, PREFIX_ERR fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) fprintf(stdout, PREFIX_INF fmt "\n", ##__VA_ARGS__)
#define pr_info_raw(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) fprintf(stderr, PREFIX_WARN fmt "\n", ##__VA_ARGS__)

#define DEBUG 1
#if DEBUG
#define pr_debug(fmt, ...) fprintf(stdout, PREFIX_DEBUG fmt "\n", ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...)                                                     \
	do {                                                                   \
	} while (0)
#endif

#define DBG_PREFIX COLOR_INF "dbg>" COLOR_RESET " "

#define ERR_RET_MSG(err, msg, ...)                                             \
	do {                                                                   \
		pr_debug(msg, ##__VA_ARGS__);                                  \
		errno = err;                                                   \
		return -1;                                                     \
	} while (0)

#endif