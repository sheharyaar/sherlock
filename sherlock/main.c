/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "log.h"
#include "sherlock.h"
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	pr_info("Hello World");
	return 0;
}
