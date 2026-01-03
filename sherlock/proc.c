/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/tracee.h>
#include <errno.h>
#include <string.h>

#define PROC_MAPS "/proc/%d/maps"

// Sets the base virtual address of the tracee using proc/<pid>/maps file.
// Returns -1 on failure.
int tracee_proc_mem_maps(tracee_t *tracee)
{
	// read the /proc/pid/maps file and get the PID
	char proc_maps_filename[SHERLOCK_MAX_STRLEN];
	FILE *proc_maps_f = NULL;

	if (snprintf(proc_maps_filename, SHERLOCK_MAX_STRLEN - 1, PROC_MAPS,
		tracee->pid) < 0) {
		pr_err("snprint failed: %s", strerror(errno));
		return -1;
	}

	if ((proc_maps_f = fopen(proc_maps_filename, "r")) == NULL) {
		pr_err("opening pid map file failed: %s", strerror(errno));
		return -1;
	}

	char line[512];
	while (fgets(line, sizeof(line), proc_maps_f)) {
		unsigned long long start, end, offset;
		char perms[5];
		char dev[16];
		unsigned long inode;
		char path[256] = { 0 };

		int n = sscanf(line, "%llx-%llx %4s %llx %15s %lu %255[^\n]",
		    &start, &end, perms, &offset, dev, &inode, path);

		pr_debug("maps: %llx-%llx perms=%s offset=0x%llx dev=%s "
			 "inode=%lu path='%s'",
		    start, end, perms, offset, dev, inode,
		    (n == 7) ? path : "<none>");

		if (n < 6)
			continue;

		if (offset != 0)
			continue;

		if (strcmp(path, tracee->exe_path) != 0)
			continue;

		tracee->va_base = start;
		break;
	}

	pr_debug("start address=%#llx", tracee->va_base);
	fclose(proc_maps_f);
	return 0;
}
