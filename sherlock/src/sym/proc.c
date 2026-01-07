/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */
#define _XOPEN_SOURCE 700
#include <sherlock/sym.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define PROC_MAPS "/proc/%d/maps"
#define PROC_COMM "/proc/%d/comm"
#define PROC_EXE "/proc/%d/exe"

static mem_map_t *memmap_list = NULL;
unsigned int memmap_idx = 0;

mem_map_t *sym_proc_addr_map(unsigned long long addr, unsigned long long size)
{
	for (unsigned int i = 0; i < memmap_idx; i++) {
		if (addr >= memmap_list[i].start &&
		    addr + size <= memmap_list[i].end) {
			return &memmap_list[i];
		}
	}

	return NULL;
}

// Sets the base virtual address of the tracee using proc/<pid>/maps file.
// Returns -1 on failure.
int sym_proc_map_setup(tracee_t *tracee)
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
	unsigned int idx = 0;
	while (fgets(line, sizeof(line), proc_maps_f)) {
		unsigned long long start, end, offset;
		char perms[5];
		char dev[16];
		unsigned long inode;
		char path[256] = { 0 };

		int n = sscanf(line, "%llx-%llx %4s %llx %15s %lu %255[^\n]",
		    &start, &end, perms, &offset, dev, &inode, path);

		pr_debug("[map] %llx-%llx perms=%s offset=0x%llx dev=%s "
			 "inode=%lu path='%s'",
		    start, end, perms, offset, dev, inode,
		    (n == 7) ? path : "<none>");

		// won't keep memory maps without a name
		if (n < 7)
			continue;

		// store the mapping into the memory map array
		mem_map_t *m =
		    realloc(memmap_list, (idx + 1) * sizeof(mem_map_t));
		if (m == NULL) {
			pr_err("error in realloc memmap_list: %s",
			    strerror(errno));

			if (memmap_list != NULL) {
				free(memmap_list);
				memmap_list = NULL;
			}

			return -1;
		} else {
			memmap_list = m;
		}

		memmap_list[idx].start = start;
		memmap_list[idx].end = end;
		// ignoring stncpy returned values for now
		strncpy(memmap_list[idx].path, path, 255);
		memmap_list[idx].path[SHERLOCK_MAX_STRLEN - 1] = '\0';
		++idx;

		if (offset != 0 || strcmp(path, tracee->exe_path) != 0)
			continue;

		tracee->va_base = start;
	}

	memmap_idx = idx;
	pr_debug("start address=%#llx", tracee->va_base);
	fclose(proc_maps_f);
	return 0;
}

// Reads the /proc/<PID>/cmdline file and sets the tracee executable name.
// Returns -1 on error.
static int get_pid_cmdline(tracee_t *tracee)
{
	// get the name of the file
	char name[SHERLOCK_MAX_STRLEN];
	char cmdline_file[SHERLOCK_MAX_STRLEN];
	FILE *cmdline_f = NULL;

	if (snprintf(cmdline_file, SHERLOCK_MAX_STRLEN, PROC_COMM,
		tracee->pid) < 0) {
		pr_err("snprint failed: %s", strerror(errno));
		return -1;
	}

	if ((cmdline_f = fopen(cmdline_file, "r")) == NULL) {
		pr_err("opening pid map file failed: %s", strerror(errno));
		return -1;
	}

	if (fscanf(cmdline_f, "%s ", name) == EOF) {
		pr_err("error in fscanf: %s", strerror(ferror(cmdline_f)));
		if (errno == ENOMEM) {
			pr_warn("a possible reason can be that the "
				"/proc/%d/cmdline is more than %d bytes",
			    tracee->pid, SHERLOCK_MAX_STRLEN);
		}
		fclose(cmdline_f);
		return -1;
	}

	strncpy(tracee->name, name, SHERLOCK_MAX_STRLEN);
	tracee->name[SHERLOCK_MAX_STRLEN - 1] = '\0';

	fclose(cmdline_f);
	return 0;
}

// Reads the /proc/<PID>/exe link and sets the tracee executable path.
// Returns -1 on error.
static int get_pid_exe_name(tracee_t *tracee)
{
	// get the name of the file
	char exe_link_file[SHERLOCK_MAX_STRLEN];

	if (snprintf(exe_link_file, SHERLOCK_MAX_STRLEN, PROC_EXE,
		tracee->pid) < 0) {
		pr_err("snprint failed: %s", strerror(errno));
		return -1;
	}

	if (readlink(exe_link_file, tracee->exe_path,
		SHERLOCK_MAX_STRLEN - 1) == -1) {
		pr_err("readlink failed: %s", strerror(errno));
		return -1;
	}

	tracee->exe_path[SHERLOCK_MAX_STRLEN - 1] = '\0';
	return 0;
}

int sym_proc_pid_info(tracee_t *tracee)
{
	// get the cmdline name of the process
	if (get_pid_cmdline(tracee) == -1) {
		pr_err("error in get_pid_cmdline");
		return -1;
	}
	pr_debug("pid cmdline: %s", tracee->name);

	if (get_pid_exe_name(tracee) == -1) {
		pr_err("error in get_pid_exe_name");
		return -1;
	}
	pr_debug("pid exe name: %s", tracee->exe_path);
	return 0;
}

void proc_cleanup(__attribute__((unused)) tracee_t *tracee)
{
	if (memmap_list != NULL) {
		free(memmap_list);
		memmap_list = NULL;
	}
}