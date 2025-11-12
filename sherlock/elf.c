#include "sherlock.h"
#include <string.h>
#include <errno.h>

#define PROC_MAPS "/proc/%d/maps"

// Sets the base virtual address of the tracee using proc/<pid>/maps file.
// Returns -1 on failure.
int elf_mem_va_base(tracee_t *tracee)
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

	unsigned long long start = 0, end = 0;
	if (fscanf(proc_maps_f, "%64llx-%64llx ", &start, &end) == EOF) {
		pr_err("error in fscanf: %s", strerror(ferror(proc_maps_f)));
		fclose(proc_maps_f);
		return -1;
	}

	tracee->va_base = start;
	pr_debug("start address=%#llx", tracee->va_base);
	fclose(proc_maps_f);
	return 0;
}