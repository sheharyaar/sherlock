/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "sherlock.h"
#include <string.h>
#include <errno.h>
#include <libelf.h>
#include <fcntl.h>
#include <unistd.h>

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

int elf_setup_syms(tracee_t *tracee)
{
	pr_debug("opening and reading file: %s", tracee->exe_path);
	int fd = open(tracee->exe_path, O_RDONLY);
	if (fd == -1) {
		pr_err("error in open: %s", strerror(errno));
		goto err;
	}

	/* this needs to be called before any elf calls. See freebsd man
	 * elf_begin. */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_err("ELF library too old");
		goto out;
	}

	struct Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		pr_err("error in elf_begin: %s", elf_errmsg(elf_errno()));
		goto out;
	}

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf_nextscn(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		// TODO:
		// iterate over RELA, for each RELA entry check the symtab
		// (hdr->link) and the corresponding strtab for symbol name
		// (symtab_hdr->link)

		// iterate over SYMTAB entries, then check for the strtab
		// (hdr->link) for name. only consider type FUNC, with
		// GLOBAL/LOCAL
	}

	// cant use elf_end here as the string pointers are in use.
	return 0;

elf_out:
	elf_end(elf);
out:
	close(fd);
err:
	return -1;
}
