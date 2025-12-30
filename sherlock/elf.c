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

// int elf_plt_init(tracee_t *tracee)
// {
// 	pr_debug("opening and reading file: %s", tracee->file_name);
// 	int fd = open(tracee->file_name, O_RDONLY);
// 	if (fd == -1) {
// 		pr_err("error in open: %s", strerror(errno));
// 		goto err;
// 	}

// 	/* this needs to be called before any elf calls. See freebsd man
// 	 * elf_begin. */
// 	if (elf_version(EV_CURRENT) == EV_NONE) {
// 		pr_err("ELF library too old");
// 		goto out;
// 	}

// 	struct Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
// 	if (elf == NULL) {
// 		pr_err("error in elf_begin: %s", elf_errmsg(elf_errno()));
// 		goto out;
// 	}

// 	size_t shstr_indx;
// 	if (elf_getshdrstrndx(elf, &shstr_indx) == -1) {
// 		pr_err(
// 		    "error in elf_getshdrstrndx: %s", elf_errmsg(elf_errno()));
// 		goto elf_out;
// 	}

// 	size_t n_shdr = 0;
// 	int ret = elf_getshdrnum(elf, &n_shdr);
// 	if (ret == -1) {
// 		pr_err("error in elf_getshdrnum");
// 		goto elf_out;
// 	}

// 	Elf_Scn *scn = NULL;
// 	Elf64_Shdr *hdr = NULL;

// 	Elf_Scn *rela_plt_scn = NULL;
// 	Elf64_Shdr *rela_plt_hdr = NULL;

// 	Elf_Scn *dynsym_scn = NULL;
// 	Elf64_Shdr *dynsym_hdr = NULL;

// 	char *name = NULL;
// 	size_t dynstr_indx;
// 	while ((scn = elf_nextscn(elf, scn)) != NULL) {
// 		if ((hdr = elf64_getshdr(scn)) == NULL) {
// 			pr_err("error in elf_nextscn(): %s",
// 			    elf_errmsg(elf_errno()));
// 			continue;
// 		}

// 		if ((name = elf_strptr(elf, shstr_indx, hdr->sh_name)) ==
// 		    NULL) {
// 			pr_err(
// 			    "error in elf_strptr: %s", elf_errmsg(elf_errno()));
// 			continue;
// 		}

// 		if (strcmp(".rela.plt", name) == 0) {
// 			rela_plt_scn = scn;
// 			rela_plt_hdr = hdr;
// 		}

// 		if (strcmp(".dynsym", name) == 0) {
// 			dynsym_scn = scn;
// 			dynsym_hdr = hdr;
// 		}

// 		if (strcmp(".dynstr", name) == 0) {
// 			dynstr_indx = elf_ndxscn(scn);
// 		}

// 		if (strcmp(".plt", name) == 0) {
// 			if (!plt_sec_found) {
// 				// lets keep the VA for now, then we will add
// 				// base later
// 				tracee->plt_start = hdr->sh_addr;
// 				tracee->plt_end = hdr->sh_addr + hdr->sh_size;
// 				tracee->plt_entsize = hdr->sh_entsize == 0
// 				    ? hdr->sh_addralign
// 				    : hdr->sh_entsize;
// 			}
// 		}

// 		if (strcmp(".plt.sec", name) == 0) {
// 			// lets keep the VA for now, then we will add base later
// 			tracee->plt_start = hdr->sh_addr;
// 			tracee->plt_end = hdr->sh_addr + hdr->sh_size;
// 			tracee->plt_entsize = hdr->sh_entsize == 0
// 			    ? hdr->sh_addralign
// 			    : hdr->sh_entsize;
// 			plt_sec_found = true;
// 			pr_debug(
// 			    "'.plt.sec' found, using it instead of '.plt'");
// 		}
// 	}

// 	pr_debug("relative plt_start=%#llx plt_end=%#llx "
// 		 "plt_entsize=%#llx",
// 	    tracee->plt_start, tracee->plt_end, tracee->plt_entsize);

// 	if (rela_plt_scn == NULL || rela_plt_hdr == NULL ||
// 	    dynsym_scn == NULL || dynsym_hdr == NULL) {
// 		pr_err(".rela.plt or .dynsym section/section header not found "
// 		       "in ELF");
// 		goto elf_out;
// 	}

// 	// .rela.plt section entries
// 	Elf64_Rela *rela = NULL;
// 	Elf_Data *data = elf_getdata(rela_plt_scn, NULL);
// 	if (data == NULL) {
// 		pr_err("error in elf_getdata: %s", elf_errmsg(elf_errno()));
// 		goto elf_out;
// 	}

// 	// for each entry of .rela.plt
// 	rela = data->d_buf;
// 	char *sym_str = NULL;
// 	for (long unsigned i = 0;
// 	    i < MIN(data->d_size / rela_plt_hdr->sh_entsize, MAX_PLT_ENTRIES);
// 	    i++) {
// 		sym_str = get_symbol_name(
// 		    elf, dynsym_scn, dynstr_indx, ELF64_R_SYM(rela[i].r_info));

// 		if (sym_str == NULL) {
// 			pr_err("error in reading PLT symbol value, exiting");
// 			goto elf_out;
// 		}

// 		pr_debug("[SYMBOL]=%s", sym_str);
// 		sym_name[i] = sym_str;
// 	}

// 	// cant use elf_end here as the string pointers are in use.
// 	return 0;

// elf_out:
// 	elf_end(elf);
// out:
// 	close(fd);
// err:
// 	return -1;
// }