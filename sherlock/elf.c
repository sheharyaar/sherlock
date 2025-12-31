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
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define PROC_MAPS "/proc/%d/maps"

static symbol_t *sherlock_symtab = NULL;

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

static int handle_rela(Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	// consider only non-dynamically linked functions, i.e,
	// offset != 0, type == FUNC, indx != UND
	unsigned long symtab_idx = hdr->sh_link;
	if (symtab_idx == 0) {
		pr_err("invalid string table for rela section");
		return -1;
	}

	Elf_Scn *symtab_scn = elf_getscn(elf, hdr->sh_link);
	if (symtab_scn == NULL) {
		pr_err("failed to get dynsym section");
		return -1;
	}

	GElf_Shdr symtab_shdr;
	if (gelf_getshdr(symtab_scn, &symtab_shdr) == NULL) {
		pr_err("error in getching dynsym header");
		return -1;
	}

	Elf_Data *rela_data = elf_getdata(scn, NULL);
	Elf_Data *sym_data = elf_getdata(symtab_scn, NULL);
	size_t rela_count = hdr->sh_size / hdr->sh_entsize;

	for (size_t i = 0; i < rela_count; i++) {
		GElf_Rela rela;
		if (gelf_getrela(rela_data, i, &rela) == NULL) {
			pr_err("error in getting symbol from symtab at "
			       "index %ld",
			    i);
			return -1;
		}

		// only consider jump slots
		if (GELF_R_TYPE(rela.r_info) != R_X86_64_JUMP_SLOT) {
			continue;
		}

		// fetch the symbol
		GElf_Sym sym;
		if (gelf_getsym(sym_data, GELF_R_SYM(rela.r_info), &sym) ==
		    NULL) {
			pr_err("error in fetching symbol for the rela entry");
			return -1;
		}

		const char *name =
		    elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);

		symbol_t *s = calloc(1, sizeof(*s));
		if (!s) {
			pr_err("calloc for sym failed: %s", strerror(errno));
			return -1;
		}

		s->base = 0;
		// TODO: do I need ot handle addend ?
		s->addr = s->base + rela.r_offset;
		s->name = name;
		s->next = sherlock_symtab;
		sherlock_symtab = s;
		pr_debug("[symbol] name=%s, addr=%#llx, base=%#llx", s->name,
		    s->addr, s->base);
	}

	return 0;
}

static int handle_symtab(
    tracee_t *tracee, Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	// consider only non-dynamically linked functions, i.e,
	// offset != 0, type == FUNC, indx != UND
	unsigned long strtab_idx = hdr->sh_link;
	if (strtab_idx == 0) {
		pr_err("invalid string table for symtab section");
		return -1;
	}

	Elf_Data *data = NULL;
	while ((data = elf_getdata(scn, data)) != NULL) {
		size_t count = hdr->sh_size / hdr->sh_entsize;

		for (size_t i = 0; i < count; i++) {
			GElf_Sym sym;
			if (gelf_getsym(data, i, &sym) == NULL) {
				pr_err("error in getting symbol from symtab at "
				       "index %ld",
				    i);
				return -1;
			}

			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC ||
			    sym.st_shndx == SHN_UNDEF || sym.st_value == 0) {
				continue;
			}

			// consider only local and global bindings
			if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL &&
			    GELF_ST_BIND(sym.st_info) != STB_LOCAL) {
				continue;
			}

			const char *name =
			    elf_strptr(elf, strtab_idx, sym.st_name);

			symbol_t *s = calloc(1, sizeof(*s));
			if (!s) {
				pr_err("calloc for sym failed: %s",
				    strerror(errno));
				return -1;
			}

			s->base = tracee->va_base;
			s->addr = s->base + sym.st_value;
			s->name = name;
			s->next = sherlock_symtab;
			sherlock_symtab = s;
			pr_debug("[symbol] name=%s, addr=%#llx, base=%#llx",
			    s->name, s->addr, s->base);
		}
	}

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

		// iterate over RELA, for each RELA entry check the symtab
		// (hdr->link) and the corresponding strtab for symbol name
		// (symtab_hdr->link)
		if (hdr->sh_type == SHT_RELA) {
			pr_debug("handling rela");
			if (handle_rela(elf, scn, hdr) == -1) {
				pr_err("handling symtab failed");
				goto elf_out;
			}
		}

		// iterate over SYMTAB entries, then check for the strtab
		// (hdr->link) for string table index.
		if (hdr->sh_type == SHT_SYMTAB) {
			pr_debug("handling symtab");
			if (handle_symtab(tracee, elf, scn, hdr) == -1) {
				pr_err("handling symtab failed");
				goto elf_out;
			}
		}
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

int elf_sym_lookup(char *name, symbol_t ***sym_list)
{
	symbol_t *s = sherlock_symtab;
	symbol_t **s_list = NULL;
	int count = 0;
	while (s != NULL) {
		if (strcmp(s->name, name) == 0) {
			s_list =
			    realloc(s_list, (count + 1) * sizeof(symbol_t *));
			if (!s_list) {
				pr_err("error in realloc: %s", strerror(errno));
				free(s_list);
				return -1;
			}
			// dont need count - 1 as count is incremented later
			s_list[count] = s;
			count++;
		}
		s = s->next;
	}

	*sym_list = s_list;
	return count;
}
