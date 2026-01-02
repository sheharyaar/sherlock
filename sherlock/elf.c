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

static const char *handle_dso_syms(Elf *elf, unsigned int versym_idx,
    Elf_Scn *versym_scn, Elf_Scn *verneed_scn)
{
	Elf_Data *versym_data = elf_getdata(versym_scn, NULL);
	if (!versym_data) {
		pr_err("error in fetching .gnu.version data");
		return NULL;
	}

	GElf_Versym verneed_idx;
	if (gelf_getversym(versym_data, versym_idx, &verneed_idx) == NULL) {
		pr_err("gelf_getversym failed");
		return NULL;
	}

	// 0: local, 1: global (reserved for these)
	if (verneed_idx <= 1) {
		return NULL;
	}

	Elf_Data *verneed_data = elf_getdata(verneed_scn, NULL);
	if (!verneed_data) {
		pr_err("error in fetching .gnu.version_r data");
		return NULL;
	}

	Elf64_Shdr *verneed_hdr = NULL;
	if ((verneed_hdr = elf64_getshdr(verneed_scn)) == NULL) {
		pr_err("error in VERNEED elf64_getshdr(): %s",
		    elf_errmsg(elf_errno()));
		return NULL;
	}

	// Version Structures
	unsigned int offset = 0;
	for (unsigned int i = 0; i < verneed_hdr->sh_info; i++) {
		GElf_Verneed ver_need;
		if (gelf_getverneed(verneed_data, offset, &ver_need) == NULL) {
			pr_err("error in elf_getverneed");
			continue;
		}
		const char *name =
		    elf_strptr(elf, verneed_hdr->sh_link, ver_need.vn_file);

		// Auxiliary version structures, need to match index with this
		// version
		unsigned int verneed_aux_off = offset + ver_need.vn_aux;
		for (int m = 0; m < ver_need.vn_cnt; m++) {
			GElf_Vernaux verneed_aux;
			if (gelf_getvernaux(verneed_data, verneed_aux_off,
				&verneed_aux) == NULL) {
				pr_err("error in gelf_getvernaux");
				continue;
			}

			if (verneed_aux.vna_other == verneed_idx) {
				return name;
			}

			verneed_aux_off += verneed_aux.vna_next;
		}

		offset = ver_need.vn_next;
	}

	return NULL;
}

static int handle_rela_plt(Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr,
    Elf_Scn *versym_scn, Elf_Scn *verneed_scn)
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

		// ignore anything other than func
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) {
			continue;
		}

		// consider only local and global bindings
		if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL &&
		    GELF_ST_BIND(sym.st_info) != STB_LOCAL) {
			continue;
		}

		const char *name =
		    elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);

		const char *lib_name = NULL;
		// Look into dynamic section for verneed and versym tables
		// For dynsym <-> .gnu.version (1:1), so,
		// for symbol i, n = version[i] is the version index
		// and .gnu.version_r[n] is the symbol version
		if (versym_scn && verneed_scn) {
			lib_name = handle_dso_syms(elf, GELF_R_SYM(rela.r_info),
			    versym_scn, verneed_scn);
		} else {
			pr_warn(
			    ".gnu.version or .gnu.version_r sections not "
			    "available, will affect DSO library resolution");
		}

		symbol_t *s = calloc(1, sizeof(*s));
		if (!s) {
			pr_err("calloc for sym failed: %s", strerror(errno));
			return -1;
		}

		s->base = 0; // TODO: handle this change when symbol loads
		// TODO: do I need to handle addend ?
		s->addr = s->base + rela.r_offset;
		s->name = name;
		s->need_plt_resolve = true;
		s->file_name = lib_name;
		s->next = sherlock_symtab;
		sherlock_symtab = s;
		pr_debug("[symbol] name=%s, file=%s, addr=%#llx, base=%#llx",
		    s->name, s->file_name, s->addr, s->base);
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
	char *file_name = NULL;
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

			// if filename is present
			if (GELF_ST_TYPE(sym.st_info) == STT_FILE) {
				file_name =
				    elf_strptr(elf, strtab_idx, sym.st_name);
				if (file_name != NULL && file_name[0] == '\0') {
					file_name = NULL;
				} else {
					pr_debug(
					    "[symbol] file_name=%s", file_name);
				}
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

			// according to the manpage, the file name is only for
			// STB_LOCAL bindings
			if (GELF_ST_BIND(sym.st_info) == STB_LOCAL) {
				s->file_name = file_name;
			}

			s->base = tracee->va_base;
			s->addr = s->base + sym.st_value;
			s->name = name;
			s->need_plt_resolve = false;
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

	size_t shstr_indx;
	if (elf_getshdrstrndx(elf, &shstr_indx) == -1) {
		pr_err(
		    "error in elf_getshdrstrndx: %s", elf_errmsg(elf_errno()));
		goto elf_out;
	}

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;
	Elf_Scn *rela_scn = NULL;
	Elf64_Shdr *rela_hdr = NULL;
	Elf_Scn *versym_scn = NULL;
	Elf_Scn *verneed_scn = NULL;
	Elf_Scn *symtab_scn = NULL;
	Elf64_Shdr *symtab_hdr = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf64_getshdr(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		// iterate over RELA, for each RELA entry check the symtab
		// (hdr->link) and the corresponding strtab for symbol name
		// (symtab_hdr->link)
		if (hdr->sh_type == SHT_RELA) {
			char *name = elf_strptr(elf, shstr_indx, hdr->sh_name);
			if (strcmp(name, ".rela.plt") == 0) {
				rela_scn = scn;
				rela_hdr = hdr;
			}
		}

		// iterate over SYMTAB entries, then check for the strtab
		// (hdr->link) for string table index.
		if (hdr->sh_type == SHT_SYMTAB) {
			symtab_scn = scn;
			symtab_hdr = hdr;
		}

		if (hdr->sh_type == SHT_GNU_versym) {
			versym_scn = scn;
		}

		if (hdr->sh_type == SHT_GNU_verneed) {
			verneed_scn = scn;
		}
	}

	if (!rela_scn || !symtab_scn) {
		pr_err("error in parsing ELF sections");
		goto elf_out;
	}

	if (handle_rela_plt(elf, rela_scn, rela_hdr, versym_scn, verneed_scn) ==
	    -1) {
		pr_err("handling symtab failed");
		goto elf_out;
	}

	if (handle_symtab(tracee, elf, symtab_scn, symtab_hdr) == -1) {
		pr_err("handling symtab failed");
		goto elf_out;
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
