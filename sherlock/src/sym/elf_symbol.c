/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "sym_internal.h"
#include <fcntl.h>
#include <unistd.h>

static symbol_t *sherlock_symtab = NULL;
struct Elf *elf = NULL;

static void sym_freeall(void)
{
	symbol_t *s = sherlock_symtab;
	symbol_t *t = NULL;
	while (s != NULL) {
		t = s;
		s = s->next;
		free(t);
	}

	sherlock_symtab = NULL;
}

void sym_printall()
{
	symbol_t *s = sherlock_symtab;
	int i = 0;
	while (s != NULL) {
		pr_info_raw(
		    "[%d] name=%s, addr=%#llx, base=%#llx, file_name=%s\n", i,
		    s->name, s->addr, s->base, s->file_name);
		s = s->next;
		i++;
	}
}

static int handle_dynamic_syms(
    tracee_t *tracee, Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	// iterate over RELA, for each RELA entry check the symtab
	// (hdr->link) and the corresponding strtab for symbol name
	// (symtab_hdr->link)
	unsigned long symtab_idx = hdr->sh_link;
	if (symtab_idx == 0) {
		pr_err("invalid symtan for dynamic section");
		return -1;
	}

	Elf_Scn *symtab_scn = elf_getscn(elf, symtab_idx);
	if (symtab_scn == NULL) {
		pr_err("error in getting dynamic symtab");
		return -1;
	}

	Elf64_Shdr *symtab_hdr = elf64_getshdr(symtab_scn);
	if (symtab_hdr == NULL) {
		pr_err("error in getting dynamic symtab header");
		return -1;
	}

	unsigned long strtab_idx = symtab_hdr->sh_link;
	if (strtab_idx == 0) {
		pr_err("invalid string table index for dynamic symtab");
		return -1;
	}

	Elf_Data *rela_data = elf_getdata(scn, NULL);
	if (rela_data == NULL) {
		pr_err("error in getting rela data");
		return -1;
	}

	Elf_Data *symtab_data = elf_getdata(symtab_scn, NULL);
	if (symtab_data == NULL) {
		pr_err("error in getting rela data");
		return -1;
	}

	size_t count = hdr->sh_size / hdr->sh_entsize;

	for (size_t i = 0; i < count; i++) {
		GElf_Rela rela;
		if (gelf_getrela(rela_data, i, &rela) == NULL) {
			pr_err("error in getting rela entry at "
			       "index %ld",
			    i);
			return -1;
		}

		unsigned long sym_idx = GELF_R_SYM(rela.r_info);
		GElf_Sym sym;
		if (gelf_getsym(symtab_data, sym_idx, &sym) == NULL) {
			pr_err("error in getting symbol from dynamic symtab");
			return -1;
		}

		// skip non function symbols
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) {
			continue;
		}

		bool plt_patch = false;
		if (GELF_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT) {
			// Patching + Resolve Probing would happen only when
			// breakpoint will be added via 'break func <symbol>'
			// and before resoltion happens. After the resolution
			// subsequent breaks will be added directly to the value
			// in GOT.
			plt_patch = true;
		} else {
			// TODO: implement R_X86_64_GLOB_DAT or RELATIVE
			pr_err("type: %ld not implemented",
			    GELF_R_TYPE(rela.r_info));
			continue;
		}

		const char *name = elf_strptr(elf, strtab_idx, sym.st_name);
		if (name == NULL || name[0] == '\0') {
			pr_err("dynamic symbol name not present");
			return -1;
		}

		symbol_t *new_sym = calloc(1, sizeof(*new_sym));
		if (!new_sym) {
			pr_err("calloc for sym failed: %s", strerror(errno));
			return -1;
		}

		// dynamic symbols, file_name will be set after address gets
		// resolved.
		SHERLOCK_SYMBOL_DYN(new_sym, tracee->va_base,
		    tracee->va_base + rela.r_offset + rela.r_addend, name,
		    plt_patch);

		new_sym->next = sherlock_symtab;
		sherlock_symtab = new_sym;
		pr_debug("[dynamic symbol] name=%s, addr=%#llx, "
			 "base=%#llx",
		    new_sym->name, new_sym->addr, new_sym->base);
	}

	return 0;
}

static int handle_static_syms(
    tracee_t *tracee, Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	unsigned long strtab_idx = hdr->sh_link;
	if (strtab_idx == 0) {
		pr_err("invalid string table for symtab section");
		return -1;
	}

	char *file_name = NULL;
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL) {
		pr_err("error in getting symtab data");
		return -1;
	}

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
			file_name = elf_strptr(elf, strtab_idx, sym.st_name);
			if (file_name != NULL && file_name[0] == '\0') {
				file_name = NULL;
			} else {
				pr_debug("[symbol] file_name=%s", file_name);
			}
		}

		// skip non-funciton and non-static func entries
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC ||
		    sym.st_value == 0) {
			continue;
		}

		const char *name = elf_strptr(elf, strtab_idx, sym.st_name);
		if (name == NULL || name[0] == '\0') {
			pr_err("static symbol name not present");
			return -1;
		}

		symbol_t *new_sym = calloc(1, sizeof(*new_sym));
		if (!new_sym) {
			pr_err("calloc for sym failed: %s", strerror(errno));
			return -1;
		}

		// static symbols
		SHERLOCK_SYMBOL_STATIC(new_sym, tracee->va_base,
		    tracee->va_base + sym.st_value, sym.st_size, name, NULL);

		// according to the manpage, the file name is
		// only for STB_LOCAL bindings
		if (GELF_ST_BIND(sym.st_info) == STB_LOCAL) {
			new_sym->file_name = file_name;
		} else {
			// resolve name based on memory maps
			mem_map_t *map = sym_proc_addr_map(new_sym->addr);
			if (map != NULL) {
				new_sym->file_name = map->path;
			}
		}

		new_sym->next = sherlock_symtab;
		sherlock_symtab = new_sym;
		pr_debug("[symbol] name=%s, size=%#llx, addr=%#llx, "
			 "base=%#llx, file_name=%s",
		    new_sym->name, new_sym->size, new_sym->addr, new_sym->base,
		    new_sym->file_name);
	}

	return 0;
}

int sym_setup(tracee_t *tracee)
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

	elf = elf_begin(fd, ELF_C_READ, NULL);
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

	Elf64_Ehdr *elf_hdr = elf64_getehdr(elf);
	if (elf_hdr == NULL) {
		pr_err("error in getting ELF header");
		goto elf_out;
	}

	// IMP: If the type of ELF is EXEC, then va_base will be 0 (No ASLR)
	if (elf_hdr->e_type == ET_EXEC) {
		tracee->va_base = 0UL;
	} else {
		if (elf_hdr->e_type != ET_DYN) {
			pr_err("this binary is neither EXEC or DYN type, other "
			       "types are not supported as of now");
			goto elf_out;
		}
	}

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;

	unsigned long plt_base = 0;
	unsigned long plt_sec_base = 0;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf64_getshdr(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		char *name = elf_strptr(elf, shstr_indx, hdr->sh_name);

		if (MATCH_STR(name, .plt.sec)) {
			plt_sec_base = hdr->sh_addr;
		}

		if (MATCH_STR(name, .plt)) {
			plt_base = hdr->sh_addr;
		}

		if (hdr->sh_type == SHT_RELA) {
			if (handle_dynamic_syms(tracee, elf, scn, hdr) == -1) {
				pr_err("handling symtab failed");
				goto syms_out;
			}
		}

		if (MATCH_STR(name, .symtab)) {
			if (handle_static_syms(tracee, elf, scn, hdr) == -1) {
				pr_err("handling symtab failed");
				goto syms_out;
			}
		}
	}

	// cant use elf_end here as the string pointers are in use.
	return 0;

syms_out:
	if (sherlock_symtab != NULL) {
		sym_freeall();
	}
elf_out:
	elf_end(elf);
	elf = NULL;
out:
	close(fd);
err:
	return -1;
}

int sym_lookup(char *name, symbol_t ***sym_list)
{
	symbol_t *s = sherlock_symtab;
	symbol_t **s_list = NULL;
	int count = 0;
	while (s != NULL) {
		if (strcmp(s->name, name) == 0) {
			symbol_t **s_list_tmp =
			    realloc(s_list, (count + 1) * sizeof(symbol_t *));
			if (!s_list_tmp) {
				pr_err("error in realloc: %s", strerror(errno));
				free(s_list);
				s_list = NULL;
				return -1;
			} else {
				s_list = s_list_tmp;
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

void sym_cleanup(__attribute__((unused)) tracee_t *tracee)
{
	pr_debug("sym cleanup");
	if (sherlock_symtab != NULL) {
		sym_freeall();
	}

	if (elf != NULL) {
		elf_end(elf);
		elf = NULL;
	}

	proc_cleanup(tracee);
}
