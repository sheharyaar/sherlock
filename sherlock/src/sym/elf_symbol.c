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

static int sherlock_sym_cmp(const symbol_t *a, const symbol_t *b)
{
	return (symbol_t *)a->addr - (symbol_t *)b->addr; // Ascending order
}

static void sym_freeall(void)
{
	symbol_t *s = sherlock_symtab;
	symbol_t *t = NULL;
	while (s != NULL) {
		t = s;
		s = s->next;
		free(t);
	}
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

static int handle_syms(
    tracee_t *tracee, Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
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

			// skip non function entries
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) {
				continue;
			}

			const char *name =
			    elf_strptr(elf, strtab_idx, sym.st_name);

			symbol_t *new_sym = calloc(1, sizeof(*new_sym));
			if (!new_sym) {
				pr_err("calloc for sym failed: %s",
				    strerror(errno));
				return -1;
			}

			if (sym.st_shndx == SHN_UNDEF || sym.st_value == 0) {
				// lazy load ?
				// TODO: handle ifunc ?
				SHERLOCK_SYMBOL(new_sym, 0UL,
				    0UL + sym.st_value, name, NULL);
			} else {
				// static symbols
				SHERLOCK_SYMBOL(new_sym, tracee->va_base,
				    tracee->va_base + sym.st_value, name, NULL);

				// according to the manpage, the file name is
				// only for STB_LOCAL bindings
				if (GELF_ST_BIND(sym.st_info) == STB_LOCAL) {
					new_sym->file_name = file_name;
				}
			}

			new_sym->next = sherlock_symtab;
			sherlock_symtab = new_sym;
			pr_debug("[symbol] name=%s, addr=%#llx, base=%#llx, "
				 "file_name=%s",
			    new_sym->name, new_sym->addr, new_sym->base,
			    new_sym->file_name);
		}
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

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;

	Elf_Scn *symtab_scn = NULL;
	Elf64_Shdr *symtab_hdr = NULL;

	Elf_Scn *dynsym_scn = NULL;
	Elf64_Shdr *dynsym_hdr = NULL;

	unsigned long plt_base = 0;
	unsigned long plt_sec_base = 0;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf64_getshdr(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		char *name = elf_strptr(elf, shstr_indx, hdr->sh_name);
		// iterate over RELA, for each RELA entry check the symtab
		// (hdr->link) and the corresponding strtab for symbol name
		// (symtab_hdr->link)

		if (MATCH_STR(name, .plt.sec)) {
			plt_sec_base = hdr->sh_addr;
		}

		if (MATCH_STR(name, .plt)) {
			plt_base = hdr->sh_addr;
		}

		if (MATCH_STR(name, .dynsym)) {
			dynsym_scn = scn;
			dynsym_hdr = hdr;
		}

		if (MATCH_STR(name, .symtab)) {
			symtab_scn = scn;
			symtab_hdr = hdr;
		}
	}

	// Finalise the symbol section
	Elf_Scn *sym_scn;
	Elf64_Shdr *sym_hdr;
	if (symtab_scn == NULL) {
		if (dynsym_scn == NULL) {
			pr_warn("both dynsym and symtab not present, willa "
				"ffect symbol resolution");
		} else {
			// dynsym to be used for sym res
			sym_scn = dynsym_scn;
			sym_hdr = dynsym_hdr;
		}
	} else {
		// symtab to be used for sym res, dynsym is a subset of symtab
		sym_scn = symtab_scn;
		sym_hdr = symtab_hdr;
	}

	if (handle_syms(tracee, elf, sym_scn, sym_hdr) == -1) {
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

int sym_lookup(char *name, symbol_t ***sym_list)
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

void sym_cleanup()
{
	if (sherlock_symtab != NULL)
		sym_freeall();

	if (elf != NULL)
		elf_end(elf);
}
