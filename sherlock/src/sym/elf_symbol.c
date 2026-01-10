/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "sym_internal.h"
#include <fcntl.h>
#include <link.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sherlock/breakpoint.h>

static symbol_t *sherlock_symtab = NULL;
static section_t *section_list = NULL;
static unsigned int section_count = 0;
static bool plt_sec = false;
static unsigned long long plt_ent_start = 0UL;
static unsigned long long plt_entsize = 0UL;
struct Elf *elf = NULL;

section_t *sym_addr_section(unsigned long long addr, unsigned long long size)
{
	for (unsigned int i = 0; i < section_count; i++) {
		if (addr >= section_list[i].start &&
		    addr + size <= section_list[i].end) {
			return &section_list[i];
		}
	}

	return NULL;
}

static int sym_sort_cmp(void *a, void *b)
{
	// decreasing order of addresses for easier overlapping interval calc
	return ((symbol_t *)b)->addr - ((symbol_t *)a)->addr;
}

void sym_sort_trigger() { HASH_SORT(sherlock_symtab, sym_sort_cmp); }

static void sym_freeall(void)
{
	symbol_t *sym, *tmp;
	HASH_ITER(hh, sherlock_symtab, sym, tmp)
	{
		HASH_DEL(sherlock_symtab, sym);
		free(sym);
	}

	sherlock_symtab = NULL;
}

void sym_printall(__attribute__((unused)) tracee_t *tracee)
{
	symbol_t *s, *tmp;
	int i = 0;
	HASH_ITER(hh, sherlock_symtab, s, tmp)
	{
		if (s->dyn_sym) {
			pr_info_raw("[%d] name=%s, addr=%#llx, got_val=%#llx, "
				    "file_name=%s\n",
			    i, s->name, s->addr, s->got.val, s->file_name);
		} else {
			pr_info_raw("[%d] name=%s, addr=%#llx, base=%#llx, "
				    "file_name=%s\n",
			    i, s->name, s->addr, s->base, s->file_name);
		}
		i++;
	}
}

int sym_resolve_dyn(tracee_t *tracee)
{
	symbol_t *sym, *t;
	HASH_ITER(hh, sherlock_symtab, sym, t)
	{
		if (!sym->dyn_sym || !sym->needs_resolve) {
			continue;
		}

		long res_addr =
		    ptrace(PTRACE_PEEKDATA, tracee->pid, sym->got.addr, 0);
		if (res_addr == -1 || res_addr == 0) {
			pr_err("error in reading GOT address : %s",
			    strerror(errno));
			return -1;
		}

		pr_debug("[DL CHECK] sym=%s, got_addr=%#llx, got_val=%#llx,  "
			 "new_val=%#lx",
		    sym->name, sym->got.addr, sym->got.val, res_addr);

		if (sym->got.val == (unsigned long)res_addr) {
			continue;
		}

		sym->got.val = res_addr;
		// for PLT, we cant update the address, it will point to PLT[i]
		// + 6
		if (sym->addr != 0) {
			continue;
		}

		SYM_UPDATE_ADDR(sym, res_addr);

		pr_debug("[DL LOAD] symbol=%s, new_addr=%#llx", sym->name,
		    sym->addr);

		if (sym->bp != NULL) {
			if (breakpoint_update(tracee, sym->bp, sym->addr) ==
			    -1) {
				pr_err("error in updating breakpoint");
				return -1;
			}
		}

		// TODO: create a new @plt sym and add to hashlist
	}

	HASH_SORT(sherlock_symtab, sym_sort_cmp);
	return 0;
}

static int handle_dynamic_syms(__attribute__((unused)) tracee_t *tracee,
    Elf *elf, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	// iterate over RELA, for each RELA entry check the symtab
	// (hdr->link) and the corresponding strtab for symbol name
	// (symtab_hdr->link)
	unsigned long symtab_idx = hdr->sh_link;
	if (symtab_idx == 0) {
		// this is probably a static binary
		return 0;
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

		unsigned long long base = 0UL;
		unsigned long long addr = 0UL;
		if (GELF_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT) {
			addr = plt_ent_start + plt_entsize * i;
		} else if (GELF_R_TYPE(rela.r_info) == R_X86_64_GLOB_DAT) {
			addr = tracee->va_base + rela.r_offset;
		} else {
			// TODO [SYM_RES]: implement  RELATIVE
			pr_err("type: %ld not implemented",
			    GELF_R_TYPE(rela.r_info));
			continue;
		}

		const char *name = elf_strptr(elf, strtab_idx, sym.st_name);
		if (name == NULL || name[0] == '\0') {
			pr_err("dynamic symbol name not present");
			return -1;
		}

		long got_val = ptrace(PTRACE_PEEKTEXT, tracee->pid,
		    tracee->va_base + rela.r_offset, 0);
		if (got_val == -1) {
			pr_err("error in getting GOT val for sym(%s): %s", name,
			    strerror(errno));
			return -1;
		}

		symbol_t *new_sym = calloc(1, sizeof(*new_sym));
		if (!new_sym) {
			pr_err("calloc for sym failed: %s", strerror(errno));
			return -1;
		}

		// dynamic symbols, file_name will be set after address
		// gets resolved.
		SHERLOCK_SYMBOL_DYN(new_sym, base, addr,
		    tracee->va_base + rela.r_offset, got_val, name);
		if (GELF_R_TYPE(rela.r_info) == R_X86_64_GLOB_DAT) {
			new_sym->addr = 0;
		}

		pr_debug("[dynamic symbol] name=%s, addr=%#llx, "
			 "base=%#llx, section=%s",
		    new_sym->name, new_sym->addr, new_sym->base,
		    new_sym->section->name);
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

		// skip undefined section index
		if (sym.st_shndx == SHN_UNDEF) {
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
		    tracee->va_base + sym.st_value, sym.st_size, name);

		// according to the manpage, the file name is
		// only for STB_LOCAL bindings
		if (GELF_ST_BIND(sym.st_info) == STB_LOCAL)
			new_sym->file_name = file_name;

		pr_debug("[symbol] name=%s, size=%#llx, addr=%#llx, "
			 "base=%#llx, file_name=%s, section=%s",
		    new_sym->name, new_sym->size, new_sym->addr, new_sym->base,
		    new_sym->file_name, new_sym->section->name);
	}

	return 0;
}

static int handle_dyn_linker(tracee_t *tracee, Elf_Scn *scn, Elf64_Shdr *hdr)
{
	// Read DT_DEBUG value from dynamic section
	Elf_Data *dyn_data = elf_getdata(scn, NULL);
	if (!dyn_data) {
		pr_err("error in reading .dynamic section data: %s",
		    elf_errmsg(elf_errno()));
		return -1;
	}

	unsigned long dyn_debug_off = 0UL;

	GElf_Dyn dyn_ent;
	int count = hdr->sh_size / hdr->sh_entsize;
	for (int i = 0; i < count; i++) {
		if (gelf_getdyn(dyn_data, i, &dyn_ent) == NULL) {
			pr_err(
			    "error in getting .dynamic data at index(%i)", i);
			return -1;
		}

		if (dyn_ent.d_tag == DT_DEBUG) {
			dyn_debug_off =
			    (i * hdr->sh_entsize) + offsetof(Elf64_Dyn, d_un);
			break;
		}
	}

	if (dyn_debug_off == 0) {
		pr_err("DYNAMIC tag not found in .dynamic section");
		return -1;
	}

	unsigned long dyn_debug_addr =
	    tracee->va_base + hdr->sh_addr + dyn_debug_off;

	// read the data, if addr != 0 then do not add watchpoint, directly
	// handle the debug structure (in cases of already running tracee)
	long dyn_debug_data =
	    ptrace(PTRACE_PEEKDATA, tracee->pid, dyn_debug_addr, NULL);
	if (dyn_debug_data == -1) {
		pr_err("error in reading DT_DEBUG data in memory (%#lx): %s",
		    dyn_debug_addr, strerror(errno));
		return -1;
	}

	if (dyn_debug_data != 0) {
		tracee->debug.need_watch = false; // data already present
		tracee->debug.r_debug_addr = dyn_debug_data;
		return sym_setup_dldebug(tracee);
	}

	// Now create the watch point from the start addr; we will watch only 8
	// bits as the write would affect the entire sh_entsize
	if (watchpoint_add(tracee, dyn_debug_addr, true) == -1) {
		pr_err("unable to add watchpoint for r_debug");
		return -1;
	}

	tracee->debug.r_debug_addr = dyn_debug_addr;
	tracee->debug.need_watch = true;

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

	// IMP: If the type of ELF is EXEC, then va_base will be 0 (No
	// ASLR)
	if (elf_hdr->e_type == ET_EXEC) {
		tracee->va_base = 0UL;
	} else {
		if (elf_hdr->e_type != ET_DYN) {
			pr_err("this binary is neither EXEC or DYN "
			       "type, other "
			       "types are not supported as of now");
			goto elf_out;
		}
	}

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;
	Elf_Scn *symtab_scn = NULL;
	Elf64_Shdr *symtab_hdr = NULL;
	Elf_Scn *rela_dyn_scn = NULL;
	Elf64_Shdr *rela_dyn_hdr = NULL;
	Elf_Scn *rela_plt_scn = NULL;
	Elf64_Shdr *rela_plt_hdr = NULL;
	Elf_Scn *dyn_scn = NULL;
	Elf64_Shdr *dyn_hdr = NULL;

	// Build section map
	unsigned int idx = 0;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf64_getshdr(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		char *name = elf_strptr(elf, shstr_indx, hdr->sh_name);

		// don't want unallocated secitons in the list
		if (hdr->sh_type == SHT_NULL)
			continue;

		if (MATCH_STR(name, .plt.sec)) {
			plt_sec = true;
			// skip one entry of the trampoline;
			plt_entsize = hdr->sh_entsize;
			// plt.sec does not have the trampoline
			plt_ent_start = tracee->va_base + hdr->sh_addr;
		}

		if (MATCH_STR(name, .plt)) {
			if (!plt_sec) {
				// skip one entry of the trampoline;
				plt_entsize = hdr->sh_entsize;
				plt_ent_start = tracee->va_base + hdr->sh_addr +
				    hdr->sh_entsize;
			}
		}

		if (MATCH_STR(name, .rela.dyn)) {
			rela_dyn_scn = scn;
			rela_dyn_hdr = hdr;
		}

		if (MATCH_STR(name, .rela.plt)) {
			rela_plt_scn = scn;
			rela_plt_hdr = hdr;
		}

		if (MATCH_STR(name, .symtab)) {
			symtab_scn = scn;
			symtab_hdr = hdr;
		}

		if (MATCH_STR(name, .dynamic)) {
			dyn_scn = scn;
			dyn_hdr = hdr;
		}

		// skip non-allocated and 0 address section
		if (hdr->sh_addr == 0 || hdr->sh_size == 0) {
			continue;
		}

		section_t *t =
		    realloc(section_list, (idx + 1) * sizeof(section_t));
		if (t == NULL) {
			pr_err("error in realloc: %s", strerror(errno));
			goto sec_out;
		} else {
			section_list = t;
		}

		section_list[idx].start = tracee->va_base + hdr->sh_addr;
		section_list[idx].end = section_list[idx].start + hdr->sh_size;
		section_list[idx].name = name;
		pr_debug("[section] name=%s, start=%#llx, end=%#llx",
		    section_list[idx].name, section_list[idx].start,
		    section_list[idx].end);

		++idx;
	}
	section_count = idx;

	if (symtab_scn) {
		if (handle_static_syms(tracee, elf, symtab_scn, symtab_hdr) ==
		    -1) {
			pr_err("handling symtab failed");
			goto syms_out;
		}
	}

	if (rela_dyn_scn) {
		if (handle_dynamic_syms(
			tracee, elf, rela_dyn_scn, rela_dyn_hdr) == -1) {
			pr_err("handling rela_dyn failed");
			goto syms_out;
		}
	}

	if (rela_plt_scn) {
		if (handle_dynamic_syms(
			tracee, elf, rela_plt_scn, rela_plt_hdr) == -1) {
			pr_err("handling rela_plt failed");
			goto syms_out;
		}
	}

	HASH_SORT(sherlock_symtab, sym_sort_cmp);

	// Get the linker debug struct address (r_debug)
	if (dyn_scn) {
		if (handle_dyn_linker(tracee, dyn_scn, dyn_hdr) == -1) {
			pr_warn("error in parsing .dynamic section, some "
				"features like breakpointing dynamic lib "
				"functions _may_ get affected");
		}
	}

#ifdef DEBUG
	symbol_t *s, *t;
	HASH_ITER(hh, sherlock_symtab, s, t)
	{
		pr_debug("[sort] addr=%#llx, base=%#llx, name=%s", s->addr,
		    s->base, s->name);
	}
#endif

	// cant use elf_end here as the string pointers are in use.
	return 0;

syms_out:
	if (sherlock_symtab != NULL) {
		sym_freeall();
	}

sec_out:
	if (section_list != NULL) {
		free(section_list);
		section_list = NULL;
	}
elf_out:
	elf_end(elf);
	elf = NULL;
out:
	close(fd);
err:
	return -1;
}

symbol_t *sym_lookup_name(__attribute__((unused)) tracee_t *tracee, char *name)
{
	if (name == NULL || name[0] == '\0') {
		pr_debug("invalid name to sym_lookup_name");
		return NULL;
	}

	symbol_t *s = NULL;
	// TODO [LATER]: handle collisions and duplicate names
	HASH_FIND_STR(sherlock_symtab, name, s);
	return s;
}

symbol_t *sym_lookup_addr(
    __attribute__((unused)) tracee_t *tracee, unsigned long long addr)
{
	if (addr == 0) {
		return NULL;
	}

	// Handle
	symbol_t *sym, *tmp;
	HASH_ITER(hh, sherlock_symtab, sym, tmp)
	{
		// for static symbols, size is valid, so for static we
		// can check if address belongs to [addr, addr+size]
		if (!sym->dyn_sym) {
			if (addr >= sym->addr &&
			    addr <= sym->addr + sym->size) {
				return sym;
			}
		} else {
			// for dyamic, size is 0, we need to check addr
			// >= addr and in the same memory section
			if (addr >= sym->addr && addr <= sym->section->end) {
				return sym;
			}
		}
	}

	return NULL;
}

void sym_cleanup(__attribute__((unused)) tracee_t *tracee)
{
	pr_debug("sym cleanup");
	if (sherlock_symtab != NULL) {
		sym_freeall();
	}

	if (section_list != NULL) {
		free(section_list);
		section_list = NULL;
	}

	if (elf != NULL) {
		elf_end(elf);
		elf = NULL;
	}

	proc_cleanup(tracee);
}
