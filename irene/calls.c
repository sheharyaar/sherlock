#include "log.h"
#include "tracee_defs.h"
#include <libelf.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

static unsigned long long va_base = 0;

void set_va_base(unsigned long long addr) { va_base = addr; }

unsigned long long call_to_va(unsigned long long rip, long instr)
{
	// convert the instruction to the address format 32-bit sign extended
	// 0x05 is added to calculatd the next instr address
	unsigned long long dest =
	    rip + 0x05 + (int)((instr & 0xffffffffff) >> 8);
	return dest - va_base;
}

// char *get_symbol_name(Elf_Scn *sym_scn, Elf64_Shdr *sym_hdr, int index) {}

void print_libs(char *file)
{
	pr_info("opening and reading file: %s", file);
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		pr_err("error in open: %s", strerror(errno));
		return;
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

	size_t n_shdr = 0;
	int ret = elf_getshdrnum(elf, &n_shdr);
	if (ret == -1) {
		pr_err("error in elf_getshdrnum");
		goto elf_out;
	}

	Elf_Scn *scn = NULL;
	Elf64_Shdr *hdr = NULL;

	Elf_Scn *rela_plt_scn = NULL;
	Elf64_Shdr *rela_plt_hdr = NULL;

	Elf_Scn *dynsym_scn = NULL;
	Elf64_Shdr *dynsym_hdr = NULL;

	char *name = NULL;
	size_t dynstr_indx;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if ((hdr = elf64_getshdr(scn)) == NULL) {
			pr_err("error in elf_nextscn(): %s",
			    elf_errmsg(elf_errno()));
			continue;
		}

		if ((name = elf_strptr(elf, shstr_indx, hdr->sh_name)) ==
		    NULL) {
			pr_err(
			    "error in elf_strptr: %s", elf_errmsg(elf_errno()));
			continue;
		}

		if (strncmp(".rela.plt", name, 9) == 0) {
			rela_plt_scn = scn;
			rela_plt_hdr = hdr;
		}

		if (strncmp(".dynsym", name, 7) == 0) {
			dynsym_scn = scn;
			dynsym_hdr = hdr;
		}

		if (strncmp(".dynstr", name, 7) == 0) {
			dynstr_indx = elf_ndxscn(scn);
		}
	}

	if (rela_plt_scn == NULL || rela_plt_hdr == NULL ||
	    dynsym_scn == NULL || dynsym_hdr == NULL) {
		pr_err(".rela.plt or .dynsym section/section header not found "
		       "in ELF");
		goto elf_out;
	}

	int n_plts = rela_plt_hdr->sh_size / rela_plt_hdr->sh_entsize;
	pr_info("Number of .rela.plt entries: %d", n_plts);

	// .rela.plt section entries
	Elf64_Rela *rela = NULL;
	Elf_Data *data = elf_getdata(rela_plt_scn, NULL);
	if (data == NULL) {
		pr_err("error in elf_getdata: %s", elf_errmsg(elf_errno()));
		goto elf_out;
	}

	// for each entry of .rela.plt
	rela = data->d_buf;
	for (int i = 0; i < data->d_size / rela_plt_hdr->sh_entsize; i++) {
		pr_info("Rela [OFFSET]=%#lx [INFO SYMBOL]=%#lx [INFO "
			"TYPE]=%ld [ADDEND]=%ld",
		    rela[i].r_offset, ELF64_R_SYM(rela[i].r_info),
		    ELF64_R_TYPE(rela[i].r_info), rela[i].r_addend);
	}

	Elf64_Sym *sym = NULL;
	data = elf_getdata(dynsym_scn, NULL);
	if (data == NULL) {
		pr_err("error in elf_getdata: %s", elf_errmsg(elf_errno()));
		goto elf_out;
	}

	// for each entry of .dynsym
	sym = data->d_buf;
	for (int i = 0; i < data->d_size / dynsym_hdr->sh_entsize; i++) {
		pr_info("symbol [index]=%d, [name]=%s", i,
		    elf_strptr(elf, dynstr_indx, sym[i].st_name));
	}

	/* TODO:
	- Now that you have got the symbol names of the functions you care
	about, now get the PLT entry for those, so that you can then related
	them
	- Objdump show:
	-    1030: ff 25 ca 2f 00 00 jmp *0x2fca(%rip) #4000 <puts@GLIBC_2.2.5>
	- This 4000 is present in .rela.plt section
	 */

elf_out:
	elf_end(elf);
out:
	close(fd);
}
