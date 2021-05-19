#include "wwp.h"

// Finds the placeholder (for address where our parasite code will jump after executing its body) and
// writes the host's entry point (original entry point address) to it.
void		AddrPatcher(u_int8_t *parasite, long placeholder, long address)
{
	u_int8_t *ptr = parasite;
	int i;
	for (i = 0 ; i < parasite_size ; ++i)
	{
		long potential_placeholder = *((long *)(ptr + i));

		if (!(placeholder ^ potential_placeholder))
		{
			*((long *)(ptr + i)) = address;
			return;
		}
	}
}

void		ModifyNOTEphdr(void *ptr, int size)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	phnum 		= ehdr->e_phnum;
	Elf64_Off	pht_offset 	= ehdr->e_phoff;
	Elf64_Phdr	*phdr		= (Elf64_Phdr *)(ptr + pht_offset);
	Elf64_Phdr	*last		= (Elf64_Phdr *)(ptr + pht_offset);

	int i;
	int check = 0;
	dprintf(2, "parasite start = %d\n", parasite_start);

	for (i = 0; i < phnum; ++i)
		if (last->p_vaddr < phdr[i].p_vaddr)
			last = &(phdr[i]);

	for (i = 0 ; i < phnum ; ++i)
	{
		dprintf(2, "[%d] vaddr = %7d, paddr = %7d, filesz = %7d, memsz = %7d, offset = %7d, align = %5d\n",
				i, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz,
				phdr[i].p_memsz, phdr[i].p_offset, phdr[i].p_align);
		if (check == 0 && phdr[i].p_type == PT_NOTE)
		{
			phdr[i].p_type = PT_LOAD;
			phdr[i].p_flags = PF_R | PF_X;
			phdr[i].p_offset = last->p_offset + last->p_filesz
				+ 4096 - (last->p_offset + last->p_filesz) % 4096;
			phdr[i].p_paddr = last->p_paddr + last->p_filesz
				+ 4096 - (last->p_paddr + last->p_filesz) % 4096; // maybe memsz ? not sure it matters
			phdr[i].p_vaddr = last->p_vaddr + last->p_memsz
				+ 4096 - (last->p_vaddr + last->p_memsz) % 4096;
			phdr[i].p_memsz = parasite_size;
			phdr[i].p_filesz = parasite_size;
			phdr[i].p_align = 4096;
			check = 1;
			//break;
			dprintf(2, "[%d] vaddr = %7d, paddr = %7d, filesz = %7d, memsz = %7d, offset = %7d, align = %5d CHANGED\n",
					i, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz,
					phdr[i].p_memsz, phdr[i].p_offset, phdr[i].p_align);
		}
	}
}

void		ModifyNOTEshdr(void *ptr, int size)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	shnum 		= ehdr->e_shnum;
	Elf64_Off	shoff 		= ehdr->e_shoff;
	Elf64_Half	shstrndx	= ehdr->e_shstrndx;
	Elf64_Shdr	*shdr		= (Elf64_Shdr *)(ptr + shoff);
	Elf64_Shdr	*last		= (Elf64_Shdr *)(ptr + shoff);

	int i;
	int check = 0;
	dprintf(2, "string ? => [%s]\n", ptr + shstrndx);
	dprintf(2, "idx = %x\n", shstrndx);

	dprintf(2, "parasite start = %d\n", parasite_start);
	for (i = 0; i < shnum; ++i)
		if (last->sh_offset < shdr[i].sh_offset)
			last = &(shdr[i]);

	for (int i = 0; i < shnum; ++i)
	{
		dprintf(2, "[%d] addr = %7d, offset = %7d, size = %7d, addralign = %7d, flags = %2xx0, type = 0x%x\n",
				i, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size,
				shdr[i].sh_addralign, shdr[i].sh_flags, shdr[i].sh_type);
		if (check == 0 && shdr[i].sh_type == SHT_NOTE)
		{
			shdr[i].sh_type = SHT_PROGBITS;
			shdr[i].sh_entsize = 0;
			shdr[i].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
			shdr[i].sh_addralign = 16; // honestly the other .text sh had 16 so *shrug*
			shdr[i].sh_size = parasite_size;
			//TODO of it's aligned it still adds 4096
			shdr[i].sh_offset = last->sh_offset + last->sh_size
				+ 4096 - (last->sh_offset + last->sh_size) % 4096;
			shdr[i].sh_addr = (last->sh_addr == 0) ? 0 : last->sh_addr + last->sh_size
				+ 4096 - (last->sh_addr + last->sh_size) % 4096; // maybe memsz ? not sure it matters
			check = 1;
			//break;
			// we don't touch, name, and link
			dprintf(2, "[%d] addr = %7d, offset = %7d, size = %7d, addralign = %7d, flags = %2xx0, type = 0x%x CHANGED\n",
					i, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size,
					shdr[i].sh_addralign, shdr[i].sh_flags, shdr[i].sh_type);

		}
	}
}

int		gestiondataphdr(void *ptr)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	phnum 		= ehdr->e_phnum;
	Elf64_Off	pht_offset 	= ehdr->e_phoff;
	Elf64_Phdr	*phdr		= (Elf64_Phdr *)(ptr + pht_offset);
	Elf64_Phdr	*dataphdr	= NULL;

	int newentry = -1;

	for (int i = 0;i < phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset)
			dataphdr = &(phdr[i]);
	}

	newentry = dataphdr->p_vaddr + dataphdr->p_filesz;
	dataphdr->p_filesz += parasite_size;
	dataphdr->p_memsz += parasite_size;
	dataphdr->p_flags |= PF_X;
	dprintf(2, "filesz = %d, memsz = %d\n", dataphdr->p_filesz, dataphdr->p_memsz);	
	
	return (newentry);
}

int		get_bss_size(void *ptr)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	phnum 		= ehdr->e_phnum;
	Elf64_Off	pht_offset 	= ehdr->e_phoff;
	Elf64_Phdr	*phdr		= (Elf64_Phdr *)(ptr + pht_offset);
	Elf64_Phdr	*dataphdr	= NULL;

	int newentry = -1;

	for (int i = 0;i < phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset)
			dataphdr = &(phdr[i]);
	}
	return (dataphdr->p_memsz - dataphdr->p_filesz);
}
