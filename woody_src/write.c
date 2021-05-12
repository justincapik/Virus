#include "wwp.h"

int			write_woody(char *ptr, off_t size, char *filename)
{
	fprintf(stdout, BOLDBLUE"-x-x-x-x- "RED"\\_<O>_<O>_/ "BLUE"-x-x-x-x-\n"RED"-> "CYAN"%s\n\n"RESET, filename); 

	// ###################################################################################################################
	// INIT
	// ###################################################################################################################
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) ptr;
	HOST_IS_EXECUTABLE = 0;	// Host is LSB Executable and not Shared Object

	parasite_start = size;

	// Identify the binary & SKIP Relocatable, files and 32-bit class of binaries
	if (ehdr->e_type == ET_REL || ehdr->e_type == ET_CORE)
		return (0);
	else if (ehdr->e_type == ET_EXEC)
		HOST_IS_EXECUTABLE = 1;
	else if (ehdr->e_type == ET_DYN )
		HOST_IS_EXECUTABLE = 0;
	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		return (0);

	// Load Parasite into memory (from disk), uses extern 'parasite_path_for_exec' defined in main.c implicitly
	int ENC = 0;
	ParasiteLoader("./obj/ASM/parasite.bin");
	
	// ###################################################################################################################
	// MODIFYING SECTION HEADER
	// ###################################################################################################################

	ModifyNOTEphdr(ptr);
	ModifyNOTEshdr(ptr);
	//

	// ###################################################################################################################
	// PARASITE PATCHING + HOST INFESTATION
	// ###################################################################################################################

	// Patch Parasite with entrypoint and .text start
	Elf64_Addr original_entry_point = ehdr->e_entry;
	//ehdr->e_entry = parasite_start;
	AddrPatcher(parasite_code, 0xAAAAAAAAAAAAAAAA, parasite_start - original_entry_point);
	//AddrPatcher(parasite_code, 0x1111111111111111, textend - load_textoff);

	// call to the key generator then the enncryptor

	// ###################################################################################################################
	// WRITE
	// ###################################################################################################################

	//write memory in a new file
	int fd;
	if ((fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		return (1);

	// ###################################################################################################################
	//  MEM STRAT
	// // passage d'informations pour le decryptage
	// ft_memmove((ptr + parasite_offset), truekey, 16);
	// free(truekey);

	// // Inject parasite in Host memory
	// ft_memmove((ptr + parasite_offset + encr_bundle_size), parasite_code, parasite_size);
	// write(fd, ptr, size);
	// ###################################################################################################################

	write(fd, ptr, size);
	
	//write(fd, "test", 4);
	write(fd, parasite_code, parasite_size);
	close(fd);

	fprintf(stdout, BOLDCYAN"<o>"RESET YELLOW" success \\o/  :  "CYAN"%s\n"RESET, filename);

	return 0;
}
