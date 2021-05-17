#ifndef WWP_H
# define WWP_H

# include "libmaster.h"
# include "color.h"

#include <elf.h>

# include <fcntl.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>

# include <sys/mman.h>
# include <sys/stat.h>

//# define ALIGN_4096(x) (4096 - (x % 4096)) FUCCCCKKKKK YOUUUUUUUUUU WIUYRGCBOWIUYBCQWIUYEB DEFINE

typedef struct	s_file_data
{
	char		*ptr;
	Elf64_Ehdr	*header;
	Elf64_Shdr	*sections;
}				t_file_data;

int 			encr_bundle_size;				// size of decryption bundle
Elf64_Addr		parasite_load_address;			// parasite entry point (if parasite is LSB EXEC)
Elf64_Off		parasite_offset;				// Parasite entry point (if parasite is .so)
u_int64_t		parasite_size;					// Size of parasite
u_int64_t		parasite_full_size;				// Size of parasite including key size
int8_t			*parasite_code;					// Parasite residence (in memory before meeting its host)
int				HOST_IS_EXECUTABLE;				// exec || so

u_int64_t		parasite_start;

// ----------------MAIN-------------------
int				write_woody(char *ptr, off_t size, char *filename);

// ----------------PATCHER----------------
void			AddrPatcher(u_int8_t *parasite, long placeholder, long address);
void			ModifyNOTEphdr(void *ptr, int size);
void			ModifyNOTEshdr(void *ptr, int size);

// ----------------INFECTOR---------------
void			ParasiteLoader(char *parasite_path);

#endif
