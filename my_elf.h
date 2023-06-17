#ifndef _SYS_MY_ELF64_H_
#define _SYS_MY_ELF64_H_ 1

#define PT_LOAD 1
#define PT_NOTE 4

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define SHF_EXECINSTR 4

#define SHT_PROGBITS 1
#define SHT_DYNAMIC 6
#define SHT_REL 9
#define SHT_RELA 4 

#define SHDR_SIZE 64

#define PHDR_SIZE 56

typedef uint64_t	Elf64_Addr;
typedef uint64_t	Elf64_Off;

typedef struct
{
  unsigned char    e_ident[16];    /* Magic number and other info */
  uint16_t    e_type;            /* Object file type */
  uint16_t    e_machine;        /* Architecture */
  uint32_t    e_version;        /* Object file version */
  uint64_t    e_entry;        /* Entry point virtual address */
  uint64_t    e_phoff;        /* Program header table file offset */
  uint64_t    e_shoff;        /* Section header table file offset */
  uint32_t    e_flags;        /* Processor-specific flags */
  uint16_t    e_ehsize;        /* ELF header size in bytes */
  uint16_t    e_phentsize;        /* Program header table entry size */
  uint16_t    e_phnum;        /* Program header table entry count */
  uint16_t    e_shentsize;        /* Section header table entry size */
  uint16_t    e_shnum;        /* Section header table entry count */
  uint16_t    e_shstrndx;        /* Section header string table index */
} Elf64_Ehdr;

typedef struct
{
  uint32_t    p_type;            /* Segment type */
  uint32_t    p_flags;        /* Segment flags */
  uint64_t    p_offset;        /* Segment file offset */
  uint64_t    p_vaddr;        /* Segment virtual address */
  uint64_t    p_paddr;        /* Segment physical address */
  uint64_t    p_filesz;        /* Segment size in file */
  uint64_t    p_memsz;        /* Segment size in memory */
  uint64_t    p_align;        /* Segment alignment */
} Elf64_Phdr;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} Elf64_Shdr;

#endif /* !_SYS_MY_ELF64_H_ */
