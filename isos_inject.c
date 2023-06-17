#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <bfd.h>
#include <err.h>

#include "my_elf.h"
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>

// Define offset of GOT entry to hijack (hijack putc function)
#define GOT_ENTRY_OFFSET 0x10110 

/* Challenge 1 */

// Define version and bug adress
const char *argp_program_version = "isos_inject 1.0";
const char *argp_program_bug_address = "<faical-sid-ahmed.rahmani@etudiant.univ-rennes1.fr>";

// Options supported by program
static struct argp_option options[] = {
  {"help", 'h', 0, 0, "Display help message", 0},
  {0}
};

// Argument struct: to store the values of the command-line arguments
struct arguments {
  char *elf_file; // The elf file that will be analyzed
  char *binary_file; // A binary file that contains the machine code to be injected
  char *section_name; // The name of the newly created section
  uint64_t base_address; // The base address of the injected code
  bool modify_entry; // A Boolean that indicates whether the entry function should be modified or not
};

/**
 * Parse function: called once for each command-line option or non-option 
 * argument that the program encounters.
 *
 * @param key: The key representing the option or argument.
 * @param arg: The value of the option or argument.
 * @param state: The current state of the argument parser.
 * @return An error code indicating the result of the parsing.
 */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  
  struct arguments *arguments = state->input;
  // Handle different options and arguments
  switch (key) {
    case 'h':
      argp_state_help(state, stdout, ARGP_HELP_LONG | ARGP_HELP_DOC);
      exit(EXIT_SUCCESS);
      break;
    
    case ARGP_KEY_ARG: // Handle non-option arguments
      if (state->arg_num == 0) {
        arguments->elf_file = arg;
      } else if (state->arg_num == 1) {
        arguments->binary_file = arg;
      } else if (state->arg_num == 2) {
        arguments->section_name = arg;
      } else if (state->arg_num == 3) {
        // Convert the input string to an unsigned long long integer
        char *endptr;
        uint64_t base_address = strtoull(arg, &endptr, 16);
        if (*arg == '\0' || *endptr != '\0') {
          warnx("Error: Invalid base address '%s'\n", arg);
          argp_usage(state);
        }
        arguments->base_address = base_address;
      } else if (state->arg_num == 4) {
        // Check if the input string matches "true" or "false"
        if (strcmp(arg, "true") == 0) {
          arguments->modify_entry = true;
        } else if (strcmp(arg, "false") == 0) {
          arguments->modify_entry = false;
        } else {
          warnx("Error: Invalid value for 'modify_entry': '%s'\n", arg);
          argp_usage(state);
        } 
      } else {
        argp_usage(state);
      }
      break;
        
    case ARGP_KEY_END: // Handle too many arguments
      if (state->arg_num != 5) {
        argp_usage(state);
      }
      break;    

    default: // Handle unknown options
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/** 
 * defines an instance of the 'argp' structure: we specify the parameters for 
 * the command-line argument parser. 
 */
static struct argp argp_parser = {
  .options = options,
  .parser = parse_opt,
  .args_doc = "<ELF_FILE> <BINARY_FILE> <SECTION_NAME> <BASE_ADDRESS> <MODIFY_ENTRY>",
  .doc = "isos_inject: injects binary code into an ELF file\n"
         "Usage: isos_inject [OPTIONS...] <ELF_FILE> <BINARY_FILE> <SECTION_NAME>" 
         "<BASE_ADDRESS> <MODIFY_ENTRY>\n",
};

/**
 * Checks if the given ELF file is a valid 64-bit executable.
 * 
 * @param elf_file: The name of the ELF file to be checked.
 * @return void
 */
void check_elf (const char * elf_file) {
  
  // Initialize BFD library */
  bfd_init();
  
  // Open ELF file */
  bfd *elf_abfd = bfd_openr(elf_file, NULL);
  
  // Check the opening
  if (elf_abfd == NULL) {
    errx(EXIT_FAILURE, "Failed to open %s: %s", elf_file, bfd_errmsg(bfd_get_error()));
  }
  
  // Check if the binary is of format ELF 
  if (!bfd_check_format(elf_abfd, bfd_object)) {
    errx(EXIT_FAILURE, "%s is not an ELF binary", elf_file);
  }
  
  // Check if the binary is of architecture 64-bit 
  if (bfd_get_arch_size(elf_abfd) != 64) {
    errx(EXIT_FAILURE, "The binary %s is not of architecture 64-bit", elf_file);
  }
  
  // Check if the binary is executable
  if (!(bfd_get_file_flags(elf_abfd) & EXEC_P)) {
    errx(EXIT_FAILURE, "%s is not executable", elf_file);
  }
  
  // Close the file
  bfd_close(elf_abfd);   
}

/* Challenge 2 */

/**
 * checks whether the given binary file has a PT_NOTE segment.
 *
 * @param file_path: The path to the binary file.
 * @return The index of the first program header of type PT_NOTE, or -1 if not found.
 */
int check_ptnote (const char * elf_file) {
  
  // Open the file
  int fd_elf = open(elf_file, O_RDONLY);
  if (fd_elf < 0) {
    errx(EXIT_FAILURE, "Failed to open %s", elf_file);
  }
  
  // Get information about a file based on its file descriptor filled in st structure 
  struct stat st;
  if (fstat(fd_elf, &st) < 0) {
    errx(EXIT_FAILURE, "Failed to get size of the file");
  }
  
  // Maps the entire file into readable memory region without affecting the underlying file 
  void *map_addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd_elf, 0);
  if (map_addr == MAP_FAILED) {
    errx(EXIT_FAILURE, "Failed to map the file");
  }
  
  // Create a pointer to Elf64_Ehdr and give it the address of the mapped 
  // memory region that contains the ELF binary file, and that allow us
  // to retrieve information about the binary file using ehdr  
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map_addr;
  
  // Retrive the number of the program headers
  int num_phdrs = ehdr->e_phnum;
  printf("number of the program headers == %d\n", num_phdrs);
  
  // Looking for the program header PT_NOTE 
  int ptnote_index = -1;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(void*)((char*)map_addr + ehdr->e_phoff);
  for (int i = 0; i < num_phdrs; i++) {
    if (phdr[i].p_type == PT_NOTE) {
      // Store the index of the first program header of type PT_NOTE
      ptnote_index = i;
      break;
    }
  }
   
  /* Unmap the file or destroys the projection in the memory area */
  if (munmap(map_addr, st.st_size) < 0) {
    errx(EXIT_FAILURE, "Failed to unmap the file");
  }

  /* Close the file descriptor */
  if (close(fd_elf) < 0) {
    errx(EXIT_FAILURE, "Failed to close the file");
  }
  
  return ptnote_index; 
}  

/* Challenge 3 */

long injected_size; // store injected size
long injected_offset; // store injected offset

/**
 * Injects code from a binary file into an ELF file.
 * 
 * @param elf_file: The path to the ELF file to be modified.
 * @param binary_file: The path to the binary file containing the code to be injected.
 * @param base_address: The base address where the injected code should be placed in the ELF file.
 * @return The difference between the injected offset and the base address modulo 4096, to ensure alignment.
 */
long inject_code (const char * elf_file, const char * binary_file, uint64_t base_address) {
  
  // Open the ELF file in binary append mode 
  FILE *target_file = fopen(elf_file, "ab");
  if (target_file == NULL) {
    errx(EXIT_FAILURE, "Failed to open %s", elf_file);  
  }
  
  // Open the injected binary file for reading
  FILE *injected_file = fopen(binary_file, "rb");
  if (injected_file == NULL) {
    errx(EXIT_FAILURE, "Failed to open %s", binary_file);   
  }
  
  // Read 0 byte from the end of the injected file, this will place
  // the file pointer at the end of the file
  if (fseek(injected_file, 0, SEEK_END) != 0) {
    errx(EXIT_FAILURE, "Failed to change position");
  }
  
  // get the size of the injected file and sets the file position to the beginning
  injected_size = ftell(injected_file);
  rewind(injected_file);
  
  // Save the byte offset where the injected code were written
  injected_offset = ftell(target_file);
  printf("injected_offset == %ld\n", injected_offset);
  
  // allocate buffer for the injected code and add the injected code to the target
  char * injected_buf = malloc(injected_size);
  if (injected_buf == NULL) {
    errx(EXIT_FAILURE, "Failed to allocate buffer fo injected code");
  }
  
  size_t bytes_read = fread(injected_buf, 1, injected_size, injected_file);
  if (bytes_read != (size_t)injected_size) {
    free(injected_buf);
    errx(EXIT_FAILURE, "Error reading injected code file");
  }
  
  size_t bytes_written = fwrite(injected_buf, 1, injected_size, target_file);
  if (bytes_written != (size_t)injected_size) {
    free(injected_buf);
    errx(EXIT_FAILURE, "Error writing injected code to binary file");
  }
  
  // free the buffer
  free(injected_buf);
  
  // close files 
  if (fclose(target_file) != 0) {
    errx(EXIT_FAILURE, "Failed to close file");
  }
  if (fclose(injected_file) != 0) {
    errx(EXIT_FAILURE, "Failed to close file");
  }
  
  // Ensures alignment 
  long diff = (injected_offset % 4096) - (base_address % 4096);
  
  return diff;  
}

/* Challenge 4 */

/**
 * Modifies the section header .note.ABI-tag section 
 * in order to describe an injected section.
 *
 * @param ehdr: Pointer to the ELF header of the file.
 * @param shdr_tab: Pointer to the section header table of the file.
 * @param shstrtab: Pointer to the string table section containing section names.
 * @param base_address: The base virtual address where the injected section will be loaded.
 * @return The index of .note.ABI-tag header, or -1 if not found.
 */
int modify_note_ABI_tag_header (Elf64_Ehdr * ehdr, Elf64_Shdr * shdr_tab, char * shstrtab, uint64_t base_address) {

  // Loop over section headers
  int note_ABI_tag_index = -1;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    // Get the current section header
    Elf64_Shdr * shdr = &shdr_tab[i];
    
    // Get the name of the current section header
    char * section_name = shstrtab + shdr->sh_name;
    
    // Check if the section header is .note.ABI-tag
    if (strcmp(section_name, ".note.ABI-tag") == 0) {
      // Save the index
      note_ABI_tag_index = i;
      // Modify the section header in order to describe the injected section
      shdr->sh_type = SHT_PROGBITS;
      shdr->sh_addr = base_address;  
      shdr->sh_offset = injected_offset;  
      shdr->sh_size = injected_size;     
      shdr->sh_addralign = 16;
      shdr->sh_flags |= SHF_EXECINSTR;
      
      // leave the loop
      break;
    }
  }
  
  return note_ABI_tag_index; 
}

/* Challenge 5 */

/**
 * Swaps the contents of two ELF section headers.
 *
 * @param sh1: Pointer to the first section header.
 * @param sh2: Pointer to the second section header.
 * @return void
 */
void swap_section_headers (Elf64_Shdr * sh1, Elf64_Shdr * sh2) {
    Elf64_Shdr temp = *sh1;
    *sh1 = *sh2;
    *sh2 = temp;
    
}

/**
 * This function reorders the section headers of an ELF binary.
 * 
 * @param ehdr: pointer to the ELF header structure
 * @param shdr_tab: pointer to the section header table
 * @param injected_sh_index: the index of the injected section in the section header table
 * @return the index of the injected section after reordering
 */
int reorder_section_headers (Elf64_Ehdr * ehdr, Elf64_Shdr * shdr_tab, int injected_sh_index) {
    
  // Store the old index for injected section
  int old_injected_sh_index = injected_sh_index;
  
  // Compare with the direct neighbors to decide whether it should be moved right or left
  int left = 0;
  if (injected_sh_index > 0 && shdr_tab[injected_sh_index].sh_addr <    
                               shdr_tab[injected_sh_index - 1].sh_addr)
    left = 1;
                                 
  int right = 0;
  if (injected_sh_index < ehdr->e_shnum - 1 && shdr_tab[injected_sh_index].sh_addr > 
                                         shdr_tab[injected_sh_index + 1].sh_addr)
    right = 1;
                                             
  // Compare the injected section with its neighbors and swap if needed 
  while (injected_sh_index > 0 && shdr_tab[injected_sh_index].sh_addr <    
                               shdr_tab[injected_sh_index - 1].sh_addr) 
  { 
    swap_section_headers(&shdr_tab[injected_sh_index], &shdr_tab[injected_sh_index - 1]);
    injected_sh_index--;
  }
  
  
  while (injected_sh_index < ehdr->e_shnum - 1 && shdr_tab[injected_sh_index].sh_addr > 
                                         shdr_tab[injected_sh_index + 1].sh_addr) 
  {
    swap_section_headers(&shdr_tab[injected_sh_index], &shdr_tab[injected_sh_index + 1]);
    injected_sh_index++;
  }
  
  // Update sh_link field 
  if (right) { // If we made right swap 
    // Update for all section headers
    for (int i = 0; i < ehdr->e_shnum; i++) {
      if (shdr_tab[i].sh_link != 0 && (int)shdr_tab[i].sh_link > old_injected_sh_index &&
                                    (int)shdr_tab[i].sh_link <= injected_sh_index) {
        shdr_tab[i].sh_link--;    
      }
    }
  }
  
  if (left) { // If we made left swap
    // Update for all section headers */
    for (int i = 0; i < ehdr->e_shnum; i++) {
      if (shdr_tab[i].sh_link != 0 && (int)shdr_tab[i].sh_link >= injected_sh_index &&
                                    (int)shdr_tab[i].sh_link < old_injected_sh_index) {
        shdr_tab[i].sh_link++;    
      }
    }
  }
  
  return injected_sh_index;
}


/**
 * Sets the name of the injected section
 * 
 * @param fd_elf: the file descriptor of the ELF file to modify
 * @param shstrtab_hdr: a pointer to the ELF section header of the section header string table
 * @param shstrtab: a pointer to the contents of the section header string table
 * @param section_name: the new name to give to the injected section
 * @return 0 if the section name was successfully set, -1 if the new section name is larger or equal to ".note.ABI-tag"
 */    
int set_section_name (int fd_elf, Elf64_Shdr * shstrtab_hdr, char * shstrtab, char * section_name) {
    
  // Get size of new name
  int section_name_size = strlen(section_name);
  
  // Get size of note-abi string
  int note_abi_size = strlen(".note.ABI-tag");
   
  // Check that the given section name has smaller length than ".note.ABI-tag"
  if (section_name_size >= note_abi_size) {
    return -1;
  }
    
  // Get the offset of ".note.ABI-tag" into shstrtab
  char *note_abi_tag_address = shstrtab;
  while (strcmp(note_abi_tag_address, ".note.ABI-tag") != 0) {
    note_abi_tag_address += strlen(note_abi_tag_address) + 1;
  } 
  int note_abi_tag_offset = note_abi_tag_address - shstrtab;
  
  // Get the offset to start of .shstrtab
  int shstrtab_offset = shstrtab_hdr->sh_offset;
  
  // Compute the file offset at which to write the new section name
  int section_name_offset = shstrtab_offset + note_abi_tag_offset;
  
  // Seek the file descriptor to that offset
  if (lseek(fd_elf, section_name_offset, SEEK_SET) < 0) {
    errx(EXIT_FAILURE, "Failed to change position");
  }
  
  // Write the new section name to the ELF binary
  if (write(fd_elf, section_name, note_abi_size) < 0) {
    errx(EXIT_FAILURE, "Failed to write the new section name");
  }
  
  return 0;   
}

/* Challenge 6 */

/**
 * Overwrites the PT_NOTE program header with new values.
 * 
 * @param phdr: Pointer to an array of Elf64_Phdr structures containing program header information.
 * @param ptnote_index: Index of the PT_NOTE program header to be modified.
 * @param base_address: address of the start of the injected section in memory.
 * @return void
 */
void modify_ptnote (Elf64_Phdr * phdr, int ptnote_index, uint64_t base_address) {
 
  /* Overwrite the relevant program header fields */
  phdr[ptnote_index].p_type = PT_LOAD;
  phdr[ptnote_index].p_offset = injected_offset;
  phdr[ptnote_index].p_vaddr = base_address;
  phdr[ptnote_index].p_paddr = base_address;
  phdr[ptnote_index].p_filesz = injected_size; 
  phdr[ptnote_index].p_memsz = injected_size;
  phdr[ptnote_index].p_flags |= PF_X;
  phdr[ptnote_index].p_align = 0x1000;  
  
}  

/* task7 */

/**
 * This function is used to modify the entry point of an ELF binary or hijack the global 
 * Offset Table (GOT) entry, depending on the value of the modify_entry parameter.
 *
 * @param fd_elf: the file descriptor of the ELF file
 * @param ehdr: a pointer to the ELF header structure
 * @param base_address: the base address to use for hijacking the GOT entry
 * @param modify_entry: a boolean indicating whether to modify the entry point or hijack the GOT entry
 * @return void
 */
void hijack (int fd_elf, Elf64_Ehdr * ehdr, uint64_t base_address, bool modify_entry) 
{ 
  if (modify_entry){ // modify entry point 
    ehdr->e_entry = base_address;
  } else { // hijack got entry 
    // Get the got entry offset already computed
    off_t got_entry_offset = GOT_ENTRY_OFFSET;
    // Seek the file descriptor to that offset
    if (lseek(fd_elf, got_entry_offset, SEEK_SET) < 0) {
      errx(EXIT_FAILURE, "Failed to change position");
    }
    // Write the updated program header
    if (write(fd_elf, &base_address, sizeof(base_address)) < 0) {
      errx(EXIT_FAILURE, "Failed to write the updated header");
    }
  }
}

/** 
 * The main program 
 */
int main(int argc, char **argv) {
  
  /* Challenge 1 */    
  
  // Create and initializes an instance of the 'arguments'
  struct arguments arguments = {0};
    
  // Parse the command-line arguments and store their values in the arguments
  argp_parse(&argp_parser, argc, argv, 0, 0, &arguments);
  
  // Checks if the given ELF file is a valid 64-bit executable  
  check_elf(arguments.elf_file);
  
  printf("\n[========== Command line parsing ==========>]: Done\n");
  
  /* Challenge 2 */
    
  // Check whether the binary has a PT_NOTE segment  
  int ptnote_index = check_ptnote(arguments.elf_file);
  if (ptnote_index < 0) {
    errx(EXIT_FAILURE, "PT_NOTE not found");
  } else {
    printf("PT_NOTE found at index == %d\n", ptnote_index);
  }
  
  printf("\n[==========    Find PT_NOTE      ==========>]: Done\n");
  
  /* Challenge 3 */
  
  // Injects code from a binary file into an ELF file
  long diff = inject_code (arguments.elf_file, arguments.binary_file, arguments.base_address);
  if (diff != 0) {
    arguments.base_address += diff;
  }
  
  printf("\n[==========    Code injection    ==========>]: Done\n");
  
  /* Challenge 4 */
  
  // open the elf file
  int fd_elf = open(arguments.elf_file, O_RDWR);
  if (fd_elf < 0) {
    errx(EXIT_FAILURE, "Failed to open %s", arguments.elf_file);
  }
  
  struct stat st;
  if (fstat(fd_elf, &st) < 0) {
    errx(EXIT_FAILURE, "Failed to get size of the file");
  }
  
  // Maps the entire file into readable and writeable memory region
  void *map_addr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd_elf, 0);
  if (map_addr == MAP_FAILED) {
    errx(EXIT_FAILURE, "Failed to map the file");
  }
  
  // Get the ELF header
  Elf64_Ehdr * ehdr = (Elf64_Ehdr *)map_addr;

  // Get the section header table
  Elf64_Shdr * shdr_tab = (Elf64_Shdr *)(void*)((char*)map_addr + ehdr->e_shoff);

  // Get the program header table
  Elf64_Phdr * phdr = (Elf64_Phdr *)(void*)((char*)map_addr + ehdr->e_phoff);

  // Get the section header string table index
  Elf64_Shdr * shstrtab_hdr = &shdr_tab[ehdr->e_shstrndx];
  
  // Get the section header string table
  char * shstrtab = ((char *)map_addr + shstrtab_hdr->sh_offset);
  
  // Modifies the section header .note.ABI-tag section in order to describe the injected section.
  int note_ABI_tag_index = modify_note_ABI_tag_header(ehdr, shdr_tab, shstrtab, arguments.base_address);
  
  // Check if we have found .note.ABI-tag
  if (note_ABI_tag_index < 0) {
    errx(EXIT_FAILURE, "Failed to find section header for .note.ABI-tag");         
  } else {
    printf(".note.ABI-tag found at index %d\n", note_ABI_tag_index);
  }
  
  printf("\n[======= Overwriting .note.ABI-tag ========>]: Done\n");
  
  /* Challenge 5 */
  
  // Reorders the section headers of an ELF binary
  int injected_sh_index = reorder_section_headers(ehdr, shdr_tab, note_ABI_tag_index);
  printf(".note.ABI-tag swapped at index: %d\n", injected_sh_index);
  
  // Sets the name of the injected section
  if (set_section_name(fd_elf, shstrtab_hdr, shstrtab, arguments.section_name) < 0) {
    munmap(map_addr, st.st_size);
    close(fd_elf);
    errx(EXIT_FAILURE, "Section name has equal or larger length than .note.ABI-tag");
  }
  
  printf("\n[======= section headers calibration ======>]: Done\n");
  
  /* Challenge 6 */
  
  // Overwrites the PT_NOTE program header
  modify_ptnote(phdr, ptnote_index, arguments.base_address);  
  
  printf("\n[========= Overwriting the PT_NOTE ========>]: Done\n");
  
  /* Challenge 7 */
  
  // Modify the entry point of an ELF binary or hijack the Global Offset Table (GOT)
  hijack(fd_elf, ehdr, arguments.base_address, arguments.modify_entry);
  
  printf("\n[====== Hijacking GOT or entry point ======>]: Done\n");
  
  /* Clean up */
  
  // Unmap the file or destroys the projection in the memory area
  if (munmap(map_addr, st.st_size) < 0) {
    errx(EXIT_FAILURE, "Failed to unmap the file");
  }
  
  // Close the file descriptor
  if (close(fd_elf) < 0) {
    errx(EXIT_FAILURE, "Failed to close the file");
  }
  
  return 0;
}






