# Software Security Project

## Name
ISOS Injector

## Description
In this project, we explore how to inject a completely new code section into an ELF binary. isos_inject is a command-line tool that allows you to inject binary code into an ELF file. The injected code can be executed by modifying the entry point of the ELF file or by hijacking GOT Entries.

## Installation
-> git clone https://gitlab.istic.univ-rennes1.fr/frahmani/software-security-project.git
-> cd software-security-project
-> make

## Usage
./isos_inject [OPTIONS...] <ELF_FILE> <BINARY_FILE> <SECTION_NAME> <BASE_ADDRESS> <MODIFY_ENTRY>

## Options
-?, --help: Give this help list
-h, --help: Display help message
--usage: Give a short usage message
-V, --version: Print program version

## Arguments
-> ELF_FILE: The path to the ELF file that will be modified.
-> BINARY_FILE: The path to the binary file that will be injected into the ELF file.
-> SECTION_NAME: The name of the section in the ELF file where the binary code will be injected.
-> BASE_ADDRESS: The base address where the binary code will be injected.
-> MODIFY_ENTRY: Whether or not to modify the entry point of the ELF file to point to the injected code.

## Building

-> make: generates the executable isos_inject
-> make entry-point: generates an entry-point executable to be injected when MODIFY_ENTRY is true
-> make hijack-got: generates a GOT hijack executable using to be injected when MODIFY_ENTRY is false
-> make update-date: This command copies the contents of the file backup-date to date, which is used to keep track of date before modification.
-> make clean: This command removes all the object files, executable files, and other temporary files generated during the compilation process.

## Testing
-> make syntax-check: checks the syntax of the source code using clang
-> make bounds-check: checks the code for array bounds, null pointer dereferencing and other memory errors using gcc
-> make analyzer-check: performs a static analysis of the code using gcc's built-in analyzer
-> make tidy-check: checks the code for code quality issues using clang-tidy
-> make memory-sanitizer: checks the code for memory errors at runtime using clang's MemorySanitizer
-> make address-sanitizer: checks the code for memory errors at runtime using clang's AddressSanitizer

## Support
"Faical Sid Ahmed Rahmani" <faical-sid-ahmed.rahmani@etudiant.univ-rennes1.fr>

## License
isos_inject is released under the CyberSchool License.
