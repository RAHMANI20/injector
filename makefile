# Compiler options
CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror -Wno-unused-parameter

# Libraries
LIBS = -lbfd

# Source files
SRC = isos_inject.c

# Object files
OBJ = $(SRC:.c=.o)

# Targets
TARGET = isos_inject

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Commands
syntax-check:
	clang -fsyntax-only -Wall -Wextra -Wuninitialized -Wpointer-arith -Wcast-qual -Wcast-align $(SRC)

bounds-check:
	gcc -O2 -Warray-bounds -Wsequence-point -Walloc-zero -Wnull-dereference -Wpointer-arith -Wcast-qual -Wcast-align=strict $(SRC) $(LIBS)

analyzer-check:
	gcc -fanalyzer $(SRC) $(LIBS)

tidy-check:
	clang-tidy $(SRC) -checks=cert-*,clang-analyzer-*

memory-sanitizer:
	clang -fsanitize=memory -fsanitize=undefined $(SRC) -o isos_inject_memory $(LIBS)

address-sanitizer:
	clang -fsanitize=address -fsanitize=undefined $(SRC) -o isos_inject_address $(LIBS)

update-date:
	cp backup-date date

entry-point:
	nasm -f bin -o entry-point entry-point.asm      

hijack-got:
	nasm -f bin -o hijack-got hijack-got.asm 
	
clean:
	rm -f $(OBJ) $(TARGET) isos_inject_memory isos_inject_address a.out entry-point hijack-got

