CC=gcc
CFLAGS=-Wall -Wextra -pedantic -O2

.PHONY: clean build run

build:
	$(CC) -x c -E filter.bpf -o filter.prep.bpf
	# C macros expand to a single line...
	sed -i 's/@/\n/g' filter.prep.bpf
	# And seccomp-tools misplaces errors if lines end with a space
	sed -i 's/[ \t]*$$//' filter.prep.bpf
	seccomp-tools asm filter.prep.bpf -f c_array -o filter.h
	$(CC) main.c -o secure_comparator $(CFLAGS)
	strip -s secure_comparator
	python assembler.py checker.asm checker.bin

run: build
	./secure_comparator checker.bin

clean:
	-rm filter.h filter.prep.bpf secure_comparator checker.bin
