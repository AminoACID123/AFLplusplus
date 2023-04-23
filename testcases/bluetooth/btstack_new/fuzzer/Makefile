

all: fuzz

fuzz: btfuzz_main.c btfuzz.c btfuzz_util.c
	gcc -g  btfuzz_main.c btfuzz.c btfuzz_util.c -o fuzzer

clean:
	rm fuzz
	rm *.o
