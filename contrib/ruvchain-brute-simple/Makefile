.PHONY: all

all: util ruvchain-brute-multi-curve25519 ruvchain-brute-multi-ed25519

util: util.c
	gcc -Wall -std=c89 -O3 -c -o util.o util.c

ruvchain-brute-multi-ed25519: ruvchain-brute-multi-ed25519.c util.o
	gcc -Wall -std=c89 -O3 -o ruvchain-brute-multi-ed25519 -lsodium ruvchain-brute-multi-ed25519.c util.o

ruvchain-brute-multi-curve25519: ruvchain-brute-multi-curve25519.c util.o
	gcc -Wall -std=c89 -O3 -o ruvchain-brute-multi-curve25519 -lsodium ruvchain-brute-multi-curve25519.c util.o
