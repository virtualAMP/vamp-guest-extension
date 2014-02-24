all: vdiguest

vdiguest: vdiguest.c
	gcc -o $@ $<
