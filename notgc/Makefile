all: libgc.so libgc.so.1

libgc.so: notgc.c
	$(CC) -O3 -g -fpic notgc.c -shared -Wl,-soname,libgc.so -o libgc.so

libgc.so.1:
	ln -s libgc.so libgc.so.1
