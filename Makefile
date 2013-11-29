all:
	gcc -w cryptfs.c `pkg-config fuse --cflags --libs` -o crypt -lcrypto
