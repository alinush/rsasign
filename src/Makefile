all:
	mkdir -p ../bin
	gcc -std=c99 hex.c rsa.c main.c -lcrypto -o ../bin/rsasign -Wall
	../scripts/genkeys.sh ../bin/keys
clean:
	rm -r ../bin/rsasign ../bin/keys
