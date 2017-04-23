LinkedLib += -lssl -lcrypto
all:
	gcc -o secuserver server.c $(LinkedLib)
	gcc -o secuclient client.c $(LinkedLib)
