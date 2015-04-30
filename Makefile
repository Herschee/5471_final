all: sslserver.c sslclient.c 
	 gcc -Wall -o server sslserver.c -L/usr/lib -lssl -lcrypto 
	 gcc -Wall -o client sslclient.c -L/usr/lib -lssl -lcrypto 
	 rm -f cert.log	


clean:
	 rm -f server *.o
	 rm -f client *.o
	 rm -f cert.log
