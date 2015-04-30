//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc/malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/sha.h>
 
#define FAIL    -1
 
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}

char **createAuds(int num){
	int i;
	char *audLenString = "auditor*";
	char **auditorList = malloc((sizeof(char*) * num));
	for(i = 0; i < num; i++){
		char *audString = malloc(sizeof(char)*strlen(audLenString));
		char id[2];
		sprintf(id, "%d", i);
		strcpy(audString, "auditor");
		char *cpy = malloc(sizeof(char)*strlen(audLenString));
		strcpy(cpy, audString);
		strcat(cpy,id);
		auditorList[i] = cpy;
		
	}
	return auditorList;
	
}


char *padCert(char *certificate, char *audId){
	char *padded = malloc(sizeof(char)*(strlen(certificate)+strlen(audId)));
	strcpy(padded,certificate);
	strcat(padded,audId);
	
	return padded;
	
	
}




int sendToRemainingAuds(char *request, char **listAuds, int numAuds){
	int i;
	int t;
	for(i = 1; i < numAuds+1; i++){
		char *auditorSign = malloc(sizeof(char) * 9);
		int j;
		printf("%s\n", request);
		printf("%d\n", strlen(request));
		int z = 0;
		for(j = strlen(request) - 8; j < strlen(request); j++){
			auditorSign[z] = request[j];
			z++;
			
		}
		auditorSign[z] = '\0';
		char testAud[] = "auditor\0";
		char id[2];
		t = i;
		t = t - 1;
		sprintf(id, "%d", t);
		printf("%s\n",id);
		strcat(testAud, id);
		printf("%s\n",testAud);
		printf("%s\n", auditorSign);
		if((strcmp(auditorSign, testAud)) == 0){
			request = padCert(request, listAuds[i]);
			
		}else{
			printf("Malicious!!!\n");
			return -1;
		}
		
	}
	return 1;
}


int sendToLog(char *request, char **listAuds, int numAuds){
	FILE *fp = fopen("cert.log", "ab");
	if(fp != NULL){
		fputs(request, fp);
		fclose(fp);
		if(sendToRemainingAuds(request,listAuds,numAuds)){
			return 1;
		}
		else{
			return -1;
		}
	}
	else{
		return -1;
	}
	
	
	
}


int sendToFirstAuditor(char *certificate, char *auditor, char **listAuds, int numAuds){
	char *firstRequest = padCert(certificate, auditor);
	printf("%s\n",firstRequest);
	if(sendToLog(firstRequest, listAuds,numAuds)){
		return 1;
	}
	return 0;
}

int check(char *certificate, char **listAuds, int numAuds){
	//send to first auditor
	if(sendToFirstAuditor(certificate, listAuds[0], listAuds,numAuds)){
		return 1;
	}
	else{
		printf("Failed to send to first auditor\n");
		return -1;
	}
	
}

SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    char *portnum;
    int numAuds;
 
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 3 )
    {
        printf("Usage: %s <portnum> <number of auditors>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
 
    portnum = strings[1];
    numAuds = atoi(strings[2]);
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    
    
    
    //parsing certificate
	char * buffer = 0;
	long length;
	FILE * f = fopen ("mycert.pem", "rb");

	if (f)
	{
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		//start of certificate in mycert.pem
		fseek (f, 944, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, f);
		}
	fclose (f);
	}
	
	
	
	char *certificate = malloc(sizeof(char) * 2048);
	
	//getting rid of ---END CERTIFICATE--- text
	int j;
	for(j = 0; j< strlen(buffer)-27; j++){
		certificate[j] = buffer[j];
	} 
	char **auditors = createAuds(numAuds);
	int i;

	printf("%s\n",auditors[0]);	
	int certFlag = 0;
	if(check(certificate,auditors,numAuds)){
		certFlag = 1;
		printf("here\n");
	}
	
	
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}

