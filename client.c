#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>

#include <errno.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>



#define MYPORT 10086
#define BUFFER_SIZE 1024
#define CAFILE "/home/wangjinwen/Desktop/OpenSSL/demoCA/cacert.pem"

//验证服务器端证书,成功返回1，否则失败
static int verify_cb(int res, X509_STORE_CTX *xs){
	
    printf("SSL VERIFY RESULT:%d\n",res);
    switch(xs->error){
	case X509_V_ERR_UNABLE_TO_GET_CRL:
	    printf("NOT GET CRL!\n");
	    return 1;
	default:
	    break;
    }
    return res;

}




//显示服务器端证书信息
void ShowCerts(SSL * ssl){
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if(cert != NULL){
	printf("**********数字证书信息**********\n");
	line = X509_NAME_oneline(X509_get_subject_name(cert),0,0);
	printf("证书：%s \n",line);
	free(line);
	line = X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
	printf("颁发者：%s \n",line);
	free(line);
	X509_free(cert);
    }
    else{
	printf("无证书信息！\n");
    }
}


int main(int argc,char** argv){
    //SSL上下文
    SSL_CTX *ctx;
    SSL *ssl;
    //SSL库初始化
    SSL_library_init();
    //加载所有OpenSSL算法
    OpenSSL_add_all_algorithms();
    //加载所有OpenSSL错误信息
    SSL_load_error_strings();
    //用兼容2、3版本模式创建SSL上下文
    ctx = SSL_CTX_new(SSLv23_client_method());
    if(ctx == NULL){
	perror("Producing SSL Context Fails!");
	exit(1);
    }
    
    //注册证书验证函数
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,verify_cb);
    //注册证书链验证长度
    SSL_CTX_set_verify_depth(ctx,10);
    //加载CA根证书
    SSL_CTX_load_verify_locations(ctx,argv[1],NULL);
    


    //定义sockfd
    int sock_cli = socket(AF_INET,SOCK_STREAM,0);
    
    //定义sockaddr_in
    struct sockaddr_in servaddr;
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(MYPORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    //连接服务器，成功返回0，错误返回-1
    if(connect(sock_cli,(struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
	perror("Client Connection Fails!");
	exit(1);
    }

    //基于ctx生成SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,sock_cli);
    //建立SSL连接
    if(SSL_connect(ssl) == -1){
	perror("SSL Connection Fails!");
    }
    else{
	ShowCerts(ssl);
    }



    char sendbuf[BUFFER_SIZE];
    char recvbuf[BUFFER_SIZE];
    while(fgets(sendbuf,sizeof(sendbuf),stdin) != NULL){
	SSL_write(ssl,sendbuf,strlen(sendbuf));
	//send(sock_cli, sendbuf, strlen(sendbuf), 0);
	if(strcmp(sendbuf,"exit\n") == 0)
	    break;
	SSL_read(ssl,recvbuf,sizeof(recvbuf));
	//recv(sock_cli, recvbuf, sizeof(recvbuf), 0);
	fputs(recvbuf, stdout);

	memset(sendbuf, 0, sizeof(sendbuf));
	memset(recvbuf, 0, sizeof(recvbuf));
    }
    //断开SSL
    SSL_shutdown(ssl);
    //释放ssl
    SSL_free(ssl);
    close(sock_cli);
    //释放上下文
    SSL_CTX_free(ctx);
    return 0;
}







