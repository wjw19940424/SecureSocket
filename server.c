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
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MYPORT 10086
#define QUEUE 20
#define BUFFER_SIZE 1024

int main(int argc,char **argv){
    //SSL上下文
    SSL_CTX *ctx;
    
    //SSL库初始化
    SSL_library_init();
    //载入所有SSL算法
    OpenSSL_add_all_algorithms();
    //载入所有SSL错误信息
    SSL_load_error_strings();
    //V2、V3兼容模式产生SSL上下文
    ctx = SSL_CTX_new(SSLv23_server_method());
    if(ctx == NULL){
	perror("Producing SSL_Context Fails!");
	exit(1);
    }
    //载入数字证书
    if(SSL_CTX_use_certificate_file(ctx,argv[1],SSL_FILETYPE_PEM) <= 0){
	perror("Loading Certificate Fails!");
	exit(1);
    }
    //载入服务器私钥
    if(SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM) <= 0){
	perror("Loading Private Key Fails!");
	exit(1);
    }
    //检查用户私钥正确性
    if(!SSL_CTX_check_private_key(ctx)){
	perror("Private Key Incorrect!");
	exit(1);
    }



    //定义sockfd
    //printf("Start!");
    int server_sockfd = socket(AF_INET,SOCK_STREAM,0);

    //定义socketadr_in
    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(MYPORT);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);		
    //printf("end");
    //bind，成功返回0，出错返回-1
    if(bind(server_sockfd,(struct sockaddr*)&server_sockaddr,sizeof(server_sockaddr)) == -1){
	perror("Bind error!");
	exit(1);
    }
    //printf("Bind Success!");

    //listen，成功返回0，出错返回-1
    if(listen(server_sockfd,QUEUE) == -1){
	perror("Listen error!");
    }
    //printf("Listen Success!");    
    
    //客户端套接字
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);

    //成功接受客户端返回非负描述字，出错返回-1
    int conn = accept(server_sockfd,(struct sockaddr*)&client_addr,&length);
    if(conn<0){
	perror("Connection fails");
	exit(1);
    }

    //基于ctx产生新的SSL
    SSL *ssl;
    ssl = SSL_new(ctx);
    //将连接用户的sodket加入到SSL
    SSL_set_fd(ssl, conn);
    //建立SSL连接
    if(SSL_accept(ssl) == -1){
	perror("SSL Connection Fails!");
	close(conn);
    }



    while(1){
	memset(buffer,0,sizeof(buffer));
	socklen_t len = SSL_read(ssl,buffer,sizeof(buffer));
	//int len = recv(conn,buffer,sizeof(buffer),0);
	if(strcmp(buffer,"exit\n")==0)
	    break;
	fputs(buffer,stdout);
	SSL_write(ssl,buffer,sizeof(buffer));
	//send(conn,buffer,len,0);
    }
    //关闭SSL
    SSL_shutdown(ssl);
    //释放SSL
    SSL_free(ssl);
    close(conn);
    close(server_sockfd);
    //释放SSL上下文
    SSL_CTX_free(ctx);
    return 0;
}


















	
