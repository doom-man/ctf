#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void){
        int fd[2] = {0} ;
        int pid;
        int num=0;
        char buf[20];
        char input[200];
        setvbuf(stdout,0,2,0);
        if(pipe(fd)<0) exit(0);
        srand(time(0));
       for(int i = 0 ; i < 30 ;i++){
               int len;
                sprintf(buf,"%d\n",rand()&0xf);
               write(fd[1],buf,20);
              len = strlen(buf);
              printf("output : %s\n",buf);
              strcpy(&input[num],buf);
             num = num+len;
                  }
       int clientSocket=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in clientsock_in;
        clientsock_in.sin_addr.s_addr=inet_addr("127.0.0.1");
        clientsock_in.sin_family=AF_INET;
        clientsock_in.sin_port=htons(32233);
        connect(clientSocket,(struct sockaddr *)&clientsock_in,sizeof(struct sockaddr));
       char receiveBuf[1000];
       read(clientSocket,receiveBuf,1000);
       read(clientSocket,receiveBuf,1000);
       memset(receiveBuf,0,sizeof(receiveBuf));
       for(int i = 0 ; i < 30 ; i++){
               write(clientSocket,input,200);
               printf("\n%s\n",buf);
               read(clientSocket,receiveBuf,1000);
               printf("%s",receiveBuf);
               memset(receiveBuf,0,sizeof(receiveBuf));
       }
       read(clientSocket,receiveBuf,1000);
       printf("%s",receiveBuf);
       return 0;
}