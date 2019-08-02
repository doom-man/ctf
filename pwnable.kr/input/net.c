#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void){
    struct sockaddr_in saddr;
    int fd;
    fd = socket(AF_INET , SOCK_STREAM , 0);
    if(fd == -1)
    {
        printf("scoket error \n");
        return 0;
    }
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    saddr.sin_port = htons(8000);
    if(-1 == connect(fd , (struct sockaddr *)&saddr , sizeof(saddr)))
    {
        printf("connect error\n");
        return 0;
    }
    write(fd , "\xde\xad\xbe\xef",4);
    printf("printf message sending \n");

    return 0;
}