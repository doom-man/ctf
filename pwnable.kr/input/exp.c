#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void){
	char * arg[101] ;
	arg[100]=NULL;
	int pid ;
	int pipefd[2];
	int errpipefd[2];
	char * env[2]  ={"\xde\xad\xbe\xef=\xca\xfe\xba\xbe",NULL};
	struct sockaddr_in sock_addr;
	int sockfd;
	for(int i = 0 ; i < 100 ;i++)
	{
		arg[i] = "a";
	}
	arg['A']="\x00";
	arg['B']="\x20\x0a\x0d";
	if(pipe(pipefd)<0 || pipe(errpipefd)<0)
		exit(0);
	write(pipefd[1] , "\x00\x0a\x00\xff", 4);
	write(errpipefd[1] , "\x00\x0a\x02\xff",4);

	FILE * fp = fopen("\x0a","w");
	if(!fp) return 0;
	if(fwrite("\x00\x00\x00\x00",4,1,fp)!=1) return 0;
	fclose(fp);
	arg['C'] = "8000";
	if((pid = fork())<0) exit(0);
// 	child
	 if(pid == 0) 
	{
		sleep(1);
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
	}
	else
	{
		dup2(pipefd[0],0);
		dup2(errpipefd[0],2);
        execve("input",arg,env);
	}
	return 0;
}
