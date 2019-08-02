#include <stdio.h>

int main(void){
char a[20];
read(0,a,4);
printf("stdin:%s",a);
read(2,a, 4);
printf("stderr:%s",a);
return 0;
}
