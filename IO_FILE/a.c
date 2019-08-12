#include <stdio.h>
#include <stdlib.h>

char * msg = "secret";
char * buf = "fakesecret";
FILE * fp;
int main(void){
    fp = fopen("p.c","rw");
    fp->_flags &= ~8;
    fp->_flags |= 0x800;
//    fp->_IO_write_base = msg;
//    fp->_IO_write_ptr = msg+5;
    fp->_IO_read_end = fp->_IO_write_base;
    fp->_fileno = 1;
    fwrite(buf,1,0x100,fp);
    fclose(fp);
    return 0;
}
