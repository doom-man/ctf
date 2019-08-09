#include <stdio.h>
#include <stdlib.h>
#define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof(INTERNAL_SIZE_T))
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define MALLOC_ALIGNMENT       (2 * SIZE_SZ < __alignof__ (long double) \
				 ? __alignof__ (long double) : 2 * SIZE_SZ)
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)


#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

int main(void){
    printf("SIZE_SZ %ld\n",SIZE_SZ);
    printf("MALLOC_ALIGNMENT %ld\n",MALLOC_ALIGNMENT);
    printf("MALLOC_ALIGN_MASK %ld\n",MALLOC_ALIGN_MASK);
    printf("MIN_CHUNK_SIZE %ld\n",MIN_CHUNK_SIZE);
    printf("%ld\n",(unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE));
    return 0;
}