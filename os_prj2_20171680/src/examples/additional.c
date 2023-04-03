#include <stdio.h>
#include <string.h>
#include <syscall.h>

int s_to_i(char* str){
    int result=0,times=1;
    for(int i=strlen(str)-1 ;i >= 0 ;i--){
        result += times * (str[i] - '0');
        times*=10;
    }
    return result;
}

int
main (int argc, char **argv)
{
  int i;
  int a = s_to_i(argv[1]);
  int b = s_to_i(argv[2]);
  int c = s_to_i(argv[3]);
  int d = s_to_i(argv[4]);

  //printf("---d---: %d\n\n\n",d);
  printf("%d ",fibonacci(a));
  printf("%d\n", max_of_four_int(a,b,c,d));

  return EXIT_SUCCESS;
}