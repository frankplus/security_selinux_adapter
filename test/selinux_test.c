#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

extern int setcon(const char *con);

extern int setexeccon(const char *con);

int main(int argc, char *argv[]) {
  FILE *fp = NULL;

  int ret = setcon("u:r:kernel:s0");
  printf("setcon %d\n", ret);
  ret = setexeccon("u:r:kernel:s0");
  printf("setexeccon %d\n", ret);
  char buf[1000];
  sleep(5);
  while (1) {
    fp = fopen("/data/abcd.txt", "r");
    if (fp != NULL) {
      memset(buf, 0, 1000);
      fread(buf, 1, 100, fp);
      fclose(fp);
      printf("buf1 %s\n", buf);
    }
    sleep(1);

    fp = fopen("/data/abcd2.txt", "r");
    if (fp != NULL) {
      memset(buf, 0, 1000);
      fread(buf, 1, 100, fp);
      fclose(fp);
      printf("buf2 %s\n", buf);
    }
    sleep(1);

    fp = fopen("/data/abcd3.txt", "r");
    if (fp != NULL) {
      memset(buf, 0, 1000);
      fread(buf, 1, 100, fp);
      fclose(fp);
      printf("buf3 %s\n", buf);
    }
    sleep(1);
  }

  return 0;
}
