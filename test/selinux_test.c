/* Copyright 2021 北京万里红科技有限公司
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
  char buf[1000];

  int ret = setcon("u:r:kernel:s0");
  printf("setcon %d\n", ret);
  ret = setexeccon("u:r:kernel:s0");
  printf("setexeccon %d\n", ret);

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
