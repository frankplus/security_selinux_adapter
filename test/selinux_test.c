/* Copyright (c) 2021 北京万里红科技有限公司
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

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <selinux/selinux.h>
#include <securec.h>

#define BUFFLEN (1000)

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    char buf[BUFFLEN];
    const sleepSeconds = 5;

    int ret = setcon("u:r:kernel:s0");
    printf("setcon %d\n", ret);
    ret = setexeccon("u:r:kernel:s0");
    printf("setexeccon %d\n", ret);

    sleep(sleepSeconds);

    while (1) {
        sleep(1);
        fp = fopen("/data/abcd.txt", "r");
        if (fp != NULL) {
            if (memset_s(buf, sizeof(buf), 0, BUFFLEN) != 0) {
                continue;
            }
            fread(buf, 1, BUFFLEN, fp);
            fclose(fp);
            printf("buf1 %s\n", buf);
        }

        sleep(1);
        fp = fopen("/data/abcd2.txt", "r");
        if (fp != NULL) {
            if (memset_s(buf, sizeof(buf), 0, BUFFLEN) != 0) {
                continue;
            }
            fread(buf, 1, BUFFLEN, fp);
            fclose(fp);
            printf("buf2 %s\n", buf);
        }

        sleep(1);
        fp = fopen("/data/abcd3.txt", "r");
        if (fp != NULL) {
            if (memset_s(buf, sizeof(buf), 0, BUFFLEN) != 0) {
                continue;
            }
            fread(buf, 1, BUFFLEN, fp);
            fclose(fp);
            printf("buf3 %s\n", buf);
        }
    }

    return 0;
}
