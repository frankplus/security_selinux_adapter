1. 同步 OpenHarmony 代码

https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-standard-package-environment.md

按照步骤同步主线 L2 代码。


2. 下载本仓库

https://gitee.com/openharmony-sig/third_party_selinux.git -> third_party/selinux/


3. 同步其他仓库

productdefine/common/     <- https://gitee.com/hu-huifeng/productdefine_common.git
third_party/toybox/       <- https://gitee.com/hu-huifeng/third_party_toybox.git
base/security/permission/ <- https://gitee.com/hu-huifeng/security_permission.git
base/startup/init_lite/   <- https://gitee.com/shell_way/startup_init_lite.git


4. 进行编译

./build/prebuilts_download.sh
./build.sh --product-name Hi3516DV300


5. 运行验证

3) ls -lZ /         # 看标签是否成功
4) ps -eZ           # 看标签是否成功
5) setenforce 1     # 进行各种操作，观察是否被拦截，以及串口是否有 avc denied

demoloop 命令暂时不验证。

