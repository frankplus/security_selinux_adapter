1. 同步 OpenHarmony 代码

https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-standard-package-environment.md

按照步骤同步主线 L2 代码。


2. 进行编译

./build/prebuilts_download.sh
./build.sh --product-name Hi3516DV300 --gn-args support_selinux=true


3. 运行验证

1) ls -lZ /         # 看标签是否成功
2) ps -eZ           # 看标签是否成功
3) setenforce 1     # 进行各种操作，观察是否被拦截，以及串口是否有 avc denied

demoloop 命令暂时不验证。

