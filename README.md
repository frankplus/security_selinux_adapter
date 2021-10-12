# security_selinux

## 目标

SELinux （安全增强式 Linux ， Security-Enhanced Linux ）是 Linux 历史上杰出的安全子系统。 SELinux SIG 的工作目标是将 SELinux 引入 OpenHarmony 。

> 1. SELinux 是一组内核修改和用户空间工具，其提供了访问控制安全策略机制，包括了强制访问控制（ Mandatory Access Control ， MAC ）。
> 2. SELinux 已经被添加到各种 Linux 发行版中。其软件架构力图将安全决策的执行与安全策略分离，并简化涉及执行安全策略的软件的数量。

## 仓库

目前（2021年10月9日15:43:21）涉及到的仓库有以下几个。

| 仓库 | 源码目录 | 说明 |
| --- | --- | --- |
| [security_selinux](https://gitee.com/openharmony-sig/security_selinux.git) | `base/security/selinux/` | 策略和一些自研接口 |
| [third_party_selinux](https://gitee.com/openharmony-sig/third_party_selinux.git) | `third_party/selinux/` | SELinux 的主仓库 |
| [productdefine_common](https://gitee.com/shell_way/productdefine_common.git) | `productdefine/common/` | 添加 SELinux 组件定义 |
| [third_party_toybox](https://gitee.com/shell_way/third_party_toybox.git) | `third_party/toybox/` | 完善了 `ls` 的 SELinux 支持 |
| [startup_init_lite](https://gitee.com/shell_way/startup_init_lite.git) | `base/startup/init_lite/` | 系统启动加载策略并分化服务的标签 |
| [third_party_FreeBSD](https://gitee.com/shell_way/third_party_FreeBSD.git) | `third_party/FreeBSD/` | 提供 fts 库 |
| [third_party_pcre](https://gitee.com/openharmony-sig/third_party_pcre.git) | `third_party/pcre/` | 提供 pcre2 库 |
| [build](https://gitee.com/shell_way/build.git) | `build/` | 编译控制 |

## 架构

### 整体架构

![整体架构](docs/images/整体架构.png)

在 [third_party_selinux](https://gitee.com/openharmony-sig/third_party_selinux.git) 中使用了下面四个 SELinux 的组件和两个其他的依赖组件。

| 组件 | 来源 | 作用 | 形式 |
| --- | --- | --- | --- |
| `checkpolicy/` | [selinux/checkpolicy](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/checkpolicy) | `checkpolicy` | 可执行文件 |
| `libselinux/` | [selinux/libselinux](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libselinux) | `libselinux.so`、`getenforce`、`setenforce` | 动态库 |
| `libsepol/` | [selinux/libsepol](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libsepol) | 提供内部使用的 API | 动态库 |
| `seclic/` | [selinux/seclic](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/secilc) | `seclic` | 可执行文件 |
| `depends/fts/` | [openbsd](https://github.com/openbsd/src/tree/e8835b178a3e9df00c1c1fe0b9875fc5ef5a7854) | 提供 fts | 静态链接 |
| `depends/pcre/pcre/` | [pcre](https://github.com/PhilipHazel/pcre/tree/2ae7c30b95d63ecbaff6727eaff7c3a6a3969d56) | 提供 `libpcre2.so` | 动态库 |

> 本仓库主要位于图中的编译侧，在板侧有两个动态库供 init 调用三方库。

### 目录结构

```
.
├── config                  # 板侧    三方库配置文件
├── docs                    #         文档资源
│   └── images
├── interfaces
│   ├── policycoreutils     # 板侧    libload_policy.so、librestorecon.so
│   │   ├── include
│   │   └── src
│   └── tools               # 板侧    load_policy、restorecon
│       ├── load_policy
│       └── restorecon
├── scripts                 # 编译侧  策略编译脚本
├── sepolicy                # 编译侧  策略文件
└── test                    #         测试程序
```

## 验证

### 同步 OpenHarmony 代码

首先配置好环境。

```
sudo apt update
sudo apt install binutils git git-lfs gnupg flex bison gperf build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev ccache libgl1-mesa-dev libxml2-utils xsltproc unzip m4 bc gnutls-bin python3.8 python3-pip ruby
git config --global user.name "yourname"
git config --global user.email "your-email-address"
git config --global credential.helper store
sudo sh -c 'curl -s https://gitee.com/oschina/repo/raw/fork_flow/repo-py3 > /usr/local/bin/repo'
sudo chmod a+x /usr/local/bin/repo
sudo pip3 install -i https://repo.huaweicloud.com/repository/pypi/simple requests
```

然后开始同步代码。

```
mkdir -pv openharmony/
cd ./openharmony/
repo init -u https://gitee.com/openharmony/manifest.git -b master --no-repo-verify
repo sync -c
repo forall -c 'git lfs pull'
```

### 同步相关仓库

代码同步完毕后，依次同步以下仓库。

| 目录 | 仓库 |
| --- | --- |
| `base/security/selinux/` | `https://gitee.com/openharmony-sig/security_selinux.git` |
| `third_party/selinux/` |  `https://gitee.com/openharmony-sig/third_party_selinux.git` |
| `productdefine/common/` | `https://gitee.com/shell_way/productdefine_common.git` |
| `third_party/toybox/` | `https://gitee.com/shell_way/third_party_toybox.git` |
| `base/startup/init_lite/` | `https://gitee.com/shell_way/startup_init_lite.git` |
| `third_party/FreeBSD/` | `https://gitee.com/shell_way/third_party_FreeBSD.git` |
| `third_party/pcre` | `https://gitee.com/openharmony-sig/third_party_pcre.git` |
| `build/` | `https://gitee.com/shell_way/build.git` |

如果你不知道怎么做，可以进入到同步好的 OpenHarmony 代码目录，执行以下命令。

```
pushd ./base/security/
git clone https://gitee.com/openharmony-sig/security_selinux.git ./selinux/
popd

pushd ./third_party/
git clone https://gitee.com/openharmony-sig/third_party_selinux.git ./selinux/
popd

pushd ./productdefine/common/
git pull https://gitee.com/shell_way/productdefine_common.git
popd

pushd ./third_party/toybox/
git pull https://gitee.com/shell_way/third_party_toybox.git
popd

pushd ./base/startup/init_lite/
git pull https://gitee.com/shell_way/startup_init_lite.git
popd

pushd ./third_party/FreeBSD/
git pull https://gitee.com/shell_way/third_party_FreeBSD.git
popd

pushd ./third_party/pcre/
git clone https://gitee.com/openharmony-sig/third_party_pcre.git ./pcre/
popd

pushd ./build/
git pull https://gitee.com/shell_way/build.git
popd
```

### 进行编译

同步完成后，执行下面的命令编译项目，注意需要使用参数 `--gn-args "build_selinux=true"` 启用 SELinux 。

```
./build/prebuilts_download.sh
./build.sh --product-name Hi3516DV300 --gn-args "build_selinux=true"
```

### 运行验证

将镜像烧录到 Hi3516DV300 开发板上，开机，通过串口拿到 Shell ，在其中执行。

```
ls -lZ /         # 查看文件标签是否成功
ps -eZ           # 查看进程标签是否成功
setenforce 1     # 进行各种操作，观察是否被拦截，以及串口是否有 avc denied
```
