# security_selinux

## 目标

SELinux （安全增强式 Linux ， Security-Enhanced Linux ）是 Linux 历史上最杰出的新安全子系统。 SELinux SIG 的工作目标是将 SELinux 引入 OpenHarmony ，至少在运行 OpenHarmony 的 L2 设备上实现访问控制。

> 1. SELinux 是一组内核修改和用户空间工具，其提供了访问控制安全策略机制，包括了强制访问控制（ Mandatory Access Control ， MAC ）。
> 2. SELinux 已经被添加到各种 Linux 发行版中。其软件架构力图将安全决策的执行与安全策略分离，并简化涉及执行安全策略的软件的数量。

## 仓库

目前涉及到的仓库有以下几个。

| 仓库 | 源码目录 | 说明 |
| --- | --- | --- |
| [security_selinux](https://gitee.com/shell_way/security_selinux.git) | `base/security/selinux/` | 策略和一些自研接口 |
| [third_party_selinux](https://gitee.com/openharmony-sig/third_party_selinux.git) | `third_party/selinux/` | SELinux 的主仓库 |
| [productdefine_common](https://gitee.com/hu-huifeng/productdefine_common.git) | `productdefine/common/` | 添加 SELinux 组件定义 |
| [third_party_toybox](https://gitee.com/hu-huifeng/third_party_toybox.git) | `third_party/toybox/` | 完善了 `ls` 的 SELinux 支持 |
| [startup_init_lite](https://gitee.com/shell_way/startup_init_lite.git) | `base/startup/init_lite/` | 系统启动加载策略并分化服务的标签 |
| [third_party_FreeBSD](https://gitee.com/shell_way/third_party_FreeBSD.git) | `third_party/FreeBSD/` | 提供 fts 库 |
| [third_party_pcre2](https://gitee.com/shell_way/third_party_pcre2.git) | `third_party/pcre2/` | 提供 pcre2 库 |
| [build](https://gitee.com/openharmony/build.git) | `build/` | 编译控制 |

> 当前未合入主线，其中链接了一些个人仓库。

## 架构

![整体架构](docs/images/整体架构.png)

在 [third_party_selinux](https://gitee.com/openharmony-sig/third_party_selinux.git) 中使用了下面四个 SELinux 的组件和两个其他的依赖组件。

| 组件 | 来源 | 作用 | 形式 |
| --- | --- | --- | --- |
| `checkpolicy/` | [selinux/checkpolicy](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/checkpolicy) | `checkpolicy` | 可执行文件 |
| `libselinux/` | [selinux/libselinux](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libselinux) | `libselinux.so`、`getenforce`、`setenforce` | 动态库 |
| `libsepol/` | [selinux/libsepol](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/libsepol) | 提供内部使用的 API | 动态库 |
| `seclic/` | [selinux/seclic](https://github.com/SELinuxProject/selinux/tree/cf853c1a0c2328ad6c62fb2b2cc55d4926301d6b/secilc) | `seclic` | 可执行文件 |
| `depends/fts/` | [openbsd](https://github.com/openbsd/src/tree/e8835b178a3e9df00c1c1fe0b9875fc5ef5a7854) | 提供 fts | 静态链接 |
| `depends/pcre/pcre2/` | [pcre2](https://github.com/PhilipHazel/pcre2/tree/2ae7c30b95d63ecbaff6727eaff7c3a6a3969d56) | 提供 `libpcre2.so` | 动态库 |

## 编译

### 同步 OpenHarmony 代码

按照[该文档](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/quickstart-standard-package-environment.md)同步主线 L2 代码。

### 同步所需仓库

| 目录 | 仓库 |
| --- | --- |
| `base/security/selinux/` | `https://gitee.com/shell_way/security_selinux.git` |
| `third_party/selinux/` |  `https://gitee.com/openharmony-sig/third_party_selinux.git` |
| `productdefine/common/` | `https://gitee.com/hu-huifeng/productdefine_common.git` |
| `third_party/toybox/` | `https://gitee.com/hu-huifeng/third_party_toybox.git` |
| `base/startup/init_lite/` | `https://gitee.com/shell_way/startup_init_lite.git` |
| `third_party/FreeBSD/` | `https://gitee.com/shell_way/third_party_FreeBSD.git` |
| `third_party_pcre2` | `https://gitee.com/shell_way/third_party_pcre2.git` |
| `build/` | `https://gitee.com/shell_way/build.git` |

### 进行编译

```
./build/prebuilts_download.sh
./build.sh --product-name Hi3516DV300 --gn-args "support_selinux=true"
```

### 运行验证

将镜像烧录到 Hi3516DV300 开发板上。

```
ls -lZ /         # 查看文件标签是否成功
ps -eZ           # 查看进程标签是否成功
setenforce 1     # 进行各种操作，观察是否被拦截，以及串口是否有 avc denied
```

