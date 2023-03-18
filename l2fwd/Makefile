# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# 二进制可执行文件名
APP = l2fwd

# SRCS-y 指定所有源文件
SRCS-y := main.c

# 用于检查系统中是否安装了 DPDK，并且可以通过 pkg-config 工具找到 DPDK 库。
# pkg-config 是一个在 Linux 工具，用于返回安装在系统中的库和头文件的路径。
# --exists 选项告诉 pkg-config 只检查 libdpdk 库是否存在，并返回一个退出代码。
# 如果返回值是 0，则说明 libdpdk 库存在。并赋值给 shell 变量。
$(shell pkg-config --exists libdpdk)

# .SHELLSTATUS 是一个特殊变量，用于表示前一个命令的退出状态码。
ifeq ($(.SHELLSTATUS),0)

# make 指令默认操作。
all: shared

# .PHONY 声明了 shared 和 static 这两种操作目标。
.PHONY: shared static
# 执行动态链接模式。
shared: build/$(APP)-shared
    # 将目标文件 build/$(APP)-shared 链接为 build/$(APP)
	ln -sf $(APP)-shared build/$(APP)
# 执行静态链接模式。
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell pkg-config --path libdpdk)        # --path 获取 libdpdk 库的路径
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)   # 将 -03（编译优化选项）和 libdpdk 库的编译选项添加到 CFLAGS。

LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)  # 将 libdpdk 库的动态链接选项添加到 LDFLAGS_SHARED。
LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk)  # 将 -Wl,-Bstatic（GCC 选项）和 libdpdk 库的静态链接选项添加到 LDFLAGS_STATIC。

# 具体的动态链接指令。
build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)
# CFLAGS 内置变量，用于存储编译器选项，如：警告等级、优化级别、调试标志等。
# LDFLAGS 内置变量，用于存储链接器选项，如：库搜索路径、链接库等。
# $(CC) 内置变量，表示编译器。
# -o $@ 内置变量，表示输出的目标文件名，为 build/$(APP)-shared。
# $(LDFLAGS) 内置变量，表示常规链接选项。

# 具体的静态连接选项指令。
build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)


build:
	@mkdir -p $@


# .PHONY 声明了 clean 操作目标。
.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	rmdir --ignore-fail-on-non-empty build


else # 使用旧的编译方式。

ifeq ($(RTE_SDK),)  # 判断编译环境变量 $RTE_SDK 是否为空。
$(error "Please define RTE_SDK environment variable")
endif

# 被环境变量 $RTE_TARGET 覆盖。
RTE_TARGET ?= x86_64-native-linuxapp-gcc

# 导入 RTE variables mk
include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -O3 
CFLAGS += $(WERROR_FLAGS)

################
# NOTE：fguiju
# 添加 DEBUG 参数
CFLAGS += -g3 -DDEBUG
################

# 导入 RTS extend app mk
include $(RTE_SDK)/mk/rte.extapp.mk


endif