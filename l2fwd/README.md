# Use Guide

- Dependent on the DPDK 18.08 runtime environment

```
$ git clone https://github.com/JmilkFan/dpdk-samples.git
$ cd dpdk-samples

$ cd l2fwd
$ source dpdk.rc

$ make
$ ll build/l2fwd

$ ./build/l2fwd -l 1-2 -- -p 0x3 -q 2 --mac-updating
```

# Documents
```
$ cd l2fwd
$ source dpdk.rc

$ doxygen doxyconfig
$ ll ./docs/index.html
```

# Blog
[《DPDK — L2 Forwarding 与网卡设备初始化流程》](https://blog.csdn.net/Jmilk/article/details/129556138)
