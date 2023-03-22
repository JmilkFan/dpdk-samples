# Use Guide

- Dependent on the DPDK 18.08 runtime environment

```
$ git clone https://github.com/JmilkFan/dpdk-samples.git
$ cd dpdk-samples

$ cd l3fwd
$ source dpdk.rc

$ make
$ ll build/l3fwd

$ ./build/l3fwd -l 1 -- -p 0x3 -P --config="(0,0,1),(1,0,1)" --parse-ptype --eth-dest=0,52:54:00:4a:1f:6d --eth-dest=1,52:54:00:53:5a:d2
```

# Documents
```
$ cd l3fwd
$ source dpdk.rc

$ doxygen doxyconfig
$ ll ./docs/index.html
```

# Blog
[《DPDK — L3 Forwarding 与 IP 路由匹配算法》](https://blog.csdn.net/Jmilk/article/details/129673463)
