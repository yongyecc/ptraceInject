# 概述

本项目是基于arm平台的ptrace注入，可用于手游破解、外挂等领域。



## dlopen/dlsym原理

获取dlopen/dlsym函数在内存空间的地址，通过修改pc程序寄存器的值为获取的函数地址，就可以执行这两个函数，接着讲我们需要注入的so模块路径名写入参数寄存器中，即可完成so库的注入



## shellcode原理

和上面的思路基本一样，只是将dlopen/dlsym操作写到shellcode中，然后将函数地址，参数地址都写到shellcode的变量里，接着将shellcode映射进被注入进程内存，将pc寄存器指向shellcode在内存的起始地即可



# 用法





# 模块

