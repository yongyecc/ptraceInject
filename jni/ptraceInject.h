/**********************************
 *  FileName:   ptraceInject.h
 *  Decription: ptrace注入
 * ********************************/

#include <stdio.h>    
#include <stdlib.h>       
#include <unistd.h> 

#define  MAX_PATH 0x100

/* 功能1：通过ptrace远程调用dlopen/dlsym方式注入模块到远程进程 */
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter);

/* 功能2：通过shellcode方式注入模块到远程进程*/
int inject_remote_process_shellcode(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter);
