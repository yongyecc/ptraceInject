/*******************************
 *  FileName: ptraceInject.c
 *  Description:       ptrace注入
 * *****************************/


#include <stdio.h>    
#include <stdlib.h>    
#include <sys/user.h>    
#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h> 
#include <PrintLog.h> 
#include <ptraceInject.h>

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";    
const char *linker_path = "/system/bin/linker";


/***************************
 *  Description:    使用ptrace Attach附加到指定进程,发送SIGSTOP信号给指定进程让其停止下来并对其进行跟踪。
 *                  但是被跟踪进程(tracee)不一定会停下来，因为同时attach和传递SIGSTOP可能会将SIGSTOP丢失。
 *                  所以需要waitpid(2)等待被跟踪进程被停下
 *  Input:          pid表示远程进程的ID
 *  Output:         无
 *  Return:         返回0表示attach成功，返回-1表示失败
 *  Others:         无
 * ************************/
int ptrace_attach(pid_t pid)
{
    int status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
    {
        LOGD("ptrace attach error, pid:%d", pid);
        return -1;
    }

    LOGD("attach process pid:%d", pid);
    waitpid(pid, &status , WUNTRACED);
    return 0;
}

/*************************************************
 *   Description:    使用ptrace detach指定进程,完成对指定进程的跟踪操作后，使用该参数即可解除附加
 *   Input:          pid表示远程进程的ID
 *   Output:         无
 *   Return:         返回0表示detach成功，返回-1表示失败
 *   Others:         无
 * ***********************************************/
int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0)
    {
        LOGD("detach process error, pid:%d", pid);
        return -1;
    }
    LOGD("detach process pid:%d", pid);  
    return 0; 
}

/*************************************************
 *  Description:    ptrace使远程进程继续运行
 *  Input:          pid表示远程进程的ID
 *  Output:         无
 *  Return:         返回0表示continue成功，返回-1表示失败
 *  Others:         无
 * ***********************************************/
int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
    {
        LOGD("ptrace cont error, pid:%d", pid);
        return -1;
    }
    return 0;
}

/*************************************************
 *  Description:    使用ptrace获取远程进程的寄存器值
 *  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储了寄存器值 
 *  Output:         无
 *  Return:         返回0表示获取寄存器成功，返回-1表示失败
 *  Others:         无
 * ***********************************************/
int ptrace_getregs(pid_t pid, struct pt_regs *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0)
    {
        LOGD("Get Regs error, pid:%d", pid);
        return -1;
    }
    return 0;
}

/*************************************************
 *  Description:    使用ptrace设置远程进程的寄存器值
 *  Input:          pid表示远程进程的ID，regs为pt_regs结构，存储需要修改的寄存器值
 *  Output:         无
 *  Return:         返回0表示设置寄存器成功，返回-1表示失败
 * ***********************************************/
int ptrace_setregs(pid_t pid, struct pt_regs *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0)
    {
        LOGD("Set Regs error, pid:%d", pid);
        return -1;
    }
    return 0;
}

/*************************************************
 *  Description:    获取返回值，ARM处理器中返回值存放在ARM_r0寄存器中
 *  Input:          regs存储远程进程当前的寄存器值
 *  Return:         在ARM处理器下返回r0寄存器值 
 * ***********************************************/
long ptrace_getret(struct pt_regs * regs)
{
    return regs->ARM_r0;
}

/*************************************************
 *  Description:    获取当前执行代码的地址，ARM处理器下存放在ARM_pc中
 *  Input:          regs存储远程进程当前的寄存器值
 *  Return:         在ARM处理器下返回pc寄存器值
 * **********************************************/
long ptrace_getpc(struct pt_regs * regs)    
{       
    return regs->ARM_pc;    
} 

/*************************************************
 *   Description:    使用ptrace从远程进程内存中读取数据
 *   Input:          pid表示远程进程的ID，pSrcBuf表示从远程进程读取数据的内存地址
 *                   pDestBuf表示用于存储读取出数据的地址，size表示读取数据的大小
 *   Return:         返回0表示读取数据成功
 *   other:          这里的*_t类型是typedef定义一些基本类型的别名，用于跨平台。例如
 *                   uint8_t表示无符号8位也就是无符号的char类型
 * **********************************************/
int ptrace_readdata(pid_t pid, uint8_t *pSrcBuf, uint8_t *pDestBuf, uint32_t size)
{
    uint32_t nReadCount = 0;
    uint32_t nRemainCount = 0;
    uint8_t *pCurSrcBuf = pSrcBuf;
    uint8_t *pCurDestBuf = pDestBuf;
    long lTmpBuf = 0;
    uint32_t i = 0; 

    //每次读取4字节数据
    nReadCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);
    for (i = 0; i < nReadCount; i++)
    {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *)(&lTmpBuf), sizeof(long));
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }
    //当最后读取的字节不足4字节时调用
    if ( nRemainCount > 0 )
    {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *)(&lTmpBuf), nRemainCount);
    }
    return 0;
}

/*************************************************
 *  Description:    使用ptrace将数据写入到远程进程空间中
 *  Input:          pid表示远程进程的ID，pWriteAddr表示写入数据到远程进程的内存地址
 *                  pWriteData用于存储写入数据的地址，size表示写入数据的大小
 *  Return:         返回0表示写入数据成功，返回-1表示写入数据失败 
 * ***********************************************/
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData, uint32_t size)
{
    uint32_t nWriteCount = 0;
    uint32_t nRemainCount = 0;
    uint8_t *pCurSrcBuf = pWriteData;
    uint8_t *pCurDestBuf = pWriteAddr;
    long lTmpBuf = 0;
    uint32_t i = 0;

    nWriteCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    //数据以sizeof(long)字节大小为单位写入到远程进程内存空间中
    for (i = 0; i < nWriteCount; i ++)
    {
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0)
        {
            LOGD("Write Remote Memory error, MemoryAddr:0x%lx", (long)pCurDestBuf);
            return -1;
        }
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }
    if (nRemainCount > 0)
    {
        //lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurDestBuf, NULL);
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, nRemainCount);
        if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0)
        {
            LOGD("Write Remote Memory error, MemoryAddr:0x%lx", (long)pCurDestBuf);
            return -1;  
        }
    }
    return 0;
}

/*************************************************
 *  Description:    使用ptrace远程call函数
 *  Input:          pid表示远程进程的ID，ExecuteAddr为远程进程函数的地址
 *                  parameters为函数参数的地址，regs为远程进程call函数前的寄存器环境
 *  Return:         返回0表示call函数成功，返回-1表示失败
 * **********************************************/
int ptrace_call(pid_t pid, uint32_t ExecuteAddr, long *parameters, long num_params, struct pt_regs* regs)    
{
    int i=0;
    // ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for(i=0; i<num_params && i<4; i++)
    {
       regs->uregs[i] = parameters[i]; 
    }
    if(i < num_params)
    {
        regs->ARM_sp -= (num_params - i) * sizeof(long);
        if (ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&parameters[i], (num_params - i) * sizeof(long))  == -1)
        {
            return -1;
        }
    }

    //修改程序计数器
    regs->ARM_pc = ExecuteAddr; 

    //判断指令集
    // 与BX跳转指令类似，判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
    if (regs->ARM_pc & 1) 
    {
        /*Thumb*/
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    }
    else
    {
        /* ARM*/
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;
    
    //设置好寄存器后，开始运行进程
    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1)
    {
        LOGD("ptrace set regs or continue error, pid:%d", pid);
        return -1;
    }

    //对于ptrace_continue运行的进程，他会在三种情况下进入暂停状态：1.下一次系统调用 2.子进程出现异常 3.子进程退出
    //参数WUNTRACED表示当进程进入暂停状态后，立即返回
    //将存放返回地址的lr寄存器设置为0，执行返回的时候就会发生错误，从子进程暂停
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    LOGD("ptrace call ret status is %d\n", stat);
    //0xb7f表示子进程进入暂停状态
    while (stat != 0xb7f)
    {
        if (ptrace_continue(pid) == -1)
        {
           LOGD("ptrace call error"); 
           return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }
    // 获取远程进程的寄存器值，方便获取返回值
    if (ptrace_getregs(pid, regs) == -1)
    {
        LOGD("After call getregs error");
        return -1;
    }
    return 0;
}

/*************************************************
 *  Description:    在指定进程中搜索对应模块的基址
 *  Input:          pid表示远程进程的ID，若为-1表示自身进程，ModuleName表示要搜索的模块的名称
 *  Return:         返回0表示获取模块基址失败，返回非0为要搜索的模块基址
 * **********************************************/
void* GetModuleBaseAddr(pid_t pid, const char* ModuleName)
{
    char szFileName[50] = {0};
    FILE *fp = NULL;
    char szMapFileLine[1024] = {0};
    char *ModulePath, *MapFileLineItem;
    long ModuleBaseAddr = 0; 

    // 读取"/proc/pid/maps"可以获得该进程加载的模块
    if (pid < 0)
    {
        snprintf(szFileName, sizeof(szFileName), "/proc/self/maps"); 
    }
    else
    {
        snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", pid);   
    }
    
    fp = fopen(szFileName, "r");
    if (fp != NULL)
    {
        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp))
        {
            if (strstr(szMapFileLine, ModuleName))
            {
                MapFileLineItem = strtok(szMapFileLine, " \t");
                char *Addr = strtok(szMapFileLine, "-");
                ModuleBaseAddr = strtoul(Addr, NULL, 16 );

                if (ModuleBaseAddr == 0x8000)
                {
                    ModuleBaseAddr = 0;
                }
                break;
            }
        }
        fclose(fp);
    }
    return (void *)ModuleBaseAddr;
}

/*************************************************
 *  Description:    获取远程进程与本进程都加载的模块中函数的地址
 *  Input:          pid表示远程进程的ID，ModuleName表示模块名称，LocalFuncAddr表示本地进程中该函数的地址
 *  Return:         返回远程进程中对应函数的地址
 * ***********************************************/
void* GetRemoteFuncAddr(pid_t pid, const char *ModuleName, void *LocalFuncAddr)
{
    void *LocalModuleAddr, *RemoteModuleAddr, *RemoteFuncAddr;
    LocalModuleAddr = GetModuleBaseAddr(-1, ModuleName);
    RemoteModuleAddr = GetModuleBaseAddr(pid, ModuleName);
    RemoteFuncAddr = (void *)((long)LocalFuncAddr - (long)LocalModuleAddr + (long)RemoteModuleAddr);
    return RemoteFuncAddr;
}

/*************************************************
 *  通过远程直接调用dlopen\dlsym的方法ptrace注入so模块到远程进程中
 *  Input:          pid表示远程进程的ID，LibPath为被远程注入的so模块路径，FunctionName为远程注入的模块后调用的函数
 *                  FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中），NumParameter为参数的个数
 *  Return:         返回0表示注入成功，返回-1表示失败
 * ***********************************************/
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, long *FuncParameter, long NumParameter)
{
    int iRet = -1;
    struct pt_regs CurrentRegs, OriginalRegs;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *RemoteMapMemoryAddr, *RemoteModuleAddr, *RemoteModuleFuncAddr; 
    long parameters[6];

    /* 1. 附加到远程进程上*/
    if (ptrace_attach(pid) == -1)
    {
        return iRet; 
    }

    /* 2. 获取远程进程的寄存器值并保存下来，为了完成注入模块后的程序恢复执行做准备*/
    if (ptrace_getregs(pid, &CurrentRegs) == -1)
    {
        ptrace_detach(pid);
        return iRet;
    }
    LOGD("ARM_r0:0x%lx, ARM_r1:0x%lx, ARM_r2:0x%lx, ARM_r3:0x%lx, ARM_r4:0x%lx, \
          ARM_r5:0x%lx, ARM_r6:0x%lx, ARM_r7:0x%lx, ARM_r8:0x%lx, ARM_r9:0x%lx, \
          ARM_r10:0x%lx, ARM_ip:0x%lx, ARM_sp:0x%lx, ARM_lr:0x%lx, ARM_pc:0x%lx", 
          CurrentRegs.ARM_r0, CurrentRegs.ARM_r1, CurrentRegs.ARM_r2, CurrentRegs.ARM_r3, CurrentRegs.ARM_r4,
          CurrentRegs.ARM_r5, CurrentRegs.ARM_r6, CurrentRegs.ARM_r7, CurrentRegs.ARM_r8, CurrentRegs.ARM_r9,
          CurrentRegs.ARM_r10, CurrentRegs.ARM_ip, CurrentRegs.ARM_sp, CurrentRegs.ARM_lr, CurrentRegs.ARM_pc);
    memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));

    /* 3. 在远程进程内部开辟一遍内存空间存放一些常量数据，为远程进程执行函数调用提供参数地址
     *    这里需要知道，我们为什么不直接传递进去常量？这是因为我们现在传递的值是我们当前这个注入工具内存空间的值，
     *    相应的内存地址也是我们注入工具的，远程进程是访问不到的，所以我们需要将这些参数都在传递到远程进程空间中去*/
    mmap_addr = GetRemoteFuncAddr(pid, libc_path, (void *)mmap);
    LOGD("mmap RemoteFuncAddr:0x%lx", (long)mmap_addr);
    
    //参数
    parameters[0] = 0;//设置NULL表示让系统自己选择内存位置进行分配
    parameters[1] = 0x1000;//分配内存空间大小为1个内存页
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;//分配的内存区域的权限是可读、可写、可执行的
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE;//匿名映射，表示不受文件支持，下面两个参数可以为0
    parameters[4] = 0;//文件标识符，这里为0表示不映射文件内容
    parameters[5] = 0;//文件映射偏移量
    
    //调用mmap函数
    if (ptrace_call(pid, (long)mmap_addr, parameters, 6, &CurrentRegs) == -1)
    {
        LOGD("Call Remote mmap Func Failed");
        ptrace_detach(pid);
        return iRet;
    }

    //获取分配出的内存区域的地址
    RemoteMapMemoryAddr = (void *)ptrace_getret(&CurrentRegs);
    LOGD("Remote Process Map Memory Addr:0x%lx", (long)RemoteMapMemoryAddr);

    /* 4. 让远程进程执行dlopen加载so库到内存中。
     *    这里需要先将dlopen参数中的so库路径传递到远程进程的内存空间中，这样它调用dlopen的时候才可以从自己的内存空间中获取相应常量值*/

    //在远程进程新开辟的内存空间中写入so库路径
    if (ptrace_writedata(pid, RemoteMapMemoryAddr, LibPath, strlen(LibPath) + 1) == -1)
    {
        LOGD("Write LibPath:%s to RemoteProcess error", LibPath);
        ptrace_detach(pid);
        return iRet;
    }

    //参数
    parameters[0] = (long)RemoteMapMemoryAddr;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;

    dlopen_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlopen);
    LOGD("dlopen RemoteFuncAddr:0x%lx", (long)dlopen_addr);
    dlerror_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlerror);
    LOGD("dlerror RemoteFuncAddr:0x%lx", (long)dlerror_addr);
    dlclose_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlclose);
    LOGD("dlclose RemoteFuncAddr:0x%lx", (long)dlclose_addr);
    if (ptrace_call(pid, (long)dlopen_addr, parameters, 2, &CurrentRegs) == -1)
    {
        LOGD("Call Remote dlopen Func Failed");
        ptrace_detach(pid);
        return iRet;
    }

    //获取远程进程内存中被加载进去模块的地址
    RemoteModuleAddr = (void *)ptrace_getret(&CurrentRegs);
    LOGD("Remote Process load module Addr:0x%lx", (long)RemoteModuleAddr);
    
    // dlopen 错误
    if ((long)RemoteModuleAddr == 0x0)
    {
        LOGD("dlopen error");
        if (ptrace_call(pid, (long)dlerror_addr, parameters, 0, &CurrentRegs) == -1)
        {
            LOGD("Call Remote dlerror Func Failed");
            ptrace_detach(pid);
            return iRet;
        }
        char *Error = (void *)ptrace_getret(&CurrentRegs);
        char LocalErrorInfo[1024] = {0};
        ptrace_readdata(pid, Error, LocalErrorInfo, 1024);
        LOGD("dlopen error:%s", LocalErrorInfo);
        ptrace_detach(pid);
        return iRet;
    }

    /* 5.远程进程调用被加载进去模块的函数。
     *   先将参数传递进远程进程空间，然后利用dlsym函数搜索函数位置，最后在进行调用*/
    if (ptrace_writedata(pid, RemoteMapMemoryAddr + strlen(LibPath) + 2, FunctionName, strlen(FunctionName) + 1) == -1)
    {
        LOGD("Write FunctionName:%s to RemoteProcess error", FunctionName);
        ptrace_detach(pid);
        return iRet;
    }

    //设置dlsym参数
    parameters[0] = (long)RemoteModuleAddr;
    parameters[1] = (long)(RemoteMapMemoryAddr + strlen(LibPath) + 2);
    LOGD("Func Name：%x\n", parameters[1]);

    //调用dlsym函数并获取返回的函数地址
    dlsym_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlsym);
    LOGD("dlsym RemoteFuncAddr:0x%lx", (long)dlsym_addr);
    if (ptrace_call(pid, (long)dlsym_addr, parameters, 2, &CurrentRegs) == -1)
    {
        LOGD("Call Remote dlsym Func Failed");
        ptrace_detach(pid);
        return iRet;
    }
    RemoteModuleFuncAddr = (void *)ptrace_getret(&CurrentRegs);
    LOGD("Remote Process ModuleFunc Addr:0x%lx", (long)RemoteModuleFuncAddr);
    
    /* 6. 在远程进程中调用加载进去模块的函数,这里为了简单起见，没有选择传入参数，所以省去写入参数到远程进空间的步骤*/
    if (ptrace_call(pid, (long)RemoteModuleFuncAddr, FuncParameter, NumParameter, &CurrentRegs) == -1)
    {
        LOGD("Call Remote injected Func Failed");
        ptrace_detach(pid);
        return iRet;
    }
    
    /* 7. 恢复远程进程的执行操作*/
    if (ptrace_setregs(pid, &OriginalRegs) == -1)
    {
        LOGD("Recover reges failed");
        ptrace_detach(pid);
        return iRet;
    }
    LOGD("Recover Regs Success");
    ptrace_getregs(pid, &CurrentRegs);
    if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0)
    {
        LOGD("Set Regs Error");
    }

    if (ptrace_detach(pid) == -1)
    {
        LOGD("ptrace detach failed");
        return iRet;
    }

    return 0;
}
