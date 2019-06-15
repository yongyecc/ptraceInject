/************************************************************
  FileName: InjectModule.c
  Description:       ptrace注入      
***********************************************************/

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
#include <ptraceInject.h>
#include <PrintLog.h> 

/*************************************************
  Description:    通过进程名称定位到进程的PID
  Input:          process_name为要定位的进程名称
  Output:         无
  Return:         返回定位到的进程PID，若为-1，表示定位失败
  Others:         无
*************************************************/ 
pid_t FindPidByProcessName(const char *process_name)
{
	int ProcessDirID = 0;
	pid_t pid = -1;
	FILE *fp = NULL;
	char filename[MAX_PATH] = {0};
	char cmdline[MAX_PATH] = {0};

	struct dirent * entry = NULL;

	if ( process_name == NULL )
		return -1;

	DIR* dir = opendir( "/proc" );
	if ( dir == NULL )
		return -1;

	while( (entry = readdir(dir)) != NULL )
	{
		ProcessDirID = atoi( entry->d_name );
		if ( ProcessDirID != 0 )
		{
			snprintf(filename, MAX_PATH, "/proc/%d/cmdline", ProcessDirID);
			fp = fopen( filename, "r" );
			if ( fp )
			{
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if (strncmp(process_name, cmdline, strlen(process_name)) == 0)
				{
					pid = ProcessDirID;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}

int main(int argc, char *argv[]) {
	char InjectModuleName[MAX_PATH] = "/data/libIHook.so";    // 注入模块全路径
	char RemoteCallFunc[MAX_PATH] = "ModifyIBored";              // 注入模块后调用模块函数名称
	char InjectProcessName[MAX_PATH] = "com.estoty.game2048";                      // 注入进程名称
	
	// 当前设备环境判断
	#if defined(__i386__)  
	LOGD("Current Environment x86");
	return -1;
	#elif defined(__arm__)
	LOGD("Current Environment ARM");
	#else     
	LOGD("other Environment");
	return -1;
	#endif
	
	pid_t pid = FindPidByProcessName(InjectProcessName);
	if (pid == -1)
	{
		printf("Get Pid Failed");
		return -1;
	}	
	
	printf("begin inject process, RemoteProcess pid:%d, InjectModuleName:%s, RemoteCallFunc:%s\n", pid, InjectModuleName, RemoteCallFunc);
	int iRet = inject_remote_process(pid,  InjectModuleName, RemoteCallFunc,  NULL, 0);
	//int iRet = inject_remote_process_shellcode(pid,  InjectModuleName, RemoteCallFunc,  NULL, 0);
	
	if (iRet == 0)
	{
		printf("Inject Success\n");
	}
	else
	{
		printf("Inject Failed\n");
	}
	printf("end inject,%d\n", pid);
    return 0;  
}  