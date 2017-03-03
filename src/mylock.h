#include <signal.h>
#include <unistd.h>
#include <fcntl.h>


#define LOCK_FILE  "/jffs/tmp/evasi0n.pid"	/* 锁文件 */

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* 创建掩码 */

void flock_reg();						//注册文件锁
void daemon_init();						//后台运行的初始化函数
int is_Running();						//检测副本是否已运行
void signal_interrupted(int signo);		//中断信号回调函数
void exit_handle();						//退出信号回调函数

