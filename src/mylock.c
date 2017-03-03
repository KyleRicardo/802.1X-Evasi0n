#include "mylock.h"
#include "evasi0n.h"
#include "dyload.h"

#define NO_NOTIFY
#define NO_DYLOAD
extern int lockfd;
extern pcap_t *hPcap;
extern u_char *pktbuf;
extern int exitFlag;

void flock_reg()
{
	char buf[16];
	struct flock fl;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_type = F_WRLCK;
	fl.l_pid = getpid();

	//阻塞式加锁F_SETLKW
	if (fcntl(lockfd, F_SETLKW, &fl) < 0){
		perror("Evasi0n!!FATAL ERROR:Failed to lock the file!");
		exit(EXIT_FAILURE);
	}

	//把PID写入锁文件
	ftruncate(lockfd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(lockfd, buf, strlen(buf) + 1);
}

void daemon_init()
{
	pid_t	pid;
	int     fd0;

	if ((pid = fork()) < 0)
		perror("Evasi0n!!FATAL ERROR:The API fork() has failed.");
	else if (pid != 0) {
		fprintf(stdout, "Evasi0n>>Evasi0n has been forked to background with PID: [%d]\n\n", pid);
		exit(EXIT_SUCCESS);
	}
	setsid();		/* become session leader */
	chdir("/tmp");		/* change working directory */
	umask(0);		/* clear our file mode creation mask */
	flock_reg();

	fd0 = open("/dev/null", O_RDWR);
	dup2(fd0, STDIN_FILENO);
	dup2(fd0, STDERR_FILENO);
	dup2(fd0, STDOUT_FILENO);
	close(fd0);
}

int is_Running()
{
	struct flock fl;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_type = F_WRLCK;

	//尝试获得文件锁
	if (fcntl(lockfd, F_GETLK, &fl) < 0){
		perror("Evasi0n!!FATAL ERROR:Unable to get to the lockfile!");
		exit(EXIT_FAILURE);
	}

	if (exitFlag) {
		if (fl.l_type != F_UNLCK) {
			if (kill(fl.l_pid, SIGINT) == -1)
				perror("Evasi0n!!FATAL ERROR:Failed to kill the evasi0n process!");
			fprintf(stdout, "Evasi0n>>Kill Signal Sent to PID %d.\n", fl.l_pid);
		}
		else
			fprintf(stderr, "Evasi0n!!Evasi0n is not running.\n");
		exit(EXIT_FAILURE);
	}


	//没有锁，则给文件加锁，否则返回锁着文件的进程pid
	if (fl.l_type == F_UNLCK) {
		flock_reg();
		return 0;
	}

	return fl.l_pid;
}

void signal_interrupted(int signo)
{
	extern int exitFlag;
	if (exitFlag)
		exit(EXIT_SUCCESS);
	exitFlag = 1;
	fprintf(stdout, "\nEvasi0n>>You have just interrupted. \n");
	if (hPcap != NULL){
		evasi0n_terminator();

	}
}

void exit_handle()
{
	/*if (hPcap != NULL){
		pcap_breakloop(hPcap);
		pcap_close(hPcap);
	}
	if (pktbuf != NULL)
		free(pktbuf);

	if (lockfd > -1)
		close(lockfd);
*/
#ifndef NO_NOTIFY
	free_libnotify();
#endif
#ifndef NO_DYLOAD
	free_libpcap();
#endif
	printf("Evasi0n>>Program terminated.\n");
}
