#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sched.h>

/* For CLONE_NEWIPC */
#include "../clone.h"

int  __attribute__((weak)) unshare(int flags)
{
       return syscall(__NR_unshare, flags);
}


#define OUTFILE  "/tmp/cr-test.out"
#define SEG_SIZE (20 * 4096)
#define DELAY 20
#define COUNT_MAX 15

int attach(unsigned char **seg, int num)
{
	int id;

	id = shmget(123, SEG_SIZE, 0700|IPC_EXCL);
	if (id < 0) {
		printf("[CHILD %i] shmget: %m\n", num);
		return -1;
	}

	*seg = shmat(id, NULL, 0);
	if (!*seg) {
		printf("[CHILD %i] shmat: %m\n", num);
		return -1;
	}

	printf("[CHILD %i] Attached\n", num);

	return 0;
}

int validate(unsigned char *seg, int num)
{
	int i;

	for (i = 1; i < SEG_SIZE; i++) {
		if (seg[i] != (unsigned char)(i % 256)) {
			printf("[CHILD %i] Mismatch at %hhu: %hhu\n",
			       num, i, seg[i]);
			return -1;
		}
	}

	printf("[CHILD %i] Validated\n", num);

	return 0;
}

int track_incr(unsigned char *seg, int num)
{
	int i;
	int last = seg[0];

	for (i = 0; i < 20; i++) {
		if (seg[0] == COUNT_MAX)
			break;

		if (abs(last - (int)seg[0]) > 1) {
			printf("[CHILD %i] Expected +/-%i (got %i) %i\n",
			       num, last, seg[0], abs(last - seg[0]));
			return 1;
		}

		last = seg[0] + 1;

		printf("[CHILD %i] Seg[0]: %i\n", num, seg[0]);
		sleep(1);
	}

	return !(seg[0] == COUNT_MAX);
}

int track_const(unsigned char *seg, int num, int val)
{
	int i;

	for (i = 0; i < 20; i++) {
		if (seg[0] != val) {
			printf("[CHILD %i] Expected %i not %i\n",
			       num, val, seg[0]);
			return 1;
		}
		printf("[CHILD %i] Seg[0]: %i\n", num, seg[0]);
		sleep(1);
	}

	return 0;
}

/*
 * Attach to the shared segment *before* the checkpoint and then track
 * the changing seg[0] position afterwards.
 */
int child1(void)
{
	unsigned char *seg;
	int num = 1;

	printf("[CHILD %i] Running\n", num);

	sleep(1); /* Allow master to finish initializing the array */

	if (attach(&seg, num))
		return -1;

	if (validate(seg, num))
		return -1;

	sleep(DELAY - 1); /* Wait until after the checkpoint */

	return track_incr(seg, num);
}

/*
 * Attempt to attach to the shared segment *after* the checkpoint to
 * verify that things are hooked up properly after restart by tracking
 * seg[0].
 */
int child2(void)
{
	unsigned char *seg;
	int num = 2;

	printf("[CHILD %i] Running\n", num);

	sleep(DELAY); /* Wait until after the checkpoint */

	if (attach(&seg, num))
		return -1;

	if (validate(seg, num))
		return -1;

	return track_incr(seg, num);
}

int child4(int constval);

/*
 * Detach from the parent's IPC namespace and verify that:
 * 1. We can't attach to the parent's segment
 * 2. We can create our own of the same ID without conflict
 * 3. We do not see the parent's changing seg[0] after restart
 */
int child3(void)
{
	unsigned char *seg;
	int num = 3;
	int cpid;
	int ret;
	int status;

	if (unshare(CLONE_NEWIPC) != 0) {
		printf("[CHILD %i] unshare(CLONE_NEWIPC): %m", num);
		return -1;
	}

	cpid = fork();
	if (cpid < 0)
		return 1;
	else if (cpid == 0)
		return child4(123);

	printf("[CHILD %i] Running (new IPC NS)\n", num);

	printf("[CHILD %i] Attempting parent attach (should fail)\n", num);
	if (!attach(&seg, num)) {
		printf("[CHILD %i] Attached to parent's IPC!\n", num);
		return -1;
	}

	if (shmget(123, SEG_SIZE, 0700|IPC_CREAT|IPC_EXCL) < 0) {
		printf("[CHILD %i] Failed to create shm in namespace: %m\n",
		       num);
		return -1;
	}

	if (attach(&seg, num))
		return -1;

	seg[0] = 123;

	sleep(DELAY); /* Wait until after checkpoint, then attach */

	ret = track_const(seg, num, 123);

	printf("[CHILD %i] Waiting for child %i\n", num, cpid);
	wait(&status);

	if (ret == 0)
		return WEXITSTATUS(status);
	else
		return ret;
}

/*
 * This child is forked from child3 under the new IPC namespace.
 * Verify that post-restart, we do not see the changing seg[0]
 */
int child4(int constval)
{
	unsigned char *seg;
	int num = 4;

	printf("[CHILD %i] Running (new IPC NS)\n", num);

	sleep(DELAY); /* Wait past my parent creating the IPC */

	if (attach(&seg, num))
		return -1;

	return track_const(seg, num, constval);

	return 0;
}

void shm_destroy(void)
{
	int id;

	id = shmget(123, SEG_SIZE, 0700);
	if (id < 0)
		return;

	if (shmctl(id, IPC_RMID, NULL) == 0)
		printf("Deleted SHM %i\n", id);
}

int main(int argc, char *argv[])
{
	int id;
	unsigned char *seg;
	int i;
	int pid1, pid2, pid3;
#ifndef TEST
	FILE *file;

	close(0);
	close(1);
	close(2);

	unlink(OUTFILE);
	file = fopen(OUTFILE, "w+");
	if (!file) {
		perror("open");
		exit(1);
	}
	if (dup2(0,2) < 0) {
		perror("dup2");
		exit(2);
	}
	stdout = file;
	setlinebuf(file);
#endif
	shm_destroy();

	pid1 = fork();
	if (pid1 == 0)
		return child1();

	pid2 = fork();
	if (pid2 == 0)
		return child2();

	pid3 = fork();
	if (pid3 == 0)
		return child3();

	id = shmget(123, SEG_SIZE, 0700|IPC_CREAT|IPC_EXCL);
	if (id < 0) {
		perror("shmget");
		exit(1);
	}

	seg = (unsigned char *) shmat(id, NULL, 0);
	if(seg == ((void *) -1)) {
		perror("shmat");
		exit(1);
	}

	for (i = 0; i < SEG_SIZE; i++)
		seg[i] = i;

	printf("[MSTER] Waiting for checkpoint\n");
	sleep(DELAY);
	printf("[MSTER] Woke\n");

	for (i = 0; i <= COUNT_MAX; i++) {
		seg[0] = i;
		sleep(1);
	}

	for (i = 0; i < 3; i++) {
		int status;

		printf("[MSTER] Waiting on child %i\n", i+1);
		wait(&status);
		if (WEXITSTATUS(status)) {
			printf("[MSTER] child exited with %i\n",
			       WEXITSTATUS(status));
			return WEXITSTATUS(status);
		}
	}

	if (shmdt(seg) < 0)
		perror("shmdt");

	shm_destroy();

	printf("[MSTER] Completed\n");

	return 0;
}
