#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifndef __USE_GNU
#define __USE_GNU
#include <sys/ipc.h>
#include <sys/sem.h>
#endif

#define OUTFILE  "/tmp/cr-test.out"

#define SEM_KEY  13
#define SEM_NUM  3

int main(int argc, char *argv[])
{
	FILE *file;
	struct sembuf sop;
	int id1, id2;
	int j;

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
		exit(1);
	}

	id1 = semget(SEM_KEY, SEM_NUM, 0700|IPC_CREAT|IPC_EXCL);
	if (id1 < 0) {
		perror("semget1");
		exit(1);
	}
	id2 = semget(IPC_PRIVATE, SEM_NUM, 0700|IPC_CREAT|IPC_EXCL);
	if (id2 < 0) {
		perror("semget2");
		exit(1);
	}

	for (j = 0; j < SEM_NUM; j++) {
		sop.sem_num = j;
		sop.sem_op = j;
		sop.sem_flg = IPC_NOWAIT;
		if (semop(id1, &sop, 1) < 0) {
			perror("semop1");
			exit(1);
		}
		if (semop(id2, &sop, 1) < 0) {
			perror("semop2");
			exit(1);
		}
	}

	fprintf(file, "set up semaphores, waiting 15 seconds\n");
	fflush(file);
	sleep(5);
	fprintf(file, "waking up\n");
	fflush(file);

	for (j = 0; j < SEM_NUM; j++) {
		fprintf(file, "iteration %d...\n", j);
		fflush(file);
		sop.sem_num = j;
		sop.sem_op = -j;
		sop.sem_flg = IPC_NOWAIT;
		if (semop(id1, &sop, 1) < 0)
			perror("semop1 after");
		if (semop(id2, &sop, 1) < 0)
			perror("semop2 after");
	}

	if (semctl(id1, 0, IPC_RMID) < 0)
		perror("rmid1 again");
	if (semctl(id2, 0, IPC_RMID) < 0)
		perror("rmid2 again");

	fprintf(file, "completed\n");
	fflush(file);

	fclose(file);
	return 0;
}
