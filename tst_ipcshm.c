#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define OUTFILE  "/tmp/cr-test.out"
#define SEG_SIZE (20 * 4096)
#define SEG_KEY1 11

int main(int argc, char *argv[])
{
	FILE *file;
	int id1, id2;
	unsigned char *seg1, *seg2;
	int i, j;

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
	
	id1 = shmget(SEG_KEY1, SEG_SIZE, 0700|IPC_CREAT|IPC_EXCL);
	if (id1 < 0) {
		perror("shmget1");
		exit(1);
	}

	id2 = shmget(IPC_PRIVATE, SEG_SIZE, 0700|IPC_CREAT|IPC_EXCL);
	if (id2 < 0) {		
		perror("shmget2");
		exit(1);
	}

	seg1 = (unsigned char *) shmat(id1, NULL, 0);
	if (seg1 == ((void *) -1)) {
		perror("shmat1");
		exit(1);
	}

	seg2 = (unsigned char *) shmat(id2, NULL, 0);
	if (seg2 == ((void *) -1)) {
		perror("shmat2");
		exit(1);
	}
	
	for (i = 0, j = 0; i < SEG_SIZE; i++, j = (j + 1) % 256) {
		seg1[i] = j;
		seg2[i] = 255 - j;
	}

	if (shmdt(seg1) < 0)
		perror("shmdt1");

	fprintf(file, "detaches 2nd, sleeping 30\n");
	fflush(file);
	sleep(20);
	fprintf(file, "waking up\n");
	fflush(file);

	seg1 = (unsigned char *) shmat(id1, NULL, 0);
	if (seg1 == ((void *) -1)) {
		perror("shmat1 again");
		exit(1);
	}

	for (i = 0, j = 0; i < SEG_SIZE; i++, j = (j + 1) % 256) {
		if (seg1[i] != j || seg2[i] != 255 - j) {
			fprintf(file, "mismatch at %d\n", i);
			fflush(file);
			break;
		}
	}

	if (shmdt(seg1) < 0)
		perror("shmdt1 again");
	if (shmdt(seg2) < 0)
		perror("shmdt2");

	if (shmctl(id1, IPC_RMID, NULL) < 0)
		perror("rmid1 again");
	if (shmctl(id2, IPC_RMID, NULL) < 0)
		perror("rmid2 again");

	fprintf(file, "completed\n");
	fflush(file);

	fclose(file);
	return 0;
}
