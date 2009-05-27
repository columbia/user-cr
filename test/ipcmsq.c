#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifndef __USE_GNU
#define __USE_GNU
#include <sys/ipc.h>
#include <sys/msg.h>
#endif

#define OUTFILE  "/tmp/cr-test.out"

#define MSG_KEY  13
#define MSG_NUM  5

int main(int argc, char *argv[])
{
	FILE *file;
	struct msgbuf *msg1, *msg2;
	unsigned char *ptr1, *ptr2;
	int id1, id2;
	int i, j, k;

	msg1 = malloc(sizeof(*msg1) + 1024);
	msg2 = malloc(sizeof(*msg2) + 1024);
	if (!msg1 || !msg2) {
		perror("malloc");
		exit(1);
	}

	ptr1 = (unsigned char *) msg1->mtext;
	ptr2 = (unsigned char *) msg2->mtext;

	for (i = 0, k = 0; i < 1024; i++, k = (k + 1) % 256) {
		ptr1[i] = k;
		ptr2[i] = 255 - k;
	}
		
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
	
	id1 = msgget(MSG_KEY, 0700|IPC_CREAT|IPC_EXCL);
	if (id1 < 0) {
		perror("msgget1");
		exit(1);
	}
	id2 = msgget(IPC_PRIVATE, 0700|IPC_CREAT|IPC_EXCL);
	if (id2 < 0) {		
		perror("msgget2");
		exit(1);
	}

	for (j = 0; j < MSG_NUM; j++) {
		msg1->mtype = j+1;
		msg2->mtype = (j+1) * 10;
		if (msgsnd(id1, msg1, 1024, 0) < 0) {
			perror("msgsnd1");
			exit(1);
		}
		if (msgsnd(id2, msg2, 1024, 0) < 0) {
			perror("msgsnd2");
			exit(1);
		}
	}

	fprintf(file, "sent messages, sleeping 20\n");
	fflush(file);
	sleep(15);
	fprintf(file, "waking up\n");
	fflush(file);

	for (j = 0; j < MSG_NUM; j++) {
		memset(ptr1, 0, 1024);
		memset(ptr2, 0, 1024);
		if (msgrcv(id1, msg1, 1024, j+1, 0) < 0) {
			perror("msgrcv1");
			exit(1);
		}
		if (msgrcv(id2, msg2, 1024, (j+1)*10, 0) < 0) {
			perror("msgrcv2");
			exit(1);
		}
		for (i = 0, k = 0; i < 1024; i++, k = (k + 1) % 256) {
			if (ptr1[i] != k || ptr2[i] != 255 - k) {
				fprintf(file, "mismatch at %d\n", i);
				fflush(file);
				break;
			}
		}
	}

	if (msgctl(id1, IPC_RMID, NULL) < 0)
		perror("rmid1 again");
	if (msgctl(id2, IPC_RMID, NULL) < 0)
		perror("rmid2 again");

	fprintf(file, "completed\n");
	fflush(file);

	fclose(file);
	return 0;
}
