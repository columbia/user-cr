#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define OUTFILE  "/tmp/cr-test.out"

int main(int argc, char *argv[])
{
	FILE *file;
	float a;
	int i;

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

	a = sqrt(2.53 * (getpid() / 1.21));

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	for (i = 0; i < 1000; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		fprintf(file, "count %d (%.2f)!\n", i, a);
		fflush(file);
	}
		
	fprintf(file, "world, hello (%.2f) !\n", a);
	fflush(file);

	return 0;
}
