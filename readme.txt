
	===== Userspace tools for Checkpoint-Restart =====


UTILITIES:

checkpoint.c: a program to do external checkpoint of other process(es)
  Run with a single argument which is the pid of the target
  process (container init), in the current pid namespace. The
  checkpoint image is written to standard output.
	$ ./checkpoint PID > out.ckpt

restart.c: a program to restart from a checkpoint of multiple processes
  It first creates the process tree and then restarts the process. By
  default it does not restore the original pids of the processes (will
  be added in the future). Redirect standard input from the checkpoint
  image.
	$ ./restart --no-pids < out.ckpt


	
CONTRIB CODE:

self_checkpoint.c: code to demonstrate how to do self-checkpoint
  Since at the moment checkpoint only works with simple file
  descriptors, you must redirect standard output to a file when
  running it:
	$ ./self > out.self

self_restart.c: code to demonstrate how to do self-restart
  It restarts the process, but does not restore the original pid of
  the process. Redirect standard input from the checkpoint image.
	$ ./self_restart < out.ckpt



TEST PROGRAMS:

onetask.c	a simple test with a single process
multitask.	a simple test with multiple processes
bigmem.c	test multiple processes with large memory allocation
shmem.c		test shared memory
pipes2.c	test one process that uses pipes
pipes.c		test multiple processes that use pipes
fifo.c		test for use of FIFO
ipcmsq.c	test SysV IPC - message queues
ipcsem.c	test SysV IPC - semaphores
ipcshm.c	test SysV IPC - shared memory
ipcshm_multi.c:	test SysV IPC - shared memory multi process
itimer.c	test posix itimers (real, virtual, profiler)
zombie.c	test multiple processes with zombies
pgrp.c		test with varying process pgids
pty.c:		test use of pseudo terminals
sigpending.c:	test pending signals

