
	===== Userspace tools for Checkpoint-Restart =====


UTILITIES:

self.c: a simple program doing self-checkpoint
  Since at the moment checkpoint only works with simple file
  descriptors, you must redirect standard output to a file when
  running it:
	$ ./self > out.self

ckpt.c: a program to do external checkpoint of other process(es)
  Run with a single argument which is the pid of the target
  process (container init), in the current pid namespace. The
  checkpoint image is written to standard output.
	$ ./ckpt PID > out.ckpt

rstr.c: a program to restart from a checkpoint of a single process
  It restarts the process, but does not restore the original pid of
  the process. Redirect standard input from the checkpoint image.
	$ ./rstr < out.ckpt

mktree.c: a program to restart from a checkpoint of multiple processes
  It first creates the process tree and then restarts the process. By
  default it does not restore the original pids of the processes (will
  be added in the future). Redirect standard input from the checkpoint
  image.
	$ ./mktree --no-pids < out.ckpt
	

TEST PROGRAMS:

test1.c: a simple test program for c/r (single process)
test2.c: a simple test program for c/r (multiple processes)
