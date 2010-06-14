#include <linux/checkpoint.h>
#include <linux/checkpoint_hdr.h>

struct cr_checkpoint_args {
	int outfd;
	int logfd;
	int uerrfd;
	int container;
	int verbose;
	int flags;
};

struct cr_restart_args {
	int self;
	int pids;
	int pidns;
	int inspect;
	char *root;
	int wait;
	int mntns;
	int mnt_pty;
	int show_status;
	int copy_status;
	char *freezer;
	int keep_frozen;
	int infd;
	int klogfd;
	int ulogfd;
	int uerrfd;
	long warn;
	int debug;
	int verbose;
	long fail;
	int keep_lsm;
};

/*
 * TODO: Implement an API to let callers choose if/how an interrupt be sent
 *  	 and remove global_send_sigint.
 */
extern int global_send_sigint;

extern int cr_checkpoint(int pid, struct cr_checkpoint_args *args);
extern int cr_restart(struct cr_restart_args *args);
