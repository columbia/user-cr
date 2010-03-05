
struct app_checkpoint_args {
	int outfd;
	int logfd;
	int uerrfd;
	int container;
	int verbose;
};

struct app_restart_args {
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

extern int app_checkpoint(int pid, unsigned long flags,
				struct app_checkpoint_args *args);

extern int app_restart(struct app_restart_args *args);
