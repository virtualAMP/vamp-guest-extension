#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/input.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <termios.h>
#include <signal.h>
#include <sched.h>

/* Parameters */
int init_nr_fast_cpus = 2;	/* -f <val>: initial # of fast cpus */
int pin_irq;			/* -i <irq num>: pin interrupts to fast vcpus */
int verbose;			/* -v: verbose level */
enum {
	MODE_STATIC,
	MODE_DYNAMIC,
	MODE_DYNAMIC_LOAD,
	MODE_LOAD,
	MODE_END
};
char *mode_desc[] = {
	"Static: # of fast & slow cpus are fixed in predefined numbers",
	"Dynamic: start with Static, and adjust # of fast cpus based on the existence of slow tasks",
	"Dynamic-load: start with Static, and adjust # of fast cpus based on CPU loads on fast cpus",
	"Load: # of slow cpus is determined based on previous CPU loads of slow tasks",
};
int mode = MODE_STATIC;

#define exit_with_msg(args...) do { fprintf(stderr, args); exit(-1); } while (0)

enum {
	VB_MAJOR = 1,
	VB_MINOR,
	VB_DEBUG
};
#define debug_printf(level, args...)  \
	do { if (level <= verbose) printf(args); } while (0)

#define SLOW_TASK_PATH		"/proc/kvm_slow_task"
#define AUDIO_FIFO_PATH		"/tmp/vdiguest-audio"

#define CPUSET_PATH		"/dev/cpuset/vdiguest"
#define SLOW_GROUP_NAME		"slow"
#define FAST_GROUP_NAME		"fast"
#define CPUS_NODE		"cpuset.cpus"
#define MEMS_NODE		"cpuset.mems"
#define PROCS_NODE		"cgroup.procs"
#define ROOT_PROCS_PATH		CPUSET_PATH "/" PROCS_NODE
#define SLOW_CPUS_PATH		CPUSET_PATH "/" SLOW_GROUP_NAME "/" CPUS_NODE
#define FAST_CPUS_PATH		CPUSET_PATH "/" FAST_GROUP_NAME "/" CPUS_NODE
#define SLOW_MEMS_PATH		CPUSET_PATH "/" SLOW_GROUP_NAME "/" MEMS_NODE
#define FAST_MEMS_PATH		CPUSET_PATH "/" FAST_GROUP_NAME "/" MEMS_NODE
#define SLOW_PROCS_PATH		CPUSET_PATH "/" SLOW_GROUP_NAME "/" PROCS_NODE
#define FAST_PROCS_PATH		CPUSET_PATH "/" FAST_GROUP_NAME "/" PROCS_NODE

#define MAX_SLOW_TASKS		64
#define MAX_PATH_LEN		256

#define MAX_INPUT_DECS		8
#define MAX_INPUT_EVENTS	32
#define INPUT_NAME_LEN		256
#define INPUT_TYPE_KEYBOARD	0
#define INPUT_TYPE_MOUSE	1
#define INPUT_TYPE_AUDIO	2
/* currently 3~ types are not defined */

int nr_fast_cpus;
unsigned long stat_mon_period_us = 1000000;
int nr_cpus;	/* # of available CPUs */
int my_pid;

struct input_descriptor {
	int fd;
	int type;
	char *path;
	char name[INPUT_NAME_LEN];
} input_desc[MAX_INPUT_DECS];

struct slow_task {
	int task_id;
	int load_pct;
	int moved;
};

/* safewrite is borrowed from libvirtd 
 * Like write(), but restarts after EINTR */
static ssize_t safewrite(int fd, const void *buf, size_t count)
{
	size_t nwritten = 0;
	while (count > 0) {
		ssize_t r = write(fd, buf, count);

		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return r;
		if (r == 0)
			return nwritten;
		buf = (const char *)buf + r;
		count -= r;
		nwritten += r;
	}
	return nwritten;
}

static int filewrite(const char *path, const char *str)
{
	int fd;
	int ret;
	if ((fd = open(path, O_WRONLY|O_TRUNC)) < 0) {
		perror("file open error");
		return -1;
	}
	ret = safewrite(fd, str, strlen(str));
	close(fd);

	debug_printf(VB_MAJOR, "write %s to %s\n", str, path);

	return ret;
}

#define fileprintf(path, args...) ({	\
	int ret;	\
	char str[256];	\
	snprintf(str, 256, args);	\
	ret = filewrite(path, str);	\
	ret;	\
}) 

static char *get_name_by_pid(int pid)
{
	static char comm[256];
	static char *na = "N/A\n";
	char comm_path[32];
	FILE *fp;

	snprintf(comm_path, 32, "/proc/%d/comm", pid);
	if ((fp = fopen(comm_path, "r")) == NULL)
		return na;
	fgets(comm, 256, fp);
	fclose(fp);

	return comm ? comm : na;
}

#define debug_procname_print(pid)	\
	do { debug_printf(VB_MAJOR, "\t%d=%s", pid, get_name_by_pid(pid)); } while(0)

static void move_slow_tasks(int nr_slow_tasks, struct slow_task *slow_tasks, int nr_slow_cpus)
{
	int i;

	fileprintf(SLOW_CPUS_PATH, "%d-%d", nr_cpus - nr_slow_cpus, nr_cpus - 1);
	for (i = 0; i < nr_slow_tasks; i++) {
		debug_printf(VB_DEBUG, "%s: i=%d pid=%d moved=%d\n",
				__func__, i, slow_tasks[i].task_id, slow_tasks[i].moved);
		if (my_pid == slow_tasks[i].task_id ||	/* unlikely */
		    slow_tasks[i].moved)		/* likely */
			continue;
		fileprintf(SLOW_PROCS_PATH, "%d", slow_tasks[i].task_id);
		debug_procname_print(slow_tasks[i].task_id);
	}
}

static void mod_irq_affinity(int nr_mod_cpus)
{
	int i;
	int affinity = 0;
	char irq_affinity_path[512];

	if (!pin_irq)
		return;

	snprintf(irq_affinity_path, 512, "/proc/irq/%d/smp_affinity", pin_irq);
	for (i = 0; i < nr_mod_cpus; i++)
		affinity |= (1 << i);

	fileprintf(irq_affinity_path, "%x", affinity);
	//fileprintf(irq_affinity_path, "1");
}

static void mod_fast_cpus(int nr_mod_cpus)
{
	fileprintf(FAST_CPUS_PATH, "%d-%d", 0, nr_mod_cpus - 1);
	mod_irq_affinity(nr_mod_cpus);
}

static void report_tasks_failed_to_move(void)
{
	int pid;
	FILE *fp;

	if (verbose < VB_MAJOR)
		return;

	if ((fp = fopen(ROOT_PROCS_PATH, "r")) == NULL)
		return;
	debug_printf(VB_MAJOR, "Process list failed to move to fast cpu group\n");
	while(fscanf(fp, "%d", &pid) == 1)
		debug_procname_print(pid);
	fclose(fp);
}

static void move_fast_tasks(void)
{
	int pid;
	FILE *fp = fopen(ROOT_PROCS_PATH, "r");
	if (!fp) {
		fprintf(stderr, "Error: %s open, so fail to move fast tasks!\n", 
				ROOT_PROCS_PATH);
		return;
	}
	while(fscanf(fp, "%d", &pid) == 1) {
		fileprintf(FAST_PROCS_PATH, "%d", pid);
		debug_procname_print(pid);
	}
	fclose(fp);

	report_tasks_failed_to_move();
}

static void restore_all_tasks(void)
{
	int pid;
	FILE *fp = fopen(SLOW_PROCS_PATH, "r");
	if (!fp) {
		fprintf(stderr, "Error: %s open, so fail to move fast tasks!\n", 
				SLOW_PROCS_PATH);
		return;
	}
	mod_fast_cpus(nr_cpus);
	while(fscanf(fp, "%d", &pid) == 1) {
		fileprintf(FAST_PROCS_PATH, "%d", pid);
		debug_procname_print(pid);
	}
	fclose(fp);
}

static void restore_fast_tasks(struct slow_task *slow_tasks, int nr_slow_tasks)
{
	int pid;
	FILE *fp = fopen(SLOW_PROCS_PATH, "r");
	if (!fp) {
		fprintf(stderr, "Error: %s open, so fail to move fast tasks!\n", 
				SLOW_PROCS_PATH);
		return;
	}
	while(fscanf(fp, "%d", &pid) == 1) {
		int i, is_slow = 0;
		for (i = 0; i < nr_slow_tasks; i++) {
			if (slow_tasks[i].task_id == pid) {
				slow_tasks[i].moved = 1;
				is_slow = 1;
				break;
			}
		}
		if (!is_slow) {
			debug_printf(VB_DEBUG, "pid=%d old slow, but now fast\n", pid);
			fileprintf(FAST_PROCS_PATH, "%d", pid);
			debug_procname_print(pid);
		}
	}
	fclose(fp);

	//report_tasks_failed_to_move();
}

static int get_fast_cpus_load(void)
{
	FILE *fp;
	char cpu[16];
	int cpuid = -1;
	unsigned long user, nice, sys, idle, iowait, irq, softirq, steal, guest, guest_nice;
	unsigned long curr_total, curr_util;
	static unsigned long prev_total, prev_util;
	int cpu_util_pct = 0;

	if ((fp = fopen("/proc/stat", "r")) == NULL)
		return 0;

	curr_total = curr_util = 0;
	while(fscanf(fp, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		cpu, &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) == 11) {
		if (cpuid++ == -1) 
			continue;
		if (cpuid > nr_fast_cpus)
			break;
		/* 0 < cpuid <= nr_fast_cpus -> cpu_0, .. cpu_(nr_fast_cpus-1) */
		debug_printf(VB_DEBUG, "\t%s user=%lu nice=%lu sys=%lu idle=%lu iowait=%lu irq=%lu softirq=%lu steal=%lu\n",
				cpu, user, nice, sys, idle, iowait, irq, softirq, steal);
		curr_total += user + nice + sys + idle + iowait + irq + softirq + steal + guest + guest_nice;
		curr_util  += user + nice + sys + irq + softirq + steal + guest + guest_nice;
	}
	fclose(fp);

	if (curr_total - prev_total)
		cpu_util_pct = (curr_util - prev_util) * 100 / (curr_total - prev_total);
	debug_printf(VB_DEBUG, "\tutil=%lu (=%lu-%lu), curr_total=%lu (=%lu-%lu)\n",
			curr_util - prev_util, curr_util, prev_util, 
			curr_total - prev_total, curr_total, prev_total);

	prev_total = curr_total;
	prev_util  = curr_util;

	return cpu_util_pct;
}

static void adjust_fast_cpus(void) {
	int fast_cpus_load = get_fast_cpus_load();

	debug_printf(VB_MAJOR, "\tfast_cpus_load=%d%% (%d cpus)\n", fast_cpus_load, nr_fast_cpus);
	if (fast_cpus_load >= 100 && nr_fast_cpus < nr_cpus - 1) {
		nr_fast_cpus++;
		mod_fast_cpus(nr_fast_cpus);
		get_fast_cpus_load();
	}
}

static inline void start_stat_monitor(void)
{
	if (mode == MODE_STATIC)
		return;
	if (stat_mon_period_us < 1000000)
		ualarm(stat_mon_period_us, 0);
	else
		alarm(stat_mon_period_us / 1000000);
}
static inline void cancel_stat_monitor(void) 
{
	alarm(0);
}


static int get_slow_tasks(struct slow_task *slow_tasks, int *nr_slow_cpus)
{
	FILE *fp;
	int n = 0;
	int load_pct = 0;

	if ((fp = fopen(SLOW_TASK_PATH, "r")) == NULL)
		return 0;

	while(fscanf(fp, "%d %d", &slow_tasks[n].task_id, &slow_tasks[n].load_pct) == 2) {
		load_pct += slow_tasks[n].load_pct;

		debug_printf(VB_MAJOR, "\t%d pct load: ", slow_tasks[n].load_pct);
		debug_procname_print(slow_tasks[n].task_id);

		slow_tasks[n].moved = 0;

		n++;
	}
	*nr_slow_cpus = (load_pct + 99) / 100;
	debug_printf(VB_MAJOR, "aggregated load of slow tasks = %d%% (nr_slow_cpus=%d)\n", 
			load_pct, *nr_slow_cpus);
	fclose(fp);

	return n;
}

/* fast version of checking if there is still a slow task */
static int slow_task_exist(void)
{
	FILE *fp;
	int ret, dummy;

	if ((fp = fopen(SLOW_TASK_PATH, "r")) == NULL)
		return 0;
	ret = fscanf(fp, "%d", &dummy) == 1;
	fclose(fp);

	debug_printf(VB_MINOR, "\tcheck if slow tasks exist -> %s\n", ret ? "true" : "false");

	return ret;
}

static void isolate_slow_tasks(int output)
{
	int nr_slow_cpus;
	int nr_slow_tasks;
	struct slow_task slow_tasks[MAX_SLOW_TASKS];

	nr_slow_tasks = get_slow_tasks(slow_tasks, &nr_slow_cpus);

	/* if no slow tasks, nothing to do */
	if (nr_slow_tasks == 0) {
		restore_all_tasks();
		return;
	}
	else 
		restore_fast_tasks(slow_tasks, nr_slow_tasks);
	if (mode < MODE_LOAD) {
		if (output) {
			cancel_stat_monitor();
			if (mode == MODE_DYNAMIC_LOAD)
				adjust_fast_cpus();
			/* in case of audio output, minimum # of fast cpus
			 * should be more than one, so that the hypervisor
			 * can track remote wake-up between sound server and
			 * client */
			if (nr_fast_cpus < 2)
				nr_fast_cpus = 2;
		}
		else 
			nr_fast_cpus = init_nr_fast_cpus;
		nr_slow_cpus = nr_cpus - nr_fast_cpus;
	}
	else if (mode == MODE_LOAD) {
		if (nr_cpus - nr_slow_cpus < init_nr_fast_cpus)	/* short of fast cpus */
			nr_slow_cpus = nr_cpus - init_nr_fast_cpus;
		nr_fast_cpus = nr_cpus - nr_slow_cpus;
	}

	debug_printf(VB_MAJOR, "# nr_fast cpus=%d, nr_slow cpus=%d (nr_slow_tasks=%d, init_nr_fast_cpus=%d)\n", 
			nr_fast_cpus, nr_slow_cpus, nr_slow_tasks, init_nr_fast_cpus); 

	move_slow_tasks(nr_slow_tasks, slow_tasks, nr_slow_cpus);
	mod_fast_cpus(nr_fast_cpus);

	/* in audio output is being generated, audio stat monitor
	 * already does periodical monitoring and signal me, so don't do monitoring
	 * otherwise, do periodic monitoring */
	if (!output) {
		/* before timer start, update fast cpus load */
		if (mode == MODE_DYNAMIC_LOAD)
			get_fast_cpus_load();

		start_stat_monitor();
	}
}

static void stat_monitor(int arg)
{
	if (!slow_task_exist()) {
		restore_all_tasks();
		return;
	}
	if (mode == MODE_DYNAMIC_LOAD)
		adjust_fast_cpus();
	start_stat_monitor();
}

static void monitor_input(int epfd)
{
	int i;
	int nr_events;
	struct epoll_event events[MAX_INPUT_EVENTS];
	struct input_event input_evt[64];
	int size = sizeof (struct input_event);
	struct input_descriptor *idesc;
	static unsigned int seq_num = 1;

	while(1) {
		nr_events = epoll_wait(epfd, events, MAX_INPUT_EVENTS, -1);
		if (nr_events < 0 && errno == EINTR) {
			debug_printf(VB_DEBUG, "[DEBUG] monitor_input: epoll_wait returns <0 (%d) nr_events and intrrupted errno (%d)\n",
					nr_events, errno);
			continue;
		}
		for (i = 0; i < nr_events; i++) {
			idesc = (struct input_descriptor *)events[i].data.ptr;

			if (idesc->type == INPUT_TYPE_KEYBOARD) {
				int rsize;
				if ((rsize = read(idesc->fd, input_evt, size * 64)) < size) {
					debug_printf(VB_DEBUG, "[DEBUG] monitor_input (i=%d, nr_events=%d, errno=%d): read returns %d (< %d)\n",
							i, nr_events, errno, rsize, size);
					continue;
				}
				if (input_evt[0].value != ' ' && 
				    input_evt[1].value == 1 && 
				    input_evt[1].type == 1 &&
				    input_evt[1].code == 28) {	/* enter key press */
					debug_printf (VB_MAJOR, "\nI%d: keyboard (code=%d)\n", 
							seq_num++,
							(input_evt[1].code));
					isolate_slow_tasks(0);
				}
			}
			else if (idesc->type == INPUT_TYPE_MOUSE) {
				int rsize;
				if ((rsize = read(idesc->fd, input_evt, size * 64)) < size) {
					debug_printf(VB_DEBUG, "[DEBUG] monitor_input (i=%d, nr_events=%d, errno=%d): read returns %d (< %d)\n",
							i, nr_events, errno, rsize, size);
					continue;
				}
				if (input_evt[1].value == 0 &&	/* mouse click released */
				    input_evt[1].type == 1) {
					debug_printf(VB_MAJOR, "\nI%d: mouse ([0].value=%x [0].type=%x [1].value=%x [1].type=%x)\n",
						seq_num++,
						input_evt[0].value, input_evt[0].type,
						input_evt[1].value, input_evt[1].type);
					isolate_slow_tasks(0);
				}
			}
			else {
				int stat = 0;
				char buf[8];
				if (read(idesc->fd, buf, 8) > 0)
					stat = atoi(buf);
				debug_printf(VB_MAJOR, "\nA: audio output (stat=%d)\n", stat);
				isolate_slow_tasks(stat);
			}
		}
	}
}

/* slow, but convinient for initialization */
#define shell_command(args...) ({	\
	int ret;	\
	char cmd[256];	\
	snprintf(cmd, 256, args);	\
	ret = system(cmd);	\
	ret;	\
})

static int setup_cpuset(void)
{
	int ret;
	shell_command("mkdir -p %s", CPUSET_PATH);
	shell_command("mount -t cgroup -o cpuset none %s", CPUSET_PATH);
	shell_command("mkdir -p %s/%s", CPUSET_PATH, SLOW_GROUP_NAME);
	shell_command("mkdir -p %s/%s", CPUSET_PATH, FAST_GROUP_NAME);

	/* FIXME: currently assume guest kernel has memory node 0 */
	fileprintf(SLOW_MEMS_PATH, "%d", 0);
	fileprintf(FAST_MEMS_PATH, "%d", 0);

	mod_fast_cpus(nr_cpus);
	move_fast_tasks();

	/* simply check the above commands by the following */
	return shell_command("ls %s/%s/tasks > /dev/null", 
			CPUSET_PATH, SLOW_GROUP_NAME);
}

static int init_input_monitor(int nr_devs, char **input_devs)
{
	int i;
	int fd;
	int epfd;
	struct epoll_event event;

	if ((epfd = epoll_create(nr_devs + 1)) < 0) {	/* input device + audio fifo */
		perror("epoll_create");
		return -1;
	}
	for (i = 0; i < nr_devs && i < MAX_INPUT_DECS; i++) {
		if ((fd = open(input_devs[i], O_RDONLY)) == -1)
			exit_with_msg("file open error: %s\n", input_devs[i]);

		/* set input descriptor */
		input_desc[i].fd = fd;
		input_desc[i].type = i;
		input_desc[i].path = input_devs[i];
		ioctl (fd, EVIOCGNAME(INPUT_NAME_LEN), input_desc[i].name);

		/* add to epoll interface */
		event.events = EPOLLIN | EPOLLET;
		event.data.ptr = &input_desc[i];
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0) {
			perror("epoll_ctl");
			return -1;
		}
		printf ("path=%s name=%s fd=%d type=%d\n", 
				input_desc[i].path, 
				input_desc[i].name, 
				input_desc[i].fd,
				input_desc[i].type);
	}
	unlink(AUDIO_FIFO_PATH);
	umask(0000);
	if (mkfifo(AUDIO_FIFO_PATH, 0666) == -1)
		exit_with_msg("fail to create fifo file for audio\n");
	if ((fd = open(AUDIO_FIFO_PATH, O_RDWR)) == -1)
		exit_with_msg("file open error: %s\n", AUDIO_FIFO_PATH);
	input_desc[i].fd = fd;
	input_desc[i].type = INPUT_TYPE_AUDIO;
	input_desc[i].path = AUDIO_FIFO_PATH;
	ioctl (fd, EVIOCGNAME(INPUT_NAME_LEN), input_desc[i].name);

	/* add to epoll interface */
	event.events = EPOLLIN;
	event.data.ptr = &input_desc[i];
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0) {
		perror("epoll_ctl");
		return -1;
	}
	printf ("path=%s name=%s fd=%d type=%d\n", 
			input_desc[i].path, 
			input_desc[i].name, 
			input_desc[i].fd,
			input_desc[i].type);

	return epfd;
}

static void init_stat_monitor(void)
{
	struct sigaction act;
	act.sa_handler = stat_monitor;
	sigaction(SIGALRM, &act, 0);
}

static void make_myself_realtime(void)
{
	struct sched_param sp = { .sched_priority = 1 };
	if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0)
		perror("sched_setscheduler");
}

static void pin_myself_on_cpu0(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	
	if (sched_setaffinity(0, sizeof (cpu_set_t), &set) == 1)
		fprintf(stderr, "fail to pin myself on cpu0\n");
}

int main (int argc, char *argv[])
{
	int c;
	int epfd = -1;

	opterr = 0;
	while ((c = getopt (argc, argv, "f:i:m:p:v:")) != -1) {
		switch (c) {
			case 'f':
				init_nr_fast_cpus = atoi(optarg);
				break;
			case 'i':
				pin_irq = atoi(optarg);
				break;
			case 'm':
				mode = atoi(optarg);
				break;
			case 'p':
				stat_mon_period_us = atoi(optarg) * 1000;	/* ms->us */
				break;
			case 'v':
				verbose = atoi(optarg);
				break;
			default:
				exit_with_msg("Error: -%c is an invalid option!\n", c);
		}
	}
	argc -= (optind - 1);

	if (argc < 2 || mode >= MODE_END || mode < 0) {
        int i;
		fprintf(stderr, "Usage: %s [-v <verbose level>, -f <# of fast cpus>, -m <mode>, -p <irq num to be pinned>, -p <monitoring period>]" 
                        " <keyboard input device file> <mouse input device file> <others> ...\nAvailable modes:\n", argv[0]);
        for(i = 0; i < MODE_END; i++)
            fprintf(stderr, "%i: %s\n", i, mode_desc[i]);
        exit(-1);
	}

	if ((getuid()) != 0)
		exit_with_msg("%s", "Error: root privilege is required!\n");

	if ((epfd = init_input_monitor(argc - 1, &argv[optind])) < 0)
		exit_with_msg("%s", "Error: input monitor set failed!\n");

	if ((nr_cpus = sysconf(_SC_NPROCESSORS_ONLN)) < 1)
		exit_with_msg("%s", "Error: fail to get the number of CPUs!\n");

	if (nr_cpus == 1)
		exit_with_msg("%s", "Error: work only on SMP guest!\n");

	if (init_nr_fast_cpus > nr_cpus)
		exit_with_msg("%s", "Error: initial # of fast cpus (%d) is greater than # of available CPUs (%d)!\n",
				init_nr_fast_cpus, nr_cpus);

	if (nr_cpus - init_nr_fast_cpus < 1)
		init_nr_fast_cpus = 1;

	my_pid = getpid();

	printf("config: init_nr_fast_cpus=%d mode=%d stat_mon_period_us=%lums verbose=%d pin_irq=%d\n", 
			init_nr_fast_cpus, mode, stat_mon_period_us / 1000, verbose, pin_irq);
	printf("\t[MODE] %s\n", mode_desc[mode]);

	if (setup_cpuset() != 0)
		exit_with_msg("%s", "Error: cpuset cgroup setup is failed!\n");
	printf("cpuset configuration is done.\n");

	make_myself_realtime();

	pin_myself_on_cpu0();

	init_stat_monitor();

	monitor_input(epfd);

	return 0;
} 
