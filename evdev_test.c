#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <dirent.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <linux/input.h>
#include <linux/uinput.h>

/*
 * definition from kernel
 */

#define NSEC_PER_SEC    1000000000L

struct input_value {
	__u16 type;
	__u16 code;
	__s32 value;
};

struct input_composite_event {
	struct input_value v;
	__s64 time;
};

#define TIMESPEC_TO_TIMEVAL(tv, ts) {                                   \
	(tv)->tv_sec = (ts)->tv_sec;                                    \
	(tv)->tv_usec = (ts)->tv_nsec / 1000;                           \
}

#define EVIOCSIFTYPE		_IOW('E', 0xa1, int)
#define EVIOCGIFTYPE		_IOR('E', 0xa2, int)

#define EVDEV_LEGACY			0x00
#define EVDEV_RAW			0x01
#define EVDEV_COMPOSITE			0x02

#define UINPUT_PATH	"/dev/uinput"
#define EVDEV_DIR	"/dev/input"
#define EVDEV_NAME	"evdev-test"

static int rel_x_cnt[3] = { 0 };
static int rel_y_cnt[3] = { 0 };
static int syn_cnt[3] = { 0 };
static int timestamp_cnt = 0;
static int child_exited = 0;
static int test_legacy = 0;
static int test_raw = 0;
static int test_composite = 0;
static int event_num = 2000;
static int dump_event_flag = 0;
static int evdev_inject = 0;

struct timespec ns_to_timespec(const int64_t nsecs)
{
	struct timespec ts;

	ts.tv_sec = nsecs / NSEC_PER_SEC;
	ts.tv_nsec = nsecs % NSEC_PER_SEC;

	return ts;
}

int timespec_compare(const struct timespec *lhs, const struct timespec *rhs)
{
	if (lhs->tv_sec < rhs->tv_sec)
		return -1;
	if (lhs->tv_sec > rhs->tv_sec)
		return 1;
	return lhs->tv_nsec - rhs->tv_nsec;
}

void show_usage(void)
{
	printf("evtest - tool to test new evdev interface\n");
	printf("Usage: evtest [-i] [-l] [-r] [-c] [-d] [-n NUM] [-h]\n");
	printf("\t-i: write event via evdev, default uinput\n");
	printf("\t-l: test legacy evdev interface, default false\n");
	printf("\t-r: test raw evdev interface, default false\n");
	printf("\t-c: test composite evdev interface, default false\n");
	printf("\t-d: dump test events, default false\n");
	printf("\t-n NUM: specify test event number, default 2000\n");
	printf("\t-h: show this help\n");
}

void show_statistic(void)
{
	printf("Result:\n");
	printf("Total event sent: %d\n", event_num * 3);
	printf("Legacy evdev: REL_X %d, REL_Y %d, EV_SYN %d\n",
			rel_x_cnt[0], rel_y_cnt[0], syn_cnt[0]);
	printf("Raw evdev: REL_X %d, REL_Y %d, EV_SYN %d\n",
			rel_x_cnt[1], rel_y_cnt[1], syn_cnt[1]);
	printf("Composite evdev: REL_X %d, REL_Y %d, EV_SYN %d, timestamp %d\n",
			rel_x_cnt[2], rel_y_cnt[2], syn_cnt[2], timestamp_cnt);
}

int find_evdev_device(char *name)
{
	char devpath[255] = { 0 };
	char devname[80] = { 0 };
	char *namep;
	DIR *dir;
	struct dirent *de;
	int fd;

	dir = opendir(EVDEV_DIR);
	if (dir == NULL)
		return -1;

	strcpy(devpath, EVDEV_DIR);
	namep = devpath + strlen(devpath);
	*namep++ = '/';

	while (de = readdir(dir)) {
		if (de->d_name[0] == '.')
			continue;
		if (strncmp(de->d_name, "event", 5))
			continue;

		strcpy(namep, de->d_name);
		fd = open(devpath, O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			warn("open %s failed", devpath);
			continue;
		}

		if (ioctl(fd, EVIOCGNAME(sizeof(devname) - 1), &devname)
				< 1) {
			warn("get %s name failed", devpath);
			close(fd);
			continue;
		}
		if (strncmp(name, devname, strlen(devname))) {
			close(fd);
			continue;
		} else {
			printf("find target device %s\n", devpath);
			break;
		}

		return -1;
	}

	return fd;
}

void validate_evdev_legacy_event(struct input_event *ev, int length)
{
	struct timespec ts;
	struct timeval tv;
	int i;

	for (i = 0; i < length; i++) {
		if (dump_event_flag)
			printf("legacy input_event: %d, %d, %d\n",
				ev[i].type, ev[i].code, ev[i].value);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		TIMESPEC_TO_TIMEVAL(&tv, &ts);
		if (!timercmp(&ev[i].time, &tv, <=))
			fprintf(stderr,
			  "old_ev: find illegal timestamp %ld.%ld, now %ld.%ld\n",
				ev[i].time.tv_sec, ev[i].time.tv_usec,
				tv.tv_sec, tv.tv_usec);

		if (ev[i].type == EV_REL) {
			if (ev[i].code == REL_X)
				rel_x_cnt[0]++;
			else if (ev[i].code == REL_Y)
				rel_y_cnt[0]++;
		} else if (ev[i].type == EV_SYN) {
			if (ev[i].code == SYN_REPORT)
				syn_cnt[0]++;
			else if (ev[i].code == SYN_DROPPED)
				fprintf(stderr,
					"legacy_ev: event drop detected\n");
		}
	}
}

void validate_evdev_raw_event(struct input_value *ev, int length)
{
	int i;

	for (i = 0; i < length; i++) {
		if (dump_event_flag)
			printf("raw input_value: %d, %d, %d\n",
				ev[i].type, ev[i].code, ev[i].value);
		if (ev[i].type == EV_REL) {
			if (ev[i].code == REL_X)
				rel_x_cnt[1]++;
			else if (ev[i].code == REL_Y)
				rel_y_cnt[1]++;
		} else if (ev[i].type == EV_SYN) {
			if (ev[i].code == SYN_REPORT)
				syn_cnt[1]++;
			else if (ev[i].code == SYN_DROPPED)
				fprintf(stderr,
					"raw_ev: event drop detected\n");
		}
	}
}

void validate_evdev_composite_event(struct input_composite_event *ev,
		int length)
{
	struct timespec now, timestamp;
	int i;

	for (i = 0; i < length; i++) {
		if (dump_event_flag) {
			printf("composite input_value: %d, %d, %d\n",
				ev[i].v.type, ev[i].v.code, ev[i].v.value);
			printf("composite timestamp: %lld\n", ev[i].time);
		}
		if (ev[i].v.type == EV_REL) {
			if (ev[i].v.code == REL_X)
				rel_x_cnt[2]++;
			else if (ev[i].v.code == REL_Y)
				rel_y_cnt[2]++;
		} else if (ev[i].v.type == EV_SYN) {
			if (ev[i].v.code == SYN_REPORT)
				syn_cnt[2]++;
			else if (ev[i].v.code == SYN_DROPPED)
				fprintf(stderr,
					"comp_ev: event drop detected\n");
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		timestamp = ns_to_timespec(ev[i].time);
		if (timespec_compare(&timestamp, &now)
				> 0)
			fprintf(stderr, "comp_ev: find illegal timestamp %lld, now %ld.%ld\n",
					ev[i].time, now.tv_sec, now.tv_nsec);
		else
			timestamp_cnt++;
	}
}

void sigusr_handle(int sig)
{
	if (sig == SIGUSR1)
		child_exited = 1;
}

void run_parent_task(int fd)
{
	char linkpath[255] = { 0 }, filepath[255] = { 0 };
	struct input_event ev_legacy[10] = { 0 };
	struct input_value ev_new[10] = { 0 };
	struct input_composite_event ev_composite[10] = { 0 };
	struct pollfd pollfds[3] = { 0 };
	int count;
	int status;
	unsigned int clock_id = CLOCK_MONOTONIC;
	unsigned int if_type = EVDEV_RAW;
	int i;

	sprintf(linkpath, "/proc/self/fd/%d", fd);
	if(readlink(linkpath, filepath, 255) < 0)
		err(1, "readlink %s failed", linkpath);

	if (test_legacy) {
		/*
		 * EVDEV_LEGACY
		 */
		pollfds[0].fd = open(filepath, O_RDWR | O_NONBLOCK);;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;
		if (ioctl(pollfds[0].fd, EVIOCSCLOCKID, &clock_id) < 0)
			err(1, "evdev ioctl clockid failed");
	}

	if (test_raw) {
		/*
		 * EVDEV_RAW
		 */
		pollfds[1].fd = open(filepath, O_RDWR | O_NONBLOCK);
		pollfds[1].events = POLLIN;
		pollfds[1].revents = 0;
		if (ioctl(pollfds[1].fd, EVIOCSCLOCKID, &clock_id) < 0)
			err(1, "evdev ioctl clockid failed");
		if (ioctl(pollfds[1].fd, EVIOCSIFTYPE, &if_type) < 0)
			err(1, "evdev ioctl evdev_raw failed");
	}

	if (test_composite) {
		/*
		 * EVDEV_COMPOSITE
		 */
		pollfds[2].fd = open(filepath, O_RDWR | O_NONBLOCK);
		pollfds[2].events = POLLIN;
		pollfds[2].revents = 0;
		if_type = EVDEV_COMPOSITE;
		if (ioctl(pollfds[2].fd, EVIOCSCLOCKID, &clock_id) < 0)
			err(1, "evdev ioctl clockid failed");
		if (ioctl(pollfds[2].fd, EVIOCSIFTYPE, &if_type) < 0)
			err(1, "evdev ioctl evdev_composite failed");
	}

	for ( ;; ) {
		/*
		 * check the child status
		 */
		if (child_exited == 1)
			child_exited++;
		else if (child_exited > 1) {
			for (i = 0; i < 3; i++)
				close(pollfds[i].fd);
			break;
		}

		if (poll(pollfds, 3, 10) <= 0)
			continue;

		if (test_legacy && (pollfds[0].revents & POLLIN)) {
			count = read(pollfds[0].fd,
					ev_legacy, sizeof(ev_legacy));
			if (count > 0) {
				validate_evdev_legacy_event(ev_legacy,
					count / sizeof(struct input_event));
				pollfds[0].revents = 0;
			} else
				warn("legacy read event failed, cnt %d", count);
		}

		if (test_raw && (pollfds[1].revents & POLLIN)) {
			count = read(pollfds[1].fd,
					ev_new, sizeof(ev_new));
			if (count > 0) {
				validate_evdev_raw_event(ev_new,
					count / sizeof(struct input_value));
				pollfds[1].revents = 0;
			} else
				warn("raw read event failed, cnt %d", count);
		}

		if (test_composite && (pollfds[2].revents & POLLIN)) {
			count = read(pollfds[2].fd,
					ev_composite, sizeof(ev_composite));
			if (count > 0) {
				validate_evdev_composite_event(ev_composite,
					count /
					sizeof(struct input_composite_event));
				pollfds[2].revents = 0;
			} else
				warn("comp read event failed, cnt %d", count);
		}
	}
}

void run_child_task(int fd)
{
	int count = 0, size;
	struct input_event ev_legacy[3] = {
		{ .type = EV_REL, .code = REL_X },
		{ .type = EV_REL, .code = REL_Y },
		{ .type = EV_SYN, .code = SYN_REPORT }
	};
	struct input_value ev_raw[3] = {
		{ .type = EV_REL, .code = REL_X },
		{ .type = EV_REL, .code = REL_Y },
		{ .type = EV_SYN, .code = SYN_REPORT }
	};
	struct input_composite_event ev_comp[3] = {
		{ .v.type = EV_REL, .v.code = REL_X },
		{ .v.type = EV_REL, .v.code = REL_Y },
		{ .v.type = EV_SYN, .v.code = SYN_REPORT }
	};
	void *ev;
	int if_type;

	if (fd < 0)
		return;

	srand(time(NULL));

	while (count++ < event_num) {
		if (evdev_inject) {
			switch (rand() % 3) {
			case 0:
				ev = ev_legacy;
				size = sizeof(ev_legacy);
				ev_legacy[0].value = count + 1;
				ev_legacy[1].value = count + 2;
				ev_legacy[2].value = 0;
				if_type = EVDEV_LEGACY;
				if (ioctl(fd, EVIOCSIFTYPE, &if_type) < 0)
					warn("evdev ioctl evdev_legacy failed");
				break;
			case 1:
				ev = ev_raw;
				size = sizeof(ev_raw);
				ev_raw[0].value = count + 1;
				ev_raw[1].value = count + 2;
				ev_raw[2].value = 0;
				if_type = EVDEV_RAW;
				if (ioctl(fd, EVIOCSIFTYPE, &if_type) < 0)
					warn("evdev ioctl evdev_raw failed");
				break;
			case 2:
				ev = ev_comp;
				size = sizeof(ev_comp);
				ev_comp[0].v.value = count + 1;
				ev_comp[1].v.value = count + 2;
				ev_comp[2].v.value = 0;
				if_type = EVDEV_COMPOSITE;
				if (ioctl(fd, EVIOCSIFTYPE, &if_type) < 0)
					warn("evdev ioctl evdev_comp failed");
				break;
			}
		} else {
			ev = ev_legacy;
			size = sizeof(ev_legacy);
			ev_legacy[0].value = count + 1;
			ev_legacy[1].value = count + 2;
			ev_legacy[2].value = 0;
		}

		if (write(fd, ev, size) < 0)
			warn("uinput: write event error");

		usleep(rand() % 100);
	}
}

int main(int argc, char *argv[])
{
	int fd, evdev_fd;
	struct uinput_user_dev uidev;
	pid_t pid;
	struct sigaction act = { .sa_handler = sigusr_handle };
	int ret = 0, i;

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "-l", 2))
			test_legacy = 1;
		else if (!strncmp(argv[i], "-r", 2))
			test_raw = 1;
		else if (!strncmp(argv[i], "-c", 2))
			test_composite = 1;
		else if (!strncmp(argv[i], "-d", 2))
			dump_event_flag = 1;
		else if (!strncmp(argv[i], "-i", 2))
			evdev_inject = 1;
		else if (!strncmp(argv[i], "-n", 2))
			event_num = atoi(argv[++i]);
		else if (!strncmp(argv[i], "-h", 2)) {
			show_usage();
			exit(0);
		} else
			fprintf(stderr, "illegal option %s\n", argv[i]);
	}

	printf("Options: legacy %d, raw, %d, composite %d, inject %d, dump %d, evnum %d\n",
			test_legacy, test_raw, test_composite,
			evdev_inject, dump_event_flag, event_num);

	fd = open(UINPUT_PATH, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		err(1 ,"open %s failed", UINPUT_PATH);

	ret = ioctl(fd, UI_SET_EVBIT, EV_REL);
	ret |= ioctl(fd, UI_SET_RELBIT, REL_X);
	ret |= ioctl(fd, UI_SET_RELBIT, REL_Y);
	if (ret < 0)
		err(1, "set evbit failed");

	memset(&uidev, 0, sizeof(uidev));
	snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, EVDEV_NAME);
	uidev.id.bustype = BUS_USB;
	uidev.id.vendor  = 0x1;
	uidev.id.product = 0x1;
	uidev.id.version = 1;

	if(write(fd, &uidev, sizeof(uidev)) < 0)
		err(1, "uinput: write uidev error");

	if(ioctl(fd, UI_DEV_CREATE) < 0)
		err(1, "uinput: create device error");

	sleep(1);

	evdev_fd = find_evdev_device(EVDEV_NAME);
	if (evdev_fd < 0)
		err(1, "can not find device %s", EVDEV_NAME);

	sigaction(SIGUSR1, &act, NULL);

	pid = fork();
	if (pid > 0) {
		run_parent_task(evdev_fd);
	} else if (pid == 0) {
		sleep(1); // wait for parent poll ready
		if (evdev_inject)
			run_child_task(evdev_fd);
		else
			run_child_task(fd);
		kill(getppid(), SIGUSR1);
		_exit(0);
	} else
		err(1, "fork error");

	show_statistic();

	close(evdev_fd);
	if(ioctl(fd, UI_DEV_DESTROY) < 0)
		err(1, "uinput: destroy device failed");

	close(fd);
	return 0;
}
