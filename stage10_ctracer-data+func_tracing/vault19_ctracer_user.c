/* Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h> 
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <errno.h>

#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"
#include <linux/blktrace_api.h>
#include "json_writer.h"
#include <perf-sys.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <fcntl.h> 
#include <sys/stat.h>

#define TRACING_DIR "/sys/kernel/debug/tracing/"
int trace_file;
int p_cnt;
FILE *json_fd;
json_writer_t *json_wtr;

struct bprog {
	int prog_fd;
	int map_fd;
	int efd;
	bool is_empty;
	char func_name[128];
};

struct bprog bprog_info[256];

static void dump_json(struct bprog *bp)
{
	struct blk_io_trace value;
	__u64 prev_key = -1, key;
	char json_key[64];
	int mfd = bp->map_fd;

	while (bpf_map_get_next_key(mfd, &prev_key, &key) == 0) {
		bpf_map_lookup_elem(mfd, &key, &value);

		snprintf(json_key, sizeof(json_key), "%lld/%s", value.time, bp->func_name);
		jsonw_name(json_wtr, json_key);

		jsonw_start_object(json_wtr);
		jsonw_ui_field(json_wtr, "magic", value.magic);
		jsonw_ui_field(json_wtr, "sequence", value.sequence);
		jsonw_llu_field(json_wtr, "time", value.time);
		jsonw_llu_field(json_wtr, "sector", value.sector);
		jsonw_ui_field(json_wtr, "bytes", value.bytes);
		jsonw_ui_field(json_wtr, "action", value.action);
		jsonw_ui_field(json_wtr, "pid", value.pid);
		jsonw_ui_field(json_wtr, "device", value.device);
		jsonw_ui_field(json_wtr, "cpu", value.cpu);
		jsonw_hu_field(json_wtr, "error", value.error);
		jsonw_hu_field(json_wtr, "pdu_len", value.pdu_len);
		jsonw_end_object(json_wtr);

		prev_key = key;
	}
	if (prev_key < 0)
		bp->is_empty = true;
}

static char *get_tracing_file(const char *name)
{
	static char file[256];

	sprintf(file, "%s/%s", TRACING_DIR, name);
	return file;
}

static int open_tracing_file(const char *name, bool append)
{
	char *file;
	int fd;
	int flags = O_WRONLY;

	file = get_tracing_file(name);
	if (!file) {
		printf("cannot get tracing file: %s: %m\n", name);
		return -1;
	}

	if (append)
		flags |= O_APPEND;
	else
		flags |= O_TRUNC;

	fd = open(file, flags);
	if (fd < 0)
		printf("cannot open tracing file: %s: %m\n", name);

	return fd;
}

static int write_all(int fd, const void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = write(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

static int _write_tracing_file(const char *name, const char *val, bool append)
{
	int ret = -1;
	ssize_t size = strlen(val);
	int fd = open_tracing_file(name, append);

	if (fd < 0)
		return -1;

	if (write(fd, val, size) == size)
		ret = 0;

	if (ret < 0)
		printf("write '%s' to tracing/%s failed: %m\n", val, name);

	close(fd);
	return ret;
}

static inline int write_tracing_file(const char *name, const char *val)
{
	return _write_tracing_file(name, val, false);
}

static inline int append_tracing_file(const char *name, const char *val)
{
	return _write_tracing_file(name, val, true);
}

static int write_kprobe_events(const char *val)
{
	int fd, ret, flags;

	if (val == NULL)
		return -1;
	else if (val[0] == '\0')
		flags = O_WRONLY | O_TRUNC;
	else
		flags = O_WRONLY | O_APPEND;

	fd = open(TRACING_DIR"kprobe_events", flags);

	ret = write(fd, val, strlen(val));
	close(fd);

	return ret;
}

static int parse_attach_event(const char *attach_type, const char *event, int *event_fd)
{
	bool need_normal_check = true;
	bool is_tracepoint, is_kprobe, is_kretprobe;
	struct perf_event_attr attr = {};
	const char *event_prefix = "";
	int efd, id, err;
	char buf[256];

	if (*attach_type == 0 || *event == 0) {
		printf("attach type or event name cannot be empty\n");
		return -EINVAL;
	}

	is_kprobe = strcmp(attach_type, "kprobe") == 0;
	is_kretprobe = strcmp(attach_type, "kretprobe") == 0;
	is_tracepoint = strcmp(attach_type, "tracepoint") == 0;

	if (is_kprobe || is_kretprobe) {
#ifdef __x86_64__
		if (strncmp(event, "sys_", 4) == 0) {
			snprintf(buf, sizeof(buf), "%c:__x64_%s __x64_%s",
				is_kprobe ? 'p' : 'r', event, event);
			err = write_kprobe_events(buf);
			if (err >= 0) {
				need_normal_check = false;
				event_prefix = "__x64_";
			}
		}
#endif
		if (need_normal_check) {
			snprintf(buf, sizeof(buf), "%c:%s %s",
				is_kprobe ? 'p' : 'r', event, event);
			err = write_kprobe_events(buf);
			if (err < 0) {
				printf("failed to create kprobe '%s' error '%s'\n",
				       event, strerror(errno));
				return -1;
			}
		}

		strcpy(buf, TRACING_DIR);
		strcat(buf, "events/kprobes/");
		strcat(buf, event_prefix);
		strcat(buf, event);
		strcat(buf, "/id");

	} else if (is_tracepoint) {
		event += 11;

		if (*event == 0) {
			printf("event name cannot be empty\n");
			return -1;
		}
		strcpy(buf, TRACING_DIR);
		strcat(buf, "events/");
		strcat(buf, event);
		strcat(buf, "/id");
	}

	efd = open(buf, O_RDONLY, 0);
	if (efd < 0) {
		printf("failed to open event %s\n", event);
		return -1;
	}

	err = read(efd, buf, sizeof(buf));
	if (err < 0 || err >= (int)sizeof(buf)) {
		printf("read from '%s' failed '%s'\n", event, strerror(errno));
		close(efd);
		return -1;
	}

	close(efd);

	buf[err] = 0;
	id = atoi(buf);
	attr.config = id;
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	efd = sys_perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (efd < 0) {
		printf("event %d fd %d err %s\n", id, efd, strerror(errno));
		return -1;
	}
	*event_fd = efd;

	return 0;
}

static int do_attach(int prog_fd, const char *func_name)
{
	int err;
	int event_fd;

	err = parse_attach_event("kprobe", func_name, &event_fd);
	if (err < 0)
		return err;

	bprog_info[p_cnt].efd = event_fd;

	err = ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (err < 0) {
		printf("ioctl PERF_EVENT_IOC_ENABLE failed err %s\n",
		       strerror(errno));
		goto err_close;
	}
	err = ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (err < 0) {
		printf("ioctl PERF_EVENT_IOC_SET_BPF failed err %s\n",
		       strerror(errno));
		goto err_close;
	}

	return 0;
err_close:
	close(event_fd);
	return -1;
}


#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

static int open_obj_pinned(char *path)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	__u32 map_ids[2];
	int fd, map_fd, err;

	fd = bpf_obj_get(path);
	if (fd < 0) {
		printf("bpf obj get (%s): %s\n", path, strerror(errno));
		return -1;
	}

	info.nr_map_ids = 1;
	info.map_ids = ptr_to_u64(map_ids);

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		printf("can't get prog info: %s", strerror(errno));
		return -1;
	}

	map_fd = bpf_map_get_fd_by_id(map_ids[0]);
	if (map_fd < 0) {
		printf("can't get map by id (%u): %s",
			      map_ids[0], strerror(errno));
		return -1;
	}

	bprog_info[p_cnt].map_fd = map_fd;

	return fd;
}

static int attach_kprobe_bpf(const char *dir_path, const char *bpf_prog_name)
{
	int prog_fd;
	char filename[256];

	strcpy(bprog_info[p_cnt].func_name, bpf_prog_name);
	sprintf(filename, "%s/%s", dir_path, bpf_prog_name);
	prog_fd = open_obj_pinned(filename);
	if (do_attach(prog_fd, bpf_prog_name) < 0) {
		printf("%s", bpf_log_buf);
		return -1;
	}
	bprog_info[p_cnt].prog_fd = prog_fd;
	append_tracing_file("set_graph_function", bpf_prog_name);
	printf("%d) Attached bpf prog: %s\n", p_cnt, filename);

	p_cnt++;
	return 0;
}

static int attach_bpf_prog_list(const char *dir_path)
{
	DIR *d;
	struct dirent *dir;

	d = opendir(dir_path);
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (!strcmp(dir->d_name, "..") || !strcmp(dir->d_name, "."))
				continue;
			if (attach_kprobe_bpf(dir_path, dir->d_name) < 0)
				return -1;
		}

		closedir(d);
	}
	return 0;
}

static void int_exit(int sig)
{
	int i;

	close(trace_file);
	write_tracing_file("tracing_on","0");

	json_wtr = jsonw_new(json_fd);
	jsonw_start_object(json_wtr); //start

	jsonw_name(json_wtr, "data");
	jsonw_start_object(json_wtr);
	for (i = 0; i < p_cnt; i++)
		dump_json(&bprog_info[i]);

	jsonw_end_object(json_wtr);

	jsonw_name(json_wtr, "srcline");
	jsonw_start_object(json_wtr);
	for (i = 0; i < p_cnt; i++) {
		if (!bprog_info[i].is_empty)
			jsonw_null_field(json_wtr, bprog_info[i].func_name);
	}
	jsonw_end_object(json_wtr);

	jsonw_end_object(json_wtr); //end
	jsonw_destroy(&json_wtr);
	fclose(json_fd);
	exit(0);
}

int main(int argc, char **argv)
{
	int trace_fd;

	printf(" Done\n");
	printf("Setting ftrace configurations ...");
	write_tracing_file("tracing_on", "0");
	write_tracing_file("trace", "0");
	write_tracing_file("options/funcgraph-abstime", "1");
	write_tracing_file("current_tracer","function_graph");
	write_tracing_file("trace_clock", "mono");
	write_tracing_file("set_ftrace_pid"," ");
	write_tracing_file("set_graph_function"," ");
	write_tracing_file("set_graph_notrace","kprobe_ftrace_handler");
	write_tracing_file("set_ftrace_notrace"," ");
	write_tracing_file("set_ftrace_filter", " ");
	write_tracing_file("set_event_pid"," ");
	write_tracing_file("set_event"," ");
	write_tracing_file("max_graph_depth","30");
	write_tracing_file("buffer_size_kb", "1408");
	printf(" Done\n");

	trace_file = open("/tmp/ftrace.data", O_WRONLY | O_CREAT| O_TRUNC, 0644);

	if (!trace_file)
		return -1;

	json_fd = fopen("/tmp/ctracer.json", "w");
	if (!json_fd)
		return -1;

	if (attach_bpf_prog_list("/sys/fs/bpf") < 0) {
		printf("Error: cannot attach bpf progs\n");
		return -1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	write_tracing_file("tracing_on","1");
	trace_fd = open(TRACING_DIR"trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return 0;
	
	while (1) {
		static char buf[4096];
		ssize_t n;
retry:
		n = read(trace_fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				goto retry;
			if (errno == EAGAIN)
				return 0;
			else
				return -errno;
		}

		if (n == 0)
			return 0;
		write_all(trace_file, buf, n);
	}
	return 0;
}

