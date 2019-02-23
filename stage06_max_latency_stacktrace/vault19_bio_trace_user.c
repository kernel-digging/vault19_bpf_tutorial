#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"
#include "trace_helpers.h"

struct called_info
{
        __u64 start;
        __u64 end;
        __u64 stack_id;
};

struct max_latency_bio_info {
        __u64 bio_ptr;
        __u64 time_duration;
        __u64 bi_sector;
};

static void print_ksym(__u64 addr)
{
        struct ksym *sym;

        if (!addr)
                return;

        sym = ksym_search(addr);
        printf("=> %s()\n", sym->name);
}

static void print_max_latency_info(int called_info_map, int max_latency_info_map, int stacktrace_map)
{
        struct called_info called_info = {};
        struct max_latency_bio_info max_info;
        __u64 ip[PERF_MAX_STACK_DEPTH] = {};
        __u32 one_idx = 0;
        int i;

        bpf_map_lookup_elem(max_latency_info_map, &one_idx, &max_info);
        bpf_map_lookup_elem(called_info_map, &max_info.bio_ptr, &called_info);

        printf("\n=====================================================\n");
        printf("From: submit_bio(bio=%p) %llu\n", (void *) max_info.bio_ptr, called_info.start);
        printf("To  : bio_endio (bio=%p) %llu\n", (void *) max_info.bio_ptr, called_info.end);
        printf("Bio Info : Sector (%llu)\n", max_info.bi_sector);
        printf("Max latency %llu ns\n", max_info.time_duration);
        printf("=====================================================\n");

        if (bpf_map_lookup_elem(stacktrace_map, &called_info.stack_id, ip) != 0) {
                printf("Stack info not found !!\n");
        } else {
                for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
                        print_ksym(ip[i]);
        }
}

static void int_exit(int sig)
{
        print_max_latency_info(map_fd[0], map_fd[1], map_fd[2]);
        exit(0);
}

int main(int argc, char **argv)
{
        char filename[256];

        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

        if (load_bpf_file(filename)) {
                printf("%s", bpf_log_buf);
                return 1;
        }

        if (load_kallsyms()) {
                printf("failed to process /proc/kallsyms\n");
                return 2;
        }

        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);

        read_trace_pipe();

        return 0;
}
