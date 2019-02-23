#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

__u32 pid_filter;

static void print_pagecache_retval_stats(int pagecache_retval_map)
{
        __u64 key = -1, next_key;
        long pagecache_retval;
        int hit = 0, miss = 0;

        while (bpf_map_get_next_key(pagecache_retval_map, &key, &next_key) == 0) {
                bpf_map_lookup_elem(pagecache_retval_map, &next_key, &pagecache_retval);

                if (pagecache_retval)
                        hit++;
                else
                        miss++;

                key = next_key;
        }

        printf("\n=====================================================\n");
        if (pid_filter)
                printf("Filtered PID : %u\n", pid_filter);
        printf("[Total %d Hit %d miss %d] \n", hit + miss, hit, miss);
        printf("=====================================================\n");
}

static void int_exit(int sig)
{
        print_pagecache_retval_stats(map_fd[0]);
        exit(0);
}

int main(int argc, char **argv)
{
        char filename[256];
        int pid_filter_map;
        __u32 one_idx = 0;

        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

        if (load_bpf_file(filename)) {
                printf("%s", bpf_log_buf);
                return 1;
        }

        pid_filter_map = map_fd[1];
        if (argc > 1) {
                pid_filter = atoi(argv[1]);
                bpf_map_update_elem(pid_filter_map, &one_idx, &pid_filter, BPF_ANY);
                printf("\n==================================\n");
                printf("pid_filter_map update: (pid=%u)\n", pid_filter);
                printf("==================================\n");
        }

        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);

        read_trace_pipe();

        return 0;
}
