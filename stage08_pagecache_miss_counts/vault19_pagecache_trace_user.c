#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

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

        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

        if (load_bpf_file(filename)) {
                printf("%s", bpf_log_buf);
                return 1;
        }

        signal(SIGINT, int_exit);
        signal(SIGTERM, int_exit);

        read_trace_pipe();

        return 0;
}
