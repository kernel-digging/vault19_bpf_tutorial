#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

struct called_info
{
        __u64 start;
        __u64 end;
};

static void print_max_latency_info(int called_info_map, int max_latency_info_map)
{
        struct called_info called_info = {};
        __u32 key_idx = 0, val_idx = 1;
        __u64 bio_ptr, max_time_duration;

        bpf_map_lookup_elem(max_latency_info_map, &key_idx, &bio_ptr);
        bpf_map_lookup_elem(max_latency_info_map, &val_idx, &max_time_duration);
        bpf_map_lookup_elem(called_info_map, &bio_ptr, &called_info);

        printf("\n=====================================================\n");
        printf("From: submit_bio(bio=%p) %llu\n", (void *) bio_ptr, called_info.start);
        printf("To  : bio_endio (bio=%p) %llu\n", (void *) bio_ptr, called_info.end);
        printf("Max latency %llu ns\n", max_time_duration);
        printf("=====================================================\n");
}

static void int_exit(int sig)
{
        print_max_latency_info(map_fd[0], map_fd[1]);
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
