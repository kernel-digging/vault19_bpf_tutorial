#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct called_info {
        u64 start;
        u64 end;
};

struct bpf_map_def SEC("maps") called_info_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(long),
        .value_size = sizeof(struct called_info),
        .max_entries = 4096,
};

SEC("kprobe/blk_mq_start_request")
int submit_bio_entry(struct pt_regs *ctx)
{
        char fmt[] = "blk_mq_start_request(rq=0x%lx) is called!\n";
        u64 start_time = bpf_ktime_get_ns();
        long rq_ptr = PT_REGS_PARM1(ctx);
        struct called_info called_info = {
                .start = start_time,
                .end = 0
        };

        bpf_map_update_elem(&called_info_map, &rq_ptr, &called_info, BPF_ANY);
        bpf_trace_printk(fmt, sizeof(fmt), rq_ptr, start_time);
        return 0;
}

SEC("kprobe/blk_account_io_completion")
int bio_endio_entry(struct pt_regs *ctx)
{
        char fmt2[] = "blk_mq_start_request() -> blk_account_io_completion() time duration: %llu ns\n\n";
        char fmt[] = "blk_account_io_completion(rq=0x%lx) is called!\n";
        u64 end_time = bpf_ktime_get_ns();
        long rq_ptr = PT_REGS_PARM1(ctx);
        struct called_info *called_info;
        u64 time_duration;

        called_info = bpf_map_lookup_elem(&called_info_map, &rq_ptr);
        if (!called_info)
                return 0;

        called_info->end = end_time;
        time_duration = called_info->end - called_info->start;

        bpf_trace_printk(fmt, sizeof(fmt), rq_ptr, end_time);
        bpf_trace_printk(fmt2, sizeof(fmt2), time_duration);
        return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
