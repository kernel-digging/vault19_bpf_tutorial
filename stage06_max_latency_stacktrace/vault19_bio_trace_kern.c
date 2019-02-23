#include <linux/ptrace.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/bio.h>
#include "bpf_helpers.h"

struct called_info {
        u64 start;
        u64 end;
        u64 stack_id;
};

struct bpf_map_def SEC("maps") called_info_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(long),
        .value_size = sizeof(struct called_info),
        .max_entries = 4096,
};

struct max_latency_bio_info {
        u64 bio_ptr;
        u64 time_duration;
        u64 bi_sector;
};

/* Only one entity */
struct bpf_map_def SEC("maps") max_latency_info = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(struct max_latency_bio_info),
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") stacktrace_map = {
        .type = BPF_MAP_TYPE_STACK_TRACE,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64) * PERF_MAX_STACK_DEPTH,
        .max_entries = 1024,
};

#define _(P) ({typeof(P) val = {0}; bpf_probe_read(&val, sizeof(val), &P); val;})

SEC("kprobe/submit_bio")
int submit_bio_entry(struct pt_regs *ctx)
{
        char fmt[] = "submit_bio(bio=0x%lx) called: %llu\n";
        u64 start_time = bpf_ktime_get_ns();
        long stack_id, bio_ptr = PT_REGS_PARM1(ctx);
        struct called_info called_info = {
                .start = start_time,
                .end = 0,
                .stack_id = 0
        };

        stack_id = bpf_get_stackid(ctx, &stacktrace_map, 0);
        if (stack_id)
                called_info.stack_id = stack_id;

        bpf_map_update_elem(&called_info_map, &bio_ptr, &called_info, BPF_ANY);
        bpf_trace_printk(fmt, sizeof(fmt), bio_ptr, start_time);
        return 0;
}

SEC("kprobe/bio_endio")
int bio_endio_entry(struct pt_regs *ctx)
{
        char fmt2[] = "submit_bio() -> bio_endio() time duration: %llu ns\n\n";
        char fmt[] = "bio_endio (bio=0x%lx) called: %llu\n";
        u64 end_time = bpf_ktime_get_ns();
        long bio_ptr = PT_REGS_PARM1(ctx);
        struct called_info *called_info;
        u32 one_idx = 0;
        struct max_latency_bio_info *prev;
        struct max_latency_bio_info curr;
        struct bvec_iter bi_iter;
        u64 time_duration;
        struct bio *bio;
        sector_t sector;

        called_info = bpf_map_lookup_elem(&called_info_map, &bio_ptr);
        if (!called_info)
                return 0;

        called_info->end = end_time;
        time_duration = called_info->end - called_info->start;

        bpf_trace_printk(fmt, sizeof(fmt), bio_ptr, end_time);
        bpf_trace_printk(fmt2, sizeof(fmt2), time_duration);

        prev = bpf_map_lookup_elem(&max_latency_info, &one_idx);

        if (prev && (time_duration <= prev->time_duration))
                return 0;

        bio = (struct bio *) bio_ptr;
        bi_iter = _(bio->bi_iter);

        curr.bio_ptr = bio_ptr;
        curr.time_duration = time_duration;
        curr.bi_sector = bi_iter.bi_sector;

        bpf_map_update_elem(&max_latency_info, &one_idx, &curr, BPF_ANY);
        return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
