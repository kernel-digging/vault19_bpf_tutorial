#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("kprobe/submit_bio")
int submit_bio_entry(struct pt_regs *ctx)
{
        char fmt[] = "submit_bio() called: %llu\n";
        u64 start_time = bpf_ktime_get_ns();

        bpf_trace_printk(fmt, sizeof(fmt), start_time);
        return 0;
}

SEC("kprobe/bio_endio")
int bio_endio_entry(struct pt_regs *ctx)
{
        char fmt[] = "bio_endio() called: %llu\n";
        u64 end_time = bpf_ktime_get_ns();

        bpf_trace_printk(fmt, sizeof(fmt), end_time);
        return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
