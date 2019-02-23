#include <linux/ptrace.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") pagecache_retval_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u64),
        .value_size = sizeof(long),
        .max_entries = 10240,
};

struct bpf_map_def SEC("maps") filter_pid_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1,
};

SEC("kretprobe/pagecache_get_page")
int pagecache_get_page_retval(struct pt_regs *ctx)
{
        char fmt[] = "pagecache_get_page (retval=0x%lx)\n";
        long pagecache_retval = PT_REGS_RC(ctx);
        u64 start_time = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid();
        u32 *filter_pid;
        u32 one_idx = 0;

        filter_pid = bpf_map_lookup_elem(&filter_pid_map, &one_idx);

        if (!(filter_pid && (*filter_pid != pid))) {
                bpf_trace_printk(fmt, sizeof(fmt), pagecache_retval);
                bpf_map_update_elem(&pagecache_retval_map, &start_time, &pagecache_retval, BPF_ANY);
        }
        return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
