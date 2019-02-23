/*
 * Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2019 Taeung Song <taeung@kosslab.kr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#include <linux/log2.h>
#include <uapi/linux/ptrace.h>
#include <linux/blktrace_api.h>
#include <linux/genhd.h>
#include <linux/bio.h>

struct bpf_map_def SEC("maps") CTRACER_MAP_NAME = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64), /* time stamp */
	.value_size = sizeof(struct blk_io_trace), /* bio info */
	.max_entries = 100
};

/*
#define BPF_ANY		0 // create new element or update existing
#define BPF_NOEXIST	1 // create new element if it didn't exist
#define BPF_EXIST	2 // update existing element
*/

#define BLK_TC_RAHEAD		BLK_TC_AHEAD
#define BLK_TC_PREFLUSH		BLK_TC_FLUSH

/* The ilog2() calls fall out because they're constant */
#define MASK_TC_BIT(rw, __name) ((rw & REQ_ ## __name) << \
	  (ilog2(BLK_TC_ ## __name) + BLK_TC_SHIFT - __REQ_ ## __name))

#define _(P) ({typeof(P) val = {0}; bpf_probe_read(&val, sizeof(val), &P); val;})

SEC("kprobe/CTRACER_KERNEL_FUNCTION")
int bpf_prog2(struct pt_regs *ctx)
{
	struct bio *bio = (struct bio *) CTRACER_ARG_NTH(ctx);
	struct blk_io_trace t = {0};
	u64 cur_time = bpf_ktime_get_ns(); /* key */

	//struct gendisk *disk = _(bio->bi_disk);
	struct bvec_iter bi_iter = _(bio->bi_iter);
	sector_t sector = bi_iter.bi_sector;
	int bytes = bi_iter.bi_size;
	
	int op_flags = bio->bi_opf;
	int op = op_flags & REQ_OP_MASK;
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();
	u32 what;
	/*
	 * Data direction bit lookup
	 */
	static const u32 ddir_act[2] = { BLK_TC_ACT(BLK_TC_READ),
					 BLK_TC_ACT(BLK_TC_WRITE) };


	//bpf_probe_read(devname, sizeof(devname), dev->name);
	what |= ddir_act[op_is_write(op) ? WRITE : READ];
	what |= MASK_TC_BIT(op_flags, SYNC);
	what |= MASK_TC_BIT(op_flags, RAHEAD);
	what |= MASK_TC_BIT(op_flags, META);
	what |= MASK_TC_BIT(op_flags, PREFLUSH);
	what |= MASK_TC_BIT(op_flags, FUA);
	if (op == REQ_OP_DISCARD || op == REQ_OP_SECURE_ERASE)
		what |= BLK_TC_ACT(BLK_TC_DISCARD);
	if (op == REQ_OP_FLUSH)
		what |= BLK_TC_ACT(BLK_TC_FLUSH);

	t.magic = BLK_IO_TRACE_MAGIC | BLK_IO_TRACE_VERSION;
	t.time = cur_time;
	t.cpu = cpu;
	t.sector = sector;
	t.bytes = bytes;
	t.action = what;
	//t.device = disk_devt(disk);

	bpf_map_update_elem(&CTRACER_MAP_NAME, &cur_time, &t, BPF_NOEXIST);

	return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
