#!/usr/bin/env python
import os, json, sys, errno, subprocess

def help():
    print "Usage: ctracer-load.py BPF_OBJS_PATH\n"
    print "       ctracer-load.py - load and pin built BPF programs(kernel) using bpftool\n"
    print "       BPF_OBJS_PATH := a path like ~/git/linux/samples/bpf/ that contains *-ctracer.o\n"
    exit()
    
if len(sys.argv) != 2:
    print "Error: wrong arguments"
    help()

obj_path = sys.argv[1]
if "~/" in obj_path:
    obj_path = obj_path.replace("~/","%s/")
if not os.path.exists(obj_path):
    print "Error: No %s"%obj_path
    exit()

t_path = "tfunc.json"
if not os.path.exists(t_path):
    print "Error: No %s"%t_path
    exit()

fd=open(t_path,"r")
t=fd.read()
tfunc_list=json.loads(t)

print "Check bpffs mount ..."
bpffs_mount_info = os.popen("mount | grep bpffs").readlines()
if not bpffs_mount_info:
    os.popen("sudo mount bpffs /sys/fs/bpf -t bpf")

print "Check /tmp ramdisk mount ..."
print "for recorded ctracer data(ftrace.data and ctracer.json)"
# prepare /tmp for ftrace.data and ctracer.json
tmp_mount_info = os.popen("mount | grep /tmp").readlines()
if not tmp_mount_info:
    os.popen("sudo mount -t tmpfs -o size=512M tmpfs /tmp")

def shell(cmd):
    p = subprocess.Popen(cmd ,stderr=subprocess.PIPE, shell=True)
    err_msg = p.stderr.read()
    if  "Permission" in err_msg or "permitted" in err_msg:
        print err_msg
        exit()
    if "err" in err_msg or "Err" in err_msg or  "cannot" in err_msg:
        print "Error: %s  cmd: %s"%(err_msg, cmd)
        return False
    return True

cnt = 0
print "Loading and  Pinning BPF programs to /sys/fs/bpf/ ..."
for tf in tfunc_list:
    func_name = tf["func_name"]
    c = "%s/%s-ctracer.o"%(obj_path, func_name)

    if not os.path.exists(c):
        print "Warning: No %s"%c
        continue

    pin = "/sys/fs/bpf/%s"%func_name
    os.popen("rm -f %s"%pin)
    l="%s %s"%(c, pin)
    if not shell("bpftool prog load " + l):
        continue
    cnt+=1
print "Done (%d) "%cnt

