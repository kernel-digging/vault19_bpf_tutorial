#!/usr/bin/env python
import os, json, sys, errno, subprocess

def help():
    print "Usage: gen-BPF-recorder.py [options] STRUCT_TYPE_NAME\n"
    print "       gen-BPF-recorder.py - generate BPF programs\n"
    print "       STRUCT_TYPE_NAME := a structure type(class) name to track (e.g. 'bio')"
    print "Options:\n"
    print "        -s, --srcline        have 'srcline' info" 

    exit()

argc =  len(sys.argv)
if argc > 3 or argc < 2:
    print "Error: wrong arguments\n"
    help()

struct_type_name = None
option=None
if argc == 3:
    option = sys.argv[1]
    if not option == "-s" or not option == "--srcline":
        print "Error: wrong option %s"%option
        exit()

    struct_type_name = sys.argv[2]
else:
    struct_type_name = sys.argv[1]

    
kfunc_json_path="vmlinux.debuginfo/kfunc.json"
if not os.path.exists(kfunc_json_path):
    print "Error: No kfunc.json, please run setup.py"
    exit()

tfunc_list = list()
fd=open(kfunc_json_path,"r")
k=fd.read()
# this is vmlinux.debuginfo/kfunc.json
func_debug_info=json.loads(k)
c0 = 0
def find_class(class_name):
    found = False
    class_name = "struct %s "%class_name
    for fi in func_debug_info:
        global c0
        c0 +=1
        if not fi["arg_type"]:
            print fi
            continue
        if class_name in fi["arg_type"] and not class_name+"* *" in fi["arg_type"] and not ")(" in fi["arg_type"]:
            found = True
            tfunc_list.append(fi)
    if not found:
        return False
    else:
        return True

if not find_class(struct_type_name):
    print ("Error: No such structure type: %s\n"%struct_type_name)
    exit()

bpf_path="bpf/bpf-kern-progs"
dir_path=bpf_path
if not os.path.exists(dir_path):
    os.mkdir(dir_path)

bpf_num = 0
dir_path += "/bpf-kprogs"
while True:
    path = dir_path+"-%d"%bpf_num
    if not os.path.exists(path):
        os.mkdir(path)
        dir_path = path
        break
    else:
        bpf_num += 1

c2=0
printed=False
for i in tfunc_list:
    c2+=1
    for j in tfunc_list:
        if not i is j and i["func_name"] == j["func_name"]:
            if not printed:
                print "-------------duplicate functions (but, different addr)--------------"
                printed=True
            print i
            print j

print "==========================="
print "all_functions counts: %d"%c0
print "trace functions counts: %d"%c2
print "==========================="

def shell(cmd):
    p = subprocess.Popen(cmd ,stderr=subprocess.PIPE, shell=True)
    err_msg = p.stderr.read()
    if "err" in err_msg or "Err" in err_msg or "Permission" in err_msg or  "cannot" in err_msg:
        print "Error: %s"%err_msg
        print cmd
        return False
    return True

f__=list()
bpf_src_file=open("bpf/utils/kern/%s-bpf.c"%struct_type_name, "r")
srclines = bpf_src_file.read().split("\n")

def gen_bpf_progs(class_name, func_name, nth):
    global bpf_src_file, dir_path, idx
    lines = list()
    found = 0
    for line in srclines:
        if "CTRACER_KERNEL_FUNCTION" in line:
            line = line.replace("CTRACER_KERNEL_FUNCTION", func_name)
            found += 1
        elif "CTRACER_ARG_NTH" in line and nth <= 5:
            line = line.replace("CTRACER_ARG_NTH",  "PT_REGS_PARM%d"%nth)
            found += 1
        elif "CTRACER_MAP_NAME" in line:
            line = line.replace("CTRACER_MAP_NAME",  "%s_%s_map"%(func_name, class_name))
            found += 1

        lines.append(line+"\n")

    if not found == 4:
        return
        
    bpf_dst_file=open(dir_path+"/%s-ctracer.c"%func_name, "w")
    for line in lines:
        bpf_dst_file.write(line)
    bpf_dst_file.close()

def get_arg_nth(class_name, arg_types):
    args = arg_types.split(", ")
    nth = 1
    class_name = "struct %s"%class_name
    found = False
    for a in args:
        if not class_name in a:
            nth += 1
        else:
            found = True
    if not found:
        print "Error: get arg nth: Not found"
        exit()
    return nth

def addr2line(addr):
    k_path = "/home/taeung/git/linux/vmlinux"
    cmd = "addr2line -e %s %s"%(k_path, addr)
    line_info = os.popen(cmd).readlines()
    if not line_info or "?" in line_info[0]:
        return None
    return  line_info[0].rstrip().split("/home/taeung/git/linux/")[1]

print "\nGenerating BPF kernel programs and tfunc.json (that is a json file of trace functions info) ..."
for tf in tfunc_list:
    if option == "-s" or option == "--srcline":
        srcline = addr2line(tf["addr"])
        if srcline:
            tf["srcline"] = srcline
    gen_bpf_progs(struct_type_name, tf["func_name"], get_arg_nth(struct_type_name, tf["arg_type"]))

fd=open("tfunc.json","w")
data=json.dumps(tfunc_list)
fd.write(data)
fd.close()
print "Done"
print "Please, enter the directory: %s"%dir_path

exit()
