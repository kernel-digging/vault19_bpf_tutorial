#!/usr/bin/env python
import os, json, sys, errno

def help():
    print "Usage: setup.py [options] KERNEL_IMG_FILE_PATH\n"
    print "       setup.py - create 'vmlinux.debuginfo/kfunc.json' that contains kernel function debug info\n"
    print "       KERNEL_IMG_FILE_PATH := 'vmlinux' file that contains debug info\n"
    print "Options:\n"
    print "        -f, --force        force to overwrite 'vmlinux.debuginfo/kfunc.json'" 
    exit()

argc =  len(sys.argv)
if argc > 3 or argc < 2:
    print "Error: wrong arguments\n"
    help()

k_path=""
option=None
if argc == 3:
    option = sys.argv[1]
    k_path = sys.argv[2]
else:
    k_path = sys.argv[1]

if not os.path.exists(k_path):
    print ("Error: No such path: %s\n"%k_path)
    help()
if not os.path.exists("vmlinux.debuginfo"):
    os.mkdir("vmlinux.debuginfo")
elif os.path.exists("vmlinux.debuginfo/kfunc.json"):
    if option == "-f" or option == "--force":
        pass
    else:
        print "Error: 'vmlinux.debuginfo/kfunc.json' exists"
        help()

def addr2line(addr):
    cmd = "addr2line -e %s %s"%(k_path, addr)
    line_info = os.popen(cmd).readlines()
    if not line_info or "?" in line_info[0]:
        return None

    line_info = line_info[0].split(":")
    return {"file_name":line_info[0], "line_num":line_info[1]}

def arg_type(l):
    tmp = l.split()
    for i in tmp:
        if "(" in i:
            func_name = i.split("(")[0]
            argtype = l.split(func_name+"(")[1]
            argtype = "("+ argtype.rstrip()[:-1]
            return func_name, argtype

pfunct_list=list()

def set_pfunct_list(obj_dir):
    print "Getting function prototypes ... from %s"%obj_dir
    l = os.popen("find %s -name '*.o'"%obj_dir).readlines()
    for obj in l:
        cmd = "pfunct -P %s | grep -v inline "%obj.rstrip()
        p_list = os.popen(cmd).readlines()
        if not p_list:
            continue
        for p in p_list:
            f, a = arg_type(p)
            if a == "(void)":
                continue
            for fi in func_debug_info:
                if f == fi["func_name"]:
                    fi["func_name"] = f
                    if not fi["arg_type"]:
                        fi["arg_type"] = a
                        break
                    elif fi["arg_type"] != a:
                        break
                        print "Error: difference arg type--------------"
                        print a
                        print fi
                        print "----------------------------------------"

# this is vmlinux.debuginfo/kfunc.json
func_debug_info=list()

print "Reading symbols ... from %s"%k_path
func_list=list()
cmd = "nm %s | grep -e ' t \| T ' "%k_path
symbol_info = os.popen(cmd).readlines()
for si in symbol_info:
    si = si.split()
    func_name = si[2]
    if "trace_" in func_name:
        continue
    fi = {"func_name":func_name, "addr":si[0], "arg_type": None}
    func_debug_info.append(fi)

root_path=""
for fi in func_debug_info:
    if fi["func_name"] == "schedule":
        addr = fi["addr"]
        root_path = addr2line(addr)["file_name"].split("/")[:-3][1:]
        root_path = "/" + "/".join(root_path)

root_path=root_path.replace("taeung", "kosslab")
set_pfunct_list(root_path + "/kernel")
set_pfunct_list(root_path + "/mm")
set_pfunct_list(root_path + "/fs")
set_pfunct_list(root_path + "/block")
set_pfunct_list(root_path + "/drivers")

print "Remove functions that don't contain arguments ..."
kfunc_info=list()
for fi in func_debug_info:
    if fi["arg_type"]:
        kfunc_info.append(fi)

#print "Setting addr2line ..."
#for kf in kfunc_info:
#    a = addr2line(addr)
#    if a:
#        kf.update(a)
#for kf in kfunc_info:
#    print kf

fd=open("vmlinux.debuginfo/kfunc.json","w")
data=json.dumps(kfunc_info)
fd.write(data)
fd.close()
print "Kernel functions debug info: vmlinux.debuginfo/kfunc.json "
