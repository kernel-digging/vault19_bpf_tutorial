#!/usr/bin/env python
import os, json, sys, errno
from shutil import copyfile

def help():
    print "Usage: ctracer-compile.py BPF_C_FILES_PATH\n"
    print "       ctracer-compile.py - compiles BPF C source files of the given path in ~/git/linux/smaples/bpf/\n"
    print "       BPF_C_FILES_PATH := a path of generated bpf c files by gen-BPF-cfiles.py\n"
    exit()
    
if len(sys.argv) != 2:
    print "Error: wrong arguments"
    help()

src_path = sys.argv[1]
if not os.path.exists(src_path):
    print "Error: No %s"%src_path
    exit()

build_path = "%s/git/linux/samples/bpf"%os.getenv("HOME")
if not os.path.exists(build_path):
    print "Error: No %s"%build_path
    exit()

f_list = os.listdir(build_path)
has_makefile = False
for f in f_list:
    if "Makefile" == f:
        has_makefile = True
if not has_makefile:
    print "Error: %s have not Makefile"%build_path
    exit()

m_path = "%s/Makefile"%build_path
if not os.path.exists(m_path+".old"):
    cmd = "mv %s %s.old"%(m_path, m_path)
    print cmd
    os.popen(cmd)

fd=open("tfunc.json","r")
t=fd.read()
tfunc_list=json.loads(t)


def copy_f(name):
    print "copy %s %s/"%(name, build_path)
    copyfile(name, build_path+"/"+name)

copy_f("vault19_ctracer_user.c")
copy_f("json_writer.c")
copy_f("json_writer.h")

c_list = list()
src_list = os.listdir(src_path)
for cfile in src_list:
    if "-ctracer.c" in cfile:
        for tf in tfunc_list:
            if tf["func_name"] in cfile:
                copyfile(src_path+"/"+cfile, build_path+"/"+cfile)
                c_list.append("always += %s-ctracer.o\n"%tf["func_name"])
                break

print "Rewriting %s ... "%m_path
makefile_fd = open("%s/Makefile.old"%build_path,"r")
m=makefile_fd.read().split('\n')
new_fd = open("%s/Makefile"%build_path,"w")

for line in m:
    if "always +=" in line and "_kern.o" in line and "vault19" in line:
        new_fd.write("#\n")
        new_fd.write("# ctracer: generated BPF programs(kernel)\n")
        for l in c_list:
            new_fd.write(l)
    else:
        new_fd.write(line+"\n")
new_fd.close()
makefile_fd.close()

print "Compiling BPF programs ... in %s"%build_path
output=os.popen("cd %s && make"%build_path)
for line in output:
    sys.stdout.write(line)
copyfile(build_path+"/vault19_ctracer", "vault19_ctracer")
os.popen("chmod +x vault19_ctracer")
