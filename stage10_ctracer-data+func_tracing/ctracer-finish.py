#!/usr/bin/env python
import os, json, sys, errno
from shutil import copyfile

if len(sys.argv) != 1:
    print "Error"
    exit()

t_path = "tfunc.json"
if not os.path.exists(t_path):
    print "Error: No %s"%t_path
    exit()


fd=open(t_path,"r")
t=fd.read()
tfunc_list=json.loads(t)

print "Writing 'ftrace.data.arg' based on 'ftrace.data' including arguemnt type info ..."

try:
    trace_data = open("/tmp/ftrace.data", "r")
    new_arg_data = open("ftrace.data.arg", "w")
except IOError as e:
    print "Error: cannot open files\n"
    help()

trace = trace_data.read().split("\n")
for t  in trace:
    tmp=t.split()
    for i in tmp:
        skip = False
        if "()" in i:
            func_name = i.split("()")[0].split(".part.")[0]
            for tf in tfunc_list:
                if tf['func_name'] == func_name:
                     t = t.replace("()", tf["arg_type"])
                     break
    new_arg_data.write(t+"\n")
new_arg_data.close()
trace_data.close()

print "Done: ftrace.data.arg"
print "Writing 'ctracer.json' that class data tracking info including 'srcline' info"
fd=open("/tmp/ctracer.json","r")
c=fd.read()
cdata=json.loads(c)
if not cdata.has_key("srcline"):
    print "Done: ctracer.json (no srcline)"
    copyfile("/tmp/ctracer.json","ctracer.json")
    exit()
srclines = cdata["srcline"]
k_list = srclines.keys()

for k in k_list:
    for tf in tfunc_list:
        if not tf.has_key("srcline"):
            print "Done: ctracer.json (no srcline)"
            copyfile("/tmp/ctracer.json","ctracer.json")
            exit()
        if k == tf["func_name"]:
            srclines[k] = tf["srcline"]

fd.close()
fd=open("ctracer.json.srcline","w")
data=json.dumps(cdata)
fd.write(data)
fd.close()

print "Done: ctracer.json.srcline"

