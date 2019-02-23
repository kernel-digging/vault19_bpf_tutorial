This prequel ctracer is a temporary version.
FYI, original 'ctracer' https://git.kernel.org/pub/scm/devel/pahole/pahole.git/tree/README.ctracer

### Installation:
```
$ sudo apt-get install dwarves
```

### Usages:
```
# collecting kernel function debug info from 'vmlinux'
# and build 'vmlinux.debuginfo/kfunc.json'
$ ./setup.py vmlinux

# generate BPF programs(kernel) based on 'struct bio' using bpf/utils/kern/*.c
# with functions that have the struct type parameters
$ ./gen-BPF-cfiles.py bio

# check generated BPF c files
$ ls bpf/bpf-kern-progs/bpf-kprogs-0/

# compile generated BPF c files in ~/git/linux/samples/bpf/
$ ./ctracer-compile.py bpf/bpf-kern-progs/bpf-kprogs-0/

# load and pin the BPF programs to /sys/fs/bpf/
$ sudo ./ctracer-load.py ~/git/linux/samples/bpf

# Data + Function tracing:
# Collect all 'struct bio' data with call trace of functions that has its parameters
$ sudo ./vault19_ctracer

Stop by 'Ctrl + c'

# check recorded ctracer data: ftrace.data and ctracer.json
$ ls /tmp

# build ftrace.data.arg and ctracer.json.srcline with arg type / srcline info
$ ./ctracer-finish.py

$ scp /tmp/ftrace.data.arg <username>@<ip>:<path>
$ scp /tmp/ctracer.json <username>@<ip>:<path>
or
$ scp /tmp/ctracer.json.srcline <username>@<ip>:<path>

# And then open bctracer web app and upload them

```