#!/bin/bash

rm -rf bpf/bpf-kern-progs/
rm -rf vmlinux.debuginfo/
rm -f ftrace.data.arg
rm -f tfunc.json
rm -f vault19_ctracer
rm -f ctracer.json
mv ~/git/linux/samples/bpf/Makefile.old ~/git/linux/samples/bpf/Makefile
rm -f ~/git/linux/samples/bpf/*-ctracer.*
