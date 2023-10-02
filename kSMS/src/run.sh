#!/bin/sh
RAND=$(head -n 100 /dev/urandom | sha256sum | awk '{printf $1}')
cp /opt/flag.txt /tmp/$RAND

timeout 120 qemu-system-x86_64 \
    -kernel /opt/bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 1G \
    -initrd /opt/rootfs.cpio.gz \
    -hda /tmp/$RAND \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1" \
    -monitor /dev/null \
    -nographic \
    -no-reboot

rm -f /tmp/$RAND