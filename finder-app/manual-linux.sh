#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u


OUTDIR=/tmp/aeld

KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
O=out

let CORESNUM=$(nproc)-1

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

ROOTFS=$OUTDIR/rootfs

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cp ${FINDER_APP_DIR}/manual-linux.patch ${OUTDIR}/linux-stable
    cd linux-stable

    # this patch needed for gcc version 10+, 
    # on ubuntu 20.04 gcc version is 9.3, 
    # but i`m use archlinux on my host machine
    patch -p1 -Nb -r /dev/null < ./manual-linux.patch || true

    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}
    rm -rf $O
    mkdir $O

    make CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH} O=${O} -j${CORESNUM} defconfig
    make CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH} O=${O} -j${CORESNUM} 
    echo "kernel compiled"

fi

echo ${OUTDIR}
echo ${ROOTFS}

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/${O}/arch/${ARCH}/boot/Image ${OUTDIR}/

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

if [ ! -d ${ROOTFS} ]
then
    mkdir ${ROOTFS}
    cd ${ROOTFS}
    mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr/{bin,sbin} var/log
fi

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}

    rm -rf $O
    mkdir $O

    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j${CORESNUM} distclean
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j${CORESNUM} defconfig

else
    cd busybox
fi

make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j${CORESNUM}
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} CONFIG_PREFIX=${ROOTFS} -j${CORESNUM} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${ROOTFS}/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${ROOTFS}/bin/busybox | grep "Shared library"

GCC_SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)

cp ${GCC_SYSROOT}/lib/ld-linux-aarch64.so.1 ${ROOTFS}/lib/ 
cp -L ${GCC_SYSROOT}/lib/ld-linux-aarch64.so.1 ${ROOTFS}/lib64/
cp -L ${GCC_SYSROOT}/lib64/libm.so.6  ${ROOTFS}/lib64/
cp -L ${GCC_SYSROOT}/lib64/libresolv.so.2 ${ROOTFS}/lib64/
cp -L ${GCC_SYSROOT}/lib64/libc.so.6 ${ROOTFS}/lib64/

sudo mknod -m 666 ${ROOTFS}/dev/null c 1 3 || true
sudo mknod -m 600 ${ROOTFS}/dev/console c 5 1 || true

cd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=${CROSS_COMPILE}

cp -r {writer,finder.sh,finder-test.sh,autorun-qemu.sh} ${ROOTFS}/home/
mkdir -p ${ROOTFS}/home/conf
cp conf/* ${ROOTFS}/home/conf/
sudo chmod 755 ${ROOTFS}/home/{writer,finder.sh,finder-test.sh,autorun-qemu.sh}

cd ${ROOTFS}
rm -rf ../initramfs.cpio*
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ../initramfs.cpio