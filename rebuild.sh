#!/usr/local/bin/bash

set -e

trap 'cd ${OLDDIR}' INT HUP TERM


export BASEDIR="/root/freebsd/"
export RAMDISKDIR="/root/bhyvearm-utils/ramdisk/"
MAKEFILE="${BASEDIR}/Makefile"
OLDDIR=`pwd`
DEFINES=""

export TARGET=arm
export TARGET_ARCH=armv6
export PLATFORM=${PLATFORM:-FVP_VE_CORTEX_A15x1}
export MAKEOBJDIRPREFIX=/root/freebsd-obj/
export ODIR=${ODIR:-${MAKEOBJDIRPREFIX}/${BASEDIR}/${TARGET}.${TARGET_ARCH}/}


usage() {
    eval 1>&2
    echo -ne  "$0 [-aghlwAGHLW]\n"
    echo -ne "[Re]build a certain component for virtual machine testing\n"
    echo -ne "Options in uppercase have the same meaning as those in lowercase"
    echo -ne " but will clean working directory first (i.e., -DNO_CLEAN or -DKERNFAST"
    echo -ne " will not be passed when running 'make')\n"
    echo -ne "\n"
    echo -ne "\t-a        Rebuild 'all' - equivalent to -w -g -h\n"
    echo -ne "\t-A        Rebuild 'all' but clean guest and host kernel image work"
    echo -ne " directories before building - equivalent to -w -G -H\n"
    echo -ne "\n"
    echo -ne "\t-g        Rebuild FreeBSD guest kernel image\n"
    echo -ne "\n"
    echo -ne "\t-h        Rebuild host kernel image with FreeBSD guest kernel image\n"
    echo -ne "\n"
    echo -ne "\t-l        Equivalent to -h, but use a Linux kernel image in stead of"
    echo -ne " a FreeBSD kernel image\n"
    echo -ne "\n"
    echo -ne "\t-w        Rebuild userspace applications\n"
    exit 0
}

build_guest() {
    (cd ${RAMDISKDIR} && bash build_ramdisk.sh Guest)
    make -f ${MAKEFILE} buildkernel ${1} KERNCONF=FVP_VE_CORTEX_A15x1_GUEST -j9
} > guest.out

build_host() {
    ./put_kernel.sh ${1}
    make -f ${MAKEFILE} buildkernel ${2} KERNCONF=${PLATFORM} -j9
    (cd ${RAMDISKDIR} && bash build_ramdisk.sh Host)
    make -f ${MAKEFILE} buildkernel -DKERNFAST KERNCONF=${PLATFORM} -j9
} > host.out

build_world() {
    make -f ${MAKEFILE} buildworld ${1} -j9
} > world.out



cd ${BASEDIR}

if [ $# -lt 1 ]; then usage; fi

date

while getopts "aghlwAGHLW" opt; do
    case "${opt}" in
        a) SUB_BUILD="-wgh" ;& # fallthrough
        A)
            echo "Building everything"
            echo "Host platform will be ${PLATFORM}"
            $0 ${SUB_BUILD:-"-wGH"}
            ;;
        g) DEFINES="-DKERNFAST" ;& # fallthrough
        G)
            echo "Building ${opt}uest..."
            build_guest ${DEFINES}
            ;;
        h) DEFINES="-DKERNFAST" ;& # fallthrough
        H)
            echo "Building ${opt}ost with FreeBSD guest image..."
            build_host FreeBSD ${DEFINES}
            ;;
        l) DEFINES="-DKERNFAST" ;& # fallthrough
        L)
            echo "Building host with ${opt}inux kernel..."
            build_host Linux ${DEFINES}
            ;;
        w) DEFINES="-DNO_CLEAN" ;& # fallthrough
        W)
            echo "Building ${opt}orld..."
            build_world ${DEFINES}
            ;;
        *)
            usage
            ;;
    esac
done
