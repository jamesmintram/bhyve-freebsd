#!/bin/sh

set -e

trap 'cd ${OLDDIR}' INT HUP TERM

# Update this to the name of the directory where you work
# It is expected that the 'freebsd' (this) repository and the 'projects/bhyvearm' repositories are there
# By default it is set to two levels above the location of rebuild.sh script
SCRIPTNAME=`readlink -f ${0}`
export WORKDIR=${SCRIPTNAME%/*/*}
export SRCDIR=${WORKDIR}/freebsd

export UTILSDIR=${WORKDIR}/bhyvearm-utils
export BOOTWRAPPERDIR=${UTILSDIR}/boot-wrapper
export RAMDISKDIR=${UTILSDIR}/ramdisk
MAKEFILE=${SRCDIR}/Makefile
OLDDIR=`pwd`
DEFINES=""

export TARGET=arm
export TARGET_ARCH=armv6
export PLATFORM=${PLATFORM:-FVP_VE_CORTEX_A15x1}
export MAKEOBJDIRPREFIX=${WORKDIR}/freebsd-obj
export ODIR=${ODIR:-${MAKEOBJDIRPREFIX}/${SRCDIR}/${TARGET}.${TARGET_ARCH}}


usage() {
    eval 1>&2
    printf  "$0 [-aghlwAGHLW]\n"
    printf "[Re]build a certain component for virtual machine testing\n"
    printf "Options in uppercase have the same meaning as those in lowercase"
    printf " but will clean working directory first (i.e., -DNO_CLEAN or -DKERNFAST"
    printf " will not be passed when running 'make')\n"
    printf "\n"
    printf "\t-a        Rebuild 'all' - equivalent to -w -g -h\n"
    printf "\t-A        Rebuild 'all' but clean guest and host kernel image work"
    printf " directories before building - equivalent to -w -G -H\n"
    printf "\n"
    printf "\t-g        Rebuild FreeBSD guest kernel image\n"
    printf "\n"
    printf "\t-h        Rebuild host kernel image with FreeBSD guest kernel image\n"
    printf "\n"
    printf "\t-l        Equivalent to -h, but use a Linux kernel image in stead of"
    printf " a FreeBSD kernel image\n"
    printf "\n"
    printf "\t-w        Rebuild userspace applications\n"
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



cd ${SRCDIR}

if [ $# -lt 1 ]; then usage; fi

date

if [ ! -d ${UTILSDIR} ]; then
    echo "The bhyvearm-utils directory does not exist. Cloning it..."
    git clone https://github.com/FreeBSD-UPB/bhyvearm-utils ${UTILSDIR}
fi

if [ ! -f ${BOOTWRAPPERDIR}/linux-system-semi.axf ]; then
    echo "${BOOTWRAPPERDIR}/linux-system-semi.axf does not exist. Building it..."
    (cd ${BOOTWRAPPERDIR}; ./build_freebsd.sh)
fi

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
