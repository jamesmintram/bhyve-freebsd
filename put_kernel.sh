#!/bin/sh

case "${1}" in
    FreeBSD)
        IMAGE="${ODIR}/sys/FVP_VE_CORTEX_A15x1_GUEST/kernel.bin"
        ;;
    Linux)
        # Unfortunately, the Linux kernel must be built on another system that
        # runs Linux, so the path is expected to be copied manually somewhere
        # in the FreeBSD filesystem
        IMAGE="/path/to/linux/Image"
        ;;
    *)
        echo "Usage: $0 <FreeBSD|Linux>"
        exit 1
esac

echo "Copying image ${IMAGE}"
cp ${IMAGE} ${RAMDISKDIR}/kernel.bin
