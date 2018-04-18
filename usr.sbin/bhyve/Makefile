#
# $FreeBSD$
#

.include <src.opts.mk>

PROG=	bhyve
PACKAGE=	bhyve

DEBUG_FLAGS= -g -O0

MAN=	bhyve.8

BHYVE_SYSDIR?=${SRCTOP}
BHYVE_SRCTOP?=${.CURDIR}

SRCS=	\
	block_if.c		\
	devemu_virtio_block.c	\
	devemu_virtio_console.c	\
	devemu_virtio_net.c	\
	devemu_virtio_rnd.c	\
	mevent.c		\
	sockstream.c

.if exists(${BHYVE_SRCTOP}/${MACHINE_ARCH})
BHYVE_ARCH=	${MACHINE_ARCH}
.else
BHYVE_ARCH=	${MACHINE_CPUARCH}
.endif

.PATH:	${BHYVE_SYSDIR}/sys/${BHYVE_ARCH}/vmm
SRCS+=	vmm_instruction_emul.c

.include "${BHYVE_SRCTOP}/${BHYVE_ARCH}/Makefile.inc"
.include "${BHYVE_SRCTOP}/${BHYVE_BUS}/Makefile.inc"

CFLAGS+=	-I${BHYVE_SRCTOP}
CFLAGS+= 	-I${BHYVE_SYSDIR}/sys/dev/virtio
CFLAGS+= 	-I${BHYVE_SYSDIR}/sys/dev/virtio/console

LIBADD+=	vmmapi md pthread

WARNS?=	2

.include <bsd.prog.mk>
