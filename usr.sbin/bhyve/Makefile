#
# $FreeBSD$
#

.include <src.opts.mk>
CFLAGS+=-I${SRCTOP}/sys
.PATH:  ${SRCTOP}/sys/cam/ctl

PROG=	bhyve
PACKAGE=	bhyve

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

LIBADD=	vmmapi md pthread

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+=-DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif
.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
.endif

.if exists(${BHYVE_SRCTOP}/${MACHINE})
BHYVE_ARCH=	${MACHINE}
.elif exists(${BHYVE_SRCTOP}/${MACHINE_ARCH})
BHYVE_ARCH=	${MACHINE_ARCH}
.else
BHYVE_ARCH=	${MACHINE_CPUARCH}
.endif

.PATH:	${BHYVE_SYSDIR}/sys/${BHYVE_ARCH}/vmm
SRCS+=	vmm_instruction_emul.c

.include "${BHYVE_SRCTOP}/${BHYVE_ARCH}/Makefile.inc"
.include "${BHYVE_SRCTOP}/${BHYVE_BUS}/Makefile.inc"

CFLAGS+=	-I${BHYVE_SRCTOP}
CFLAGS+=	-I${BHYVE_SRCTOP}/${BHYVE_ARCH}
CFLAGS+= 	-I${BHYVE_SYSDIR}/sys/dev/virtio
CFLAGS+= 	-I${BHYVE_SYSDIR}/sys/dev/virtio/console

.ifdef GDB_LOG
CFLAGS+=-DGDB_LOG
.endif

WARNS?=	2

.include <bsd.prog.mk>
