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

.if exists(${BHYVE_SRCTOP}/${MACHINE_ARCH})
BHYVE_ARCH=	${MACHINE_ARCH}
.else
BHYVE_ARCH=	${MACHINE_CPUARCH}
.endif

.include "${BHYVE_SRCTOP}/${BHYVE_ARCH}/Makefile.inc"
LIBADD+=	vmmapi md pthread

WARNS?=	2

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/virtio/console

.include <bsd.prog.mk>
