#
# $FreeBSD$
#

PROG=	bhyvectl
PACKAGE=	bhyve

LIBADD=	vmmapi util

WARNS?=	3

CFLAGS+= -I${SRCTOP}/sys/amd64/vmm
MAN=	bhyvectl.8

.include "${.CURDIR}/${MACHINE}/Makefile.inc"
.include <bsd.prog.mk>
