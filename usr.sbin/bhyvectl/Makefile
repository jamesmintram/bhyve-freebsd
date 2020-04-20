#
# $FreeBSD$
#

PROG=	bhyvectl
PACKAGE=	bhyve

LIBADD=	vmmapi util

WARNS?=	3

CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm

.include "${.CURDIR}/${MACHINE}/Makefile.inc"
.include <bsd.prog.mk>
