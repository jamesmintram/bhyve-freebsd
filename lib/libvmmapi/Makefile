# $FreeBSD$

PACKAGE=lib${LIB}
LIB=	vmmapi
SRCS=	vmmapi.c
INCS=	vmmapi.h

WARNS?=	2

LIBADD=	util

CFLAGS+= -I${.CURDIR} -I${.CURDIR}/${MACHINE}

.include "${MACHINE}/Makefile.inc"
.include <bsd.lib.mk>
