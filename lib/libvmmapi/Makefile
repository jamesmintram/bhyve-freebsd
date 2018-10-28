# $FreeBSD$

PACKAGE=	lib${LIB}
LIB= 		vmmapi

LIB_SRCTOP?= 	${.CURDIR}
.if exists(${LIB_SRCTOP}/${MACHINE})
LIB_ARCH= 	${MACHINE}
.elif exists(${LIB_SRCTOP}/${MACHINE_ARCH})
LIB_ARCH= 	${MACHINE_ARCH}
.else
LIB_ARCH= 	${MACHINE_CPUARCH}
.endif

CFLAGS+= 	-I${LIB_SRCTOP} -I${LIB_SRCTOP}/${LIB_ARCH}
WARNS?= 	2

SRCS= 		vmmapi.c
INCS= 		vmmapi.h

LIBADD=		util

.include "${LIB_SRCTOP}/${LIB_ARCH}/Makefile.inc"
.include <bsd.lib.mk>
