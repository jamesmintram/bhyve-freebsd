# $FreeBSD$

KMOD=	vmm

SRCS=	opt_acpi.h opt_ddb.h device_if.h bus_if.h pci_if.h

CFLAGS+= -DVMM_KEEP_STATS -DSMP

.include <bsd.arch.inc.mk>

.include <bsd.kmod.mk>
