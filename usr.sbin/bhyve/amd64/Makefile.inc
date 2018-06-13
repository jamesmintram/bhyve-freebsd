#
# $FreeBSD$
#
.PATH: ${BHYVE_SRCTOP}/amd64/

MAN=	bhyve.8

SRCS+=	\
	atkbdc.c		\
	acpi.c			\
	bhyvegc.c		\
	bhyverun.c		\
	bootrom.c		\
	console.c		\
	consport.c		\
	dbgport.c		\
	fwctl.c			\
	gdb.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mptbl.c			\
	pm.c			\
	post.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	task_switch.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	vga.c			\
	xmsr.c			\
	spinup_ap.c

LIBADD+=	z

CFLAGS+=	-I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+=	-I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+=	-I${BHYVE_SYSDIR}/sys/dev/usb/controller

BHYVE_BUS=	pci
