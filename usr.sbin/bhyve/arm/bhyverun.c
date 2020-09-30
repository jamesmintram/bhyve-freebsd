/*
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "../mmio/mmio_emul.h"
#include "../mmio/mmio_irq.h"
#include "mem.h"
#include "mevent.h"
#include "reset.h"

#define	GUEST_NIO_PORT	0x488	/* guest upcalls via i/o port */

#define	VMEXIT_SWITCH	0	/* force vcpu switch in mux mode */
#define	VMEXIT_CONTINUE	1	/* continue from next instruction */
#define	VMEXIT_RESTART	2	/* restart current instruction */
#define	VMEXIT_ABORT	3	/* abort the vm run loop */
#define	VMEXIT_RESET	4	/* guest machine has reset */

#define	MB		(1024UL * 1024)
#define	GB		(1024UL * MB)

typedef int (*vmexit_handler_t)(struct vmctx *, struct vm_exit *, int *vcpu);

char *vmname;

int guest_ncpus;

int raw_stdio = 0;

static int pincpu = -1;

static int foundcpus;

static char *progname;
static const int BSP = 0;

static int cpumask;

static void vm_loop(struct vmctx *ctx, int vcpu, uint64_t pc);

struct vm_exit vmexit[VM_MAXCPU];

struct bhyvestats {
        uint64_t        vmexit_bogus;
        uint64_t        vmexit_inst_emul;
} stats;

struct mt_vmm_info {
	pthread_t	mt_thr;
	struct vmctx	*mt_ctx;
	int		mt_vcpu;
} mt_vmm_info[VM_MAXCPU];

static void
usage(int code)
{

        fprintf(stderr,
                "Usage: %s [-b] [-c vcpus][-p pincpu][-s <devemu>]"
		" <vmname>\n"
		"       -b: use bvmconsole\n"
		"       -c: # cpus (default 1)\n"
		"       -p: pin vcpu 'n' to host cpu 'pincpu + n'\n"
		"       -s: device emulation config\n"
		"       -h: help\n",
		progname);

	exit(code);
}

void *
paddr_guest2host(struct vmctx *ctx, uintptr_t gaddr, size_t len)
{

	return (vm_map_gpa(ctx, gaddr, len));
}


int
fbsdrun_virtio_msix(void)
{

	return 0;
}

static void *
fbsdrun_start_thread(void *param)
{
	char tname[MAXCOMLEN + 1];
	struct mt_vmm_info *mtp;
	int vcpu;

	mtp = param;
	vcpu = mtp->mt_vcpu;

	snprintf(tname, sizeof(tname), "%s vcpu %d", vmname, vcpu);
	pthread_set_name_np(mtp->mt_thr, tname);

	vm_loop(mtp->mt_ctx, vcpu, vmexit[vcpu].pc);

	/* not reached */
	exit(1);
	return (NULL);
}

void
fbsdrun_addcpu(struct vmctx *ctx, int vcpu, uint64_t pc)
{
	int error;

	if (cpumask & (1 << vcpu)) {
		fprintf(stderr, "addcpu: attempting to add existing cpu %d\n",
		    vcpu);
		exit(1);
	}

	cpumask |= 1 << vcpu;
	foundcpus++;

	/*
	 * Set up the vmexit struct to allow execution to start
	 * at the given RIP
	 */
	vmexit[vcpu].pc = pc;
	vmexit[vcpu].inst_length = 0;

	if (vcpu == BSP) {
		mt_vmm_info[vcpu].mt_ctx = ctx;
		mt_vmm_info[vcpu].mt_vcpu = vcpu;

		error = pthread_create(&mt_vmm_info[vcpu].mt_thr, NULL,
				fbsdrun_start_thread, &mt_vmm_info[vcpu]);
		assert(error == 0);
	}
}

static int
fbsdrun_get_next_cpu(int curcpu)
{

	/*
	 * Get the next available CPU. Assumes they arrive
	 * in ascending order with no gaps.
	 */
	return ((curcpu + 1) % foundcpus);
}

static int
vmexit_hyp(struct vmctx *ctx, struct vm_exit *vmexit, int *pvcpu)
{

	fprintf(stderr, "vm exit[%d]\n", *pvcpu);
	fprintf(stderr, "\treason\t\tHYP\n");
	fprintf(stderr, "\tpc\t\t0x%016llx\n", vmexit->pc);
	fprintf(stderr, "\tinst_length\t%d\n", vmexit->inst_length);

	return (VMEXIT_ABORT);
}

static int
vmexit_bogus(struct vmctx *ctx, struct vm_exit *vmexit, int *pvcpu)
{

	stats.vmexit_bogus++;

	return (VMEXIT_RESTART);
}

static int
vmexit_inst_emul(struct vmctx *ctx, struct vm_exit *vmexit, int *pvcpu)
{
	int err;
	struct vie *vie;

	stats.vmexit_inst_emul++;

	vie = &vmexit->u.inst_emul.vie;
	err = emulate_mem(ctx, *pvcpu, vmexit->u.inst_emul.gpa, vie);

	if (err) {
		if (err == ESRCH) {
			fprintf(stderr, "Unhandled memory access to 0x%llx\n",
			    vmexit->u.inst_emul.gpa);
		}

		if (err == RESET_MAGIC)
			return (VMEXIT_RESET);

		fprintf(stderr, "Failed to emulate instruction at 0x%llx\n",
			vmexit->pc);
		return (VMEXIT_ABORT);
	}
	return (VMEXIT_CONTINUE);
}


static vmexit_handler_t handler[VM_EXITCODE_MAX] = {
	[VM_EXITCODE_HYP]    = vmexit_hyp,
	[VM_EXITCODE_BOGUS]  = vmexit_bogus,
	[VM_EXITCODE_INST_EMUL] = vmexit_inst_emul,
};

static void
vm_loop(struct vmctx *ctx, int vcpu, uint64_t pc)
{
	cpuset_t mask;
	int error, rc, prevcpu;
	enum vm_exitcode exitcode;

	if (pincpu >= 0) {
		CPU_ZERO(&mask);
		CPU_SET(pincpu + vcpu, &mask);
		error = pthread_setaffinity_np(pthread_self(),
					       sizeof(mask), &mask);
		assert(error == 0);
	}
	while (1) {

		error = vm_run(ctx, vcpu, pc, &vmexit[vcpu]);

		if (error != 0) {
			/*
			 * It is possible that 'vmmctl' or some other process
			 * has transitioned the vcpu to CANNOT_RUN state right
			 * before we tried to transition it to RUNNING.
			 *
			 * This is expected to be temporary so just retry.
			 */
			if (errno == EBUSY)
				continue;
			else
				break;
		}

		prevcpu = vcpu;

		exitcode = vmexit[vcpu].exitcode;
		if (exitcode >= VM_EXITCODE_MAX || handler[exitcode] == NULL) {
			fprintf(stderr, "vm_loop: unexpected exitcode 0x%x\n",
			    exitcode);
			exit(1);
		}

                rc = (*handler[exitcode])(ctx, &vmexit[vcpu], &vcpu);

		switch (rc) {
		case VMEXIT_CONTINUE:
                        pc = vmexit[vcpu].pc + vmexit[vcpu].inst_length;
			break;
		case VMEXIT_RESTART:
                        pc = vmexit[vcpu].pc;
			break;
		case VMEXIT_RESET:
			exit(0);
		default:
			exit(1);
		}
	}
	fprintf(stderr, "vm_run error %d, errno %d\n", error, errno);
}

static int
num_vcpus_allowed(struct vmctx *ctx)
{
	/* Max one VCPU */
	return (1);
}

int
main(int argc, char *argv[])
{
	int c, error, bvmcons;
	int max_vcpus;
	struct vmctx *ctx;
	uint64_t pc;
	uint64_t memory_base_address, mem_size;

	mem_size = 128 * MB;
	memory_base_address = 0xc0000000;

	bvmcons = 0;
	progname = basename(argv[0]);
	guest_ncpus = 1;

	while ((c = getopt(argc, argv, "abehAB:HIPp:g:c:s:S:")) != -1) {
		switch (c) {
		case 'b':
			bvmcons = 1;
			break;
		case 'p':
			pincpu = atoi(optarg);
			break;
                case 'c':
			guest_ncpus = atoi(optarg);
			break;
		case 's':
			if (mmio_parse_opts(optarg) != 0)
				exit(1);
			break;
		case 'B':
			memory_base_address = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(1);

	vmname = argv[0];

	ctx = vm_open(vmname);
	if (ctx == NULL) {
		perror("vm_open");
		exit(1);
	}

	max_vcpus = num_vcpus_allowed(ctx);
	if (guest_ncpus > max_vcpus) {
		fprintf(stderr, "%d vCPUs requested but only %d available\n",
			guest_ncpus, max_vcpus);
		exit(1);
	}

	error = vm_setup_memory(ctx, memory_base_address, mem_size, VM_MMAP_ALL);
	if (error != 0) {
		fprintf(stderr, "Unable to setup memory (%d)\n", error);
		exit(1);
	}

	init_mem();
	mmio_irq_init(ctx);

	if (init_mmio(ctx) != 0) {
		fprintf(stderr, "Failed to initialize device emulation\n");
		exit(1);
	}

	if (bvmcons)
		init_bvmcons();

	init_reset();

	error = vm_get_register(ctx, BSP, VM_REG_GUEST_PC, &pc);
	assert(error == 0);
	/*
	 * Add CPU 0
	 */
	fbsdrun_addcpu(ctx, BSP, pc);

	/*
	 * Head off to the main event dispatch loop
	 */
	mevent_dispatch();

	exit(1);
}
