#!/bin/sh

#
# Copyright (c) 2012 Peter Holm <pho@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

# core dumps seen in watchdogd after mlockall() was added.
# This scenario demonstrates the problem. Fixed in r242012.

mem=`sysctl hw.usermem | awk '{print $NF}'`

here=`pwd`
cd /tmp
sed '1,/^EOF/d' < $here/$0 > mlockall2.c
cc -o mlockall2 -Wall -Wextra -O2 -g mlockall2.c
rm -f mlockall2.c
cd $here

rm -f mlockall2.core
/tmp/mlockall2 $mem &
while kill -0 $! 2>/dev/null; do
        [ -r mlockall2.core ] && kill $! && break
        sleep 10
done
[ -r mlockall2.core ] && echo "FAIL"
killall mlockall2
rm -f /tmp/mlockall2
exit 0
EOF
#include <sys/types.h>
#include <err.h>
#include <sys/rtprio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOAD 40
#define N 90000
#define PARALLEL 5

long size;

void
swap(void)
{
	char *c;
	int page;
	long i;

	setproctitle("swap");
	c = malloc(size);
	while (c == NULL) {
		size -=  1024 * 1024;
		c = malloc(size);
	}
	page = getpagesize();
	for (;;) {
		i = 0;
		while (i < size) {
			c[i] = 0;
			i += page;
		}
	}
}

void
test(void)
{
        pid_t p;
        int i, status;

	setproctitle("test");
        for (i = 0; i < N; i++) {
                if ((p = fork()) == 0) {
			_exit(0);
		}
                if (p > 0)
                        wait(&status);
		if (status != 0)
			break;
        }
        _exit(0);
}

int
main(int argc __unused, char **argv)
{
	struct rtprio rtp;
        int i, j;

	size = atol(argv[1]) / LOAD * 1.5;
	for (i = 0; i < LOAD; i++)
		if (fork() == 0)
			swap();
	sleep(10);

	rtp.type = RTP_PRIO_REALTIME;
	rtp.prio = 0;
	if (rtprio(RTP_SET, 0, &rtp) == -1)
		err(1, "rtprio");

	if (madvise(0, 0, MADV_PROTECT) != 0)
		err(1, "madvise failed");
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		err(1, "mlockall failed");

	alarm(600);
	for (j = 0; j < 10; j++) {
		for (i = 0; i < PARALLEL; i++) {
			if (fork() == 0)
				test();
		}

		for (i = 0; i < PARALLEL; i++)
			wait(NULL);
		if (access("mlockall2.core", R_OK) == 0)
			break;
	}

        return (0);
}
