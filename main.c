
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/ucontext.h>

#include "syscall.h"
#include "util.h"

extern void init(void);

static void sighnd(int sig, siginfo_t *info, void *ctx) {
	ucontext_t *uc = (ucontext_t *) ctx;
	greg_t *regs = uc->uc_mcontext.gregs;

	uint8_t *ins = (uint8_t *)regs[REG_RIP];
	if (ins[0] != 0xCD) {
		abort();
	}
	uint8_t *next = &ins[2];
	unsigned long rax = regs[REG_RAX];
	if (rax != os_syscall_nr_print) {
		abort();
	} 
	char* str = regs[REG_RBX];
	unsigned long len = regs[REG_RCX];
	sys_print(str, len);
	regs[REG_RIP] = (unsigned long) next;
}

int main(int argc, char *argv[]) {
	struct sigaction act = {
		.sa_sigaction = sighnd,
		.sa_flags = SA_RESTART,
	};
	sigemptyset(&act.sa_mask);

	if (-1 == sigaction(SIGSEGV, &act, NULL)) {
		perror("signal set failed");
		return 1;
	}

	init();
	return 0;
}
