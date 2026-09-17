#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

int load_bpf_program(const char *license,
                     void *prog,
                     unsigned int prog_size)
{
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SCHED_CLS,
        .insn_cnt  = prog_size,
        .insns     = (uint64_t)prog,
        .license   = (uint64_t)license,
    };
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    return prog_fd;
}
