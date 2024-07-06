#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Удаляем собственное определение макроса SEC

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
    char msg[] = "Hello, BPF World!";
    bpf_printk("%s\n", msg);
    return 0;
}

char _license[] SEC("license") = "GPL";
