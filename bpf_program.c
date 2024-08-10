#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Удаляем собственное определение макроса SEC

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
    
    bpf_printk("Hello, BPF World!\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
