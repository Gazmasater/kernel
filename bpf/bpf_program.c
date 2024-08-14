#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

typedef int u32;
typedef __u64 u64;

// Определяем карту типа PERF_EVENT_ARRAY
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0); // Замените на количество CPU или более
} perf_map SEC(".maps");

struct data_t {
    u32 pid; // PID процесса
    char comm[16]; // Имя процесса
    u64 start_time; // Время начала
    u64 end_time; // Время окончания
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog_start(struct pt_regs *ctx) {
    struct data_t data = {};

    // Получаем PID и имя процесса
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(data.comm, sizeof(data.comm));

    // Записываем время начала события
    data.start_time = bpf_ktime_get_ns();

    // Отправляем данные в пользовательское пространство
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int bpf_prog_end(struct pt_regs *ctx) {
    struct data_t data = {};

    // Получаем PID и имя процесса
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(data.comm, sizeof(data.comm));

    // Записываем время окончания события
    data.end_time = bpf_ktime_get_ns();

    // Отправляем данные в пользовательское пространство
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// Лицензия для eBPF программы
char _license[] SEC("license") = "GPL";
	


	
