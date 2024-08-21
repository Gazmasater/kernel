#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h> // Для структуры task_struct

#define TASK_COMM_LEN 16

typedef int u32;

// Определяем карту типа PERF_EVENT_ARRAY для передачи данных в пространство пользователя
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
} perf_map SEC(".maps");

// Структура для передачи данных в пространство пользователя
struct data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // TASK_COMM_LEN определено как 16 символов
};

// Простая программа для отладки
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct pt_regs *ctx)
{
    struct data_t data = {};

    // Получаем PID текущего процесса
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // Получаем имя процесса (comm) и сохраняем в структуре data
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Отправляем данные в пространство пользователя
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// Лицензия
char _license[] SEC("license") = "GPL";
