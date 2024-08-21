#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

typedef int u32;

// Определяем карту типа HASH
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[6]);
} my_map SEC(".maps");

// Определяем карту типа PERF_EVENT_ARRAY
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0); // Замените на количество CPU или более
} perf_map SEC(".maps");

// Структура для передачи данных в пользовательское пространство
struct data_t
{
    char message[64];
};

// Простая программа для отладки
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct pt_regs *ctx)
{
    u32 key = 0;
    char hello[] = "Hello!!!";
    struct data_t data = {};

    // Обновляем элемент карты
    bpf_map_update_elem(&my_map, &key, hello, BPF_ANY);

    // Вывод отладочной информации
    bpf_printk("Hello from BPF\n");

    // Подготовка данных для отправки
    __builtin_memcpy(data.message, hello, sizeof(hello));

    // Отправка данных в пользовательское пространство
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// Лицензия
char _license[] SEC("license") = "GPL";