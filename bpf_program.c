#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>


typedef int u32;

// Определяем карту (map) типа HASH с одним элементом
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[6]); // Строка "Hello" длиной 5 символов + 1 символ для null-терминатора
} my_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct pt_regs *ctx)
{
    u32 key = 0; // Ключ для доступа к значению в карте
    char hello[] = "Hello"; // Строка для хранения в карте

    // Вставляем строку "Hello" в карту
    bpf_map_update_elem(&my_map, &key, hello, BPF_ANY);

    // Получаем значение из карты по ключу
    char *map_value = bpf_map_lookup_elem(&my_map, &key);
    if (map_value) {
        bpf_printk("%s, BPF World!\n", map_value); // Выводим значение из карты
    }

    return 0;
}

// Лицензия для eBPF программы
char _license[] SEC("license") = "GPL";

