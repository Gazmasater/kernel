Должно быть установлено

clang --version

llvm-config --version

pkg-config --modversion libelf

bpftool --version



sudo sysctl -a | grep kernel.unprivileged_bpf_disabled 

должны увидеть:

kernel.unprivileged_bpf_disabled = 0

Поменять на 0 kernel.unprivileged_bpf_disabled

sudo nano /etc/sysctl.conf

Проверка прав

ls -ld /sys/fs/bpf

Если не соответствует, то

sudo chmod 755 /sys/fs/bpf

Убедитесь, что файловая система bpf смонтирована:

mount | grep bpf

Если файловая система bpf не смонтирована, попробуйте смонтировать её:

sudo mount -t bpf bpf /sys/fs/bpf

Проверьте права доступа к блокировке памяти:

ulimit -l



