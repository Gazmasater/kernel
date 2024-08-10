BPFTOOL=bpftool
CLANG=clang
LLVM_STRIP=llvm-strip
BPF_FLAGS= -target bpf -O2

TARGET=bpf_program.o

SRC=bpf_program.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CLANG) $(BPF_FLAGS) -c $(SRC) -o $(TARGET)

The clean:
	rm -f $(TARGET)