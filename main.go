package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func main() {
	// Загружаем BPF программу из файла
	obj, err := ebpf.LoadCollection("bpf/bpf_program.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF collection: %v", err)
	}
	defer obj.Close()

	// Получаем указатель на программу
	prog, ok := obj.Programs["bpf_prog"]
	if !ok {
		log.Fatalf("program bpf_prog not found")
	}

	// Прикрепляем программу к tracepoint
	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("failed to attach program to tracepoint: %v", err)
	}
	defer tracepoint.Close()

	// Получаем карту perf_map
	perfMap, ok := obj.Maps["perf_map"]
	if !ok {
		log.Fatalf("perf_map not found")
	}

	// Создаем новый perf буфер для чтения событий
	reader, err := perf.NewReader(perfMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer reader.Close()

	// Обработка сигналов для завершения программы
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Listening for events...")

	go func() {
		for {
			// Читаем события из perf буфера
			record, err := reader.Read()
			if err != nil {
				log.Printf("failed to read event: %v", err)
				continue
			}

			// Обрабатываем событие
			var data struct {
				PID  uint32
				Comm [16]byte
			}
			binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data)

			fmt.Printf("Received event: PID: %d, Comm: %s\n", data.PID, string(data.Comm[:]))
		}
	}()

	<-c // Ждем завершения
	fmt.Println("Exiting...")
}
