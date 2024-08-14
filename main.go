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

	// Получаем указатель на программу для начала
	progStart, ok := obj.Programs["bpf_prog_start"]
	if !ok {
		log.Fatalf("program bpf_prog_start not found")
	}

	// Получаем указатель на программу для окончания
	progEnd, ok := obj.Programs["bpf_prog_end"]
	if !ok {
		log.Fatalf("program bpf_prog_end not found")
	}

	// Прикрепляем программы к tracepoint
	tracepointStart, err := link.Tracepoint("syscalls", "sys_enter_execve", progStart, nil)
	if err != nil {
		log.Fatalf("failed to attach start program to tracepoint: %v", err)
	}
	defer tracepointStart.Close()

	tracepointEnd, err := link.Tracepoint("syscalls", "sys_exit_execve", progEnd, nil)
	if err != nil {
		log.Fatalf("failed to attach end program to tracepoint: %v", err)
	}
	defer tracepointEnd.Close()

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
				PID       uint32
				Comm      [16]byte
				StartTime uint64
				EndTime   uint64
			}
			binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data)

			// Отображаем начало и конец события
			if data.EndTime != 0 {
				fmt.Printf("End event: PID: %d, Comm: %s, Start: %d ns, End: %d ns\n",
					data.PID, string(data.Comm[:]), data.StartTime, data.EndTime)
			} else {
				fmt.Printf("Start event: PID: %d, Comm: %s, Start: %d ns\n",
					data.PID, string(data.Comm[:]), data.StartTime)
			}
		}
	}()

	<-c // Ждем завершения
	fmt.Println("Exiting...")
}
