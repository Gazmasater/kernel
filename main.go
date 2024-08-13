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
	// Load BPF program from object file
	obj, err := ebpf.LoadCollection("bpf/bpf_program.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF collection: %v", err)
	}
	defer obj.Close()

	// Get the program
	prog, ok := obj.Programs["bpf_prog"] // Ensure this matches your function name
	if !ok {
		log.Fatalf("program bpf_prog not found")
	}

	// Get the PERF_EVENT_ARRAY map
	perfMap, ok := obj.Maps["perf_map"] // Ensure this matches your map name
	if !ok {
		log.Fatalf("perf_map not found")
	}

	// Attach program to tracepoint
	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("failed to attach program to tracepoint: %v", err)
	}
	defer tracepoint.Close()

	// Create a new perf reader
	reader, err := perf.NewReader(perfMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer reader.Close()

	// Signal handling for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Listening for events...")

	go func() {
		for {
			// Read events from the perf buffer
			record, err := reader.Read()
			if err != nil {
				log.Printf("failed to read event: %v", err)
				continue
			}

			// Process the event
			var data struct {
				Message [64]byte
			}

			// Use bytes.NewReader to wrap record.RawSample
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data)
			if err != nil {
				log.Printf("failed to decode event data: %v", err)
				continue
			}

			fmt.Printf("Received event: %s\n", data.Message)
		}
	}()

	<-c // Wait for termination
	fmt.Println("Exiting...")
}
