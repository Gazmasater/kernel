package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const bpfProgramFile = "bpf/bpf_program.bpf.o"

func main() {
	// Загружаем eBPF программу
	spec, err := ebpf.LoadCollectionSpec(bpfProgramFile)
	if err != nil {
		log.Fatalf("Ошибка загрузки eBPF программы: %v", err)
	}

	// Создаём экземпляр eBPF программы
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Ошибка создания коллекции eBPF: %v", err)
	}
	defer coll.Close()

	// Получаем ссылку на eBPF программу
	prog := coll.Programs["xdp_prog"]
	if prog == nil {
		log.Fatalf("Не удалось найти программу 'xdp_prog' в eBPF объекте")
	}

	// Прикрепляем программу к сетевому интерфейсу (например, eth0)
	iface := "eth0"
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex(iface),
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Ошибка прикрепления eBPF программы: %v", err)
	}
	defer l.Close()

	fmt.Printf("eBPF программа прикреплена к интерфейсу %s\n", iface)

	// Чтение сообщений, отправленных с помощью bpf_printk
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		log.Fatalf("Ошибка создания perf reader: %v", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Fatalf("Ошибка чтения perf событий: %v", err)
			}

			if record.LostSamples != 0 {
				fmt.Printf("Потеряно %d событий\n", record.LostSamples)
				continue
			}

			var msg string
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &msg); err != nil {
				log.Fatalf("Ошибка преобразования данных perf события: %v", err)
			}

			fmt.Printf("Сообщение от eBPF программы: %s\n", msg)
		}
	}()

	// Ожидание сигнала завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Завершаем программу...")
}

// ifaceIndex получает индекс сетевого интерфейса по его имени.
func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Ошибка получения индекса интерфейса %s: %v", name, err)
	}
	return iface.Index
}
