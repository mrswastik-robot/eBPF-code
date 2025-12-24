package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf/drop_port.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}

	objs := struct {
		Prog      *ebpf.Program `ebpf:"drop_tcp_port"`
		PortMap   *ebpf.Map     `ebpf:"blocked_port"`
		CountMap  *ebpf.Map     `ebpf:"drop_count"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF objects: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.PortMap.Close()
	defer objs.CountMap.Close()

	// Set blocked port (default 4040)
	key := uint32(0)
	port := uint16(4040)
	if err := objs.PortMap.Put(key, port); err != nil {
		log.Fatalf("failed to set blocked port: %v", err)
	}

	// Initialize drop counter to 0
	var initialCount uint64 = 0
	if err := objs.CountMap.Put(key, initialCount); err != nil {
		log.Fatalf("failed to initialize drop counter: %v", err)
	}

	// Get interface index
	ifaceName := "wlan0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get interface %s: %v", ifaceName, err)
	}

	tcx, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.Prog,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach TCX: %v", err)
	}
	defer tcx.Close()

	log.Printf("Dropping TCP packets on port %d (interface: %s)", port, ifaceName)
	log.Println("Press Ctrl+C to stop...")

	// Set up signal handling for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Periodically print drop statistics
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastCount uint64 = 0

	for {
		select {
		case <-ticker.C:
			var count uint64
			if err := objs.CountMap.Lookup(key, &count); err != nil {
				log.Printf("failed to read drop count: %v", err)
				continue
			}
			
			if count != lastCount {
				log.Printf("Dropped %d TCP packets to port %d (+%d since last check)",
					count, port, count-lastCount)
				lastCount = count
			}

		case <-stop:
			// Final stats
			var finalCount uint64
			objs.CountMap.Lookup(key, &finalCount)
			log.Printf("Shutting down. Total packets dropped: %d", finalCount)
			return
		}
	}
}
