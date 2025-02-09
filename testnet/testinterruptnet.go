package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// Create UDP listener
	addr, err := net.ResolveUDPAddr("udp", ":12345")
	if err != nil {
		fmt.Printf("Failed to resolve address: %v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Printf("Listening on %s\n", conn.LocalAddr().String())

	// Channel to get read results
	readCh := make(chan []byte)

	// Start reader goroutine that waits indefinitely
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					fmt.Println("Read timeout occurred")
					continue
				}
				fmt.Printf("Read error: %v\n", err)
				continue
			}
			// Make a copy of received data
			data := make([]byte, n)
			copy(data, buffer[:n])
			readCh <- data
		}
	}()

	// Main loop to demonstrate deadline control
	for i := 0; i < 3; i++ {
		fmt.Printf("\nIteration %d:\n", i+1)

		// Set read deadline 2 seconds from now
		fmt.Println("Setting 2 second deadline...")
		err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			fmt.Printf("Failed to set deadline: %v\n", err)
			return
		}

		// Wait for data
		fmt.Println("Waiting for data...")
		select {
		case data := <-readCh:
			fmt.Printf("Received: %s\n", string(data))
		case <-time.After(3 * time.Second):
			fmt.Println("No data received within timeout")
		}

		// Sleep before next iteration
		time.Sleep(time.Second)
	}
}
