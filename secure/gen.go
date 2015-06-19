package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
)

var numBits = flag.Int("bits", 2048, "number of bits for rsa key")

func main() {
	dk, err := xcrypt.MakeDualKey(rand.Reader, *numBits)
	if err != nil {
		fmt.Printf("Unable to make keys: %v\n", err)
		os.Exit(1)
	}
	dpk, _ := dk.MakePublicKey()
	private, err := os.Create("private.key")
	if err != nil {
		fmt.Printf("Unable to make keys: %v\n", err)
		os.Exit(1)
	}
	defer private.Close()
	public, err := os.Create("public.key")
	if err != nil {
		fmt.Printf("Unable to make keys: %v\n", err)
		os.Exit(1)
	}
	defer public.Close()
	fmt.Fprintf(private, "%v\n", dk)
	fmt.Fprintf(public, "%v\n", dpk)
}
