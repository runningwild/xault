package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"text/template"

	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
)

var numBits = flag.Int("bits", 2048, "number of bits for rsa key")
var packageName = flag.String("package", "xault", "package name of the generated package")
var keyName = flag.String("key-name", "key", "name to give generated variables")
var dstPath = flag.String("dst", "./key.go", "path of the output file")

type templateParams struct {
	Package      string
	KeyName      string
	PublicKeyStr string
}

func main() {
	flag.Parse()
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
	t, err := template.ParseFiles("key.go.template")
	if err != nil {
		fmt.Printf("unable to parse template file: %v\n", err)
		os.Exit(1)
	}
	f, err := os.Create(*dstPath)
	if err != nil {
		fmt.Printf("unable to open output file %q for writing: %v", *dstPath, err)
		os.Exit(1)
	}
	defer f.Close()
	data := templateParams{
		Package:      *packageName,
		KeyName:      *keyName,
		PublicKeyStr: fmt.Sprintf("%v", dpk),
	}
	if err := t.Execute(f, data); err != nil {
		fmt.Printf("failed to execute template: %v\n", err)
		os.Exit(1)
	}
}
