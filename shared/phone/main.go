// This is the Go entry point for Xault.
// It is invoked from Java.
package main

import (
	"golang.org/x/mobile/app"

	_ "github.com/runningwild/xault/shared/phone/xault/go_xault"
	"golang.org/x/mobile/bind/java"
)

func main() {
	app.Run(app.Callbacks{Start: java.Init})
}
