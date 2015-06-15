package xault

import (
	"crypto/rsa"
	"testing"

	"github.com/runningwild/cmwc"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDualKeys(t *testing.T) {
	// Use a deterministic RNG so tests can't flake, but run it a bunch of times so that we can be
	// certain about the results.
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)

	Convey("Can make dual keys successfully.", t, func() {
		for i := 0; i < 10; i++ {
			dk, err := MakeDualKey(c, 1024)
			So(err, ShouldBeNil)
			So(dk, ShouldNotBeNil)
			keys := []*rsa.PrivateKey{dk.makeRSAEncryptionKey(), dk.makeRSASigniatureKey()}
			So(keys[0].E, ShouldNotEqual, keys[1].E)
			So(keys[0].Validate(), ShouldBeNil)
			So(keys[1].Validate(), ShouldBeNil)
		}
	})
}
