package xault

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/runningwild/cmwc"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDualKeys(t *testing.T) {
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)

	Convey("can make dual keys successfully", t, func() {
		dk, err := makeDualKey(c, 1024)
		So(err, ShouldBeNil)
		So(dk, ShouldNotBeNil)
		keys := []*rsa.PrivateKey{dk.getRSADecryptionKey(), dk.getRSASigniatureKey()}
		So(keys[0].E, ShouldNotEqual, keys[1].E)
		So(keys[0].Validate(), ShouldBeNil)
		So(keys[1].Validate(), ShouldBeNil)
		pdk, err := dk.MakePublicKey()
		So(err, ShouldBeNil)
		So(pdk, ShouldNotBeNil)

		Convey("dual keys can encrypt/decrypt", func() {
			enc := pdk.getRSAEncryptionKey()
			dec := dk.getRSADecryptionKey()
			msg := "This message is awesome"
			label := "label"
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), c, enc, []byte(msg), []byte(label))
			So(err, ShouldBeNil)
			plaintext, err := rsa.DecryptOAEP(sha256.New(), c, dec, ciphertext, []byte(label))
			So(err, ShouldBeNil)
			So(string(plaintext), ShouldEqual, msg)
		})

		Convey("dual keys can sign/verify", func() {
			verify := pdk.getRSAVerificationKey()
			sign := dk.getRSASigniatureKey()
			msg := "This message is awesome"
			hashed := sha256.Sum256([]byte(msg))
			signiature, err := rsa.SignPKCS1v15(c, sign, crypto.SHA256, hashed[:])
			So(err, ShouldBeNil)
			err = rsa.VerifyPKCS1v15(verify, crypto.SHA256, hashed[:], signiature)
			So(err, ShouldBeNil)
		})
	})
}

func TestEnvelope(t *testing.T) {
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)
	keySize := 2048
	Convey("DualKeys can be used to seal and open envelopes", t, func() {
		localPrivate, err := makeDualKey(c, keySize)
		So(err, ShouldBeNil)
		localPublic, err := localPrivate.MakePublicKey()
		So(err, ShouldBeNil)
		remotePrivate, err := makeDualKey(c, keySize)
		So(err, ShouldBeNil)
		remotePublic, err := remotePrivate.MakePublicKey()
		So(err, ShouldBeNil)

		plaintext := []byte("this is some awesome plaintext, check out how awesome it is!!!")
		envelope, err := remotePrivate.sealEnvelope(c, localPublic, plaintext)
		So(err, ShouldBeNil)
		So(envelope, ShouldNotBeNil)
		decoded, err := localPrivate.openEnvelope(c, remotePublic, envelope)
		So(err, ShouldBeNil)
		So(decoded, ShouldResemble, plaintext)
	})
}

func benchmarkEnvelope(msgSize, keySize int, b *testing.B) {
	b.StopTimer()
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)
	sender, err := makeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	receiverPrivate, err := makeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	receiver, err := receiverPrivate.MakePublicKey()
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, msgSize)
	if _, err := sender.sealEnvelope(c, receiver, plaintext); err != nil {
		panic(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sender.sealEnvelope(c, receiver, plaintext)
	}
}

func Benchmark1KEnvelope(b *testing.B) {
	benchmarkEnvelope(1<<10, 2048, b)
}

func Benchmark1MEnvelope(b *testing.B) {
	benchmarkEnvelope(1<<20, 2048, b)
}

func Benchmark10MEnvelope(b *testing.B) {
	benchmarkEnvelope(10<<20, 2048, b)
}
