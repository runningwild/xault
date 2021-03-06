package xcrypt

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
		dk, err := MakeDualKey(c, 1024)
		So(err, ShouldBeNil)
		So(dk, ShouldNotBeNil)
		keys := []*rsa.PrivateKey{dk.GetRSADecryptionKey(), dk.GetRSASigniatureKey()}
		So(keys[0].E, ShouldNotEqual, keys[1].E)
		So(keys[0].Validate(), ShouldBeNil)
		So(keys[1].Validate(), ShouldBeNil)
		pdk, err := dk.MakePublicKey()
		So(err, ShouldBeNil)
		So(pdk, ShouldNotBeNil)

		Convey("can convert keys to and from strings", func() {
			dk2, err := DualKeyFromString(dk.String())
			So(err, ShouldBeNil)
			So(dk.D0.Cmp(dk2.D0), ShouldEqual, 0)
			So(dk.D1.Cmp(dk2.D1), ShouldEqual, 0)
			So(dk.P.Cmp(dk2.P), ShouldEqual, 0)
			So(dk.Q.Cmp(dk2.Q), ShouldEqual, 0)
		})

		Convey("dual keys can encrypt/decrypt", func() {
			enc := pdk.GetRSAEncryptionKey()
			dec := dk.GetRSADecryptionKey()
			msg := "This message is awesome"
			label := "label"
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), c, enc, []byte(msg), []byte(label))
			So(err, ShouldBeNil)
			plaintext, err := rsa.DecryptOAEP(sha256.New(), c, dec, ciphertext, []byte(label))
			So(err, ShouldBeNil)
			So(string(plaintext), ShouldEqual, msg)
		})

		Convey("dual keys can sign/verify", func() {
			verify := pdk.GetRSAVerificationKey()
			sign := dk.GetRSASigniatureKey()
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
	Convey("dualKeys can be used to seal and open envelopes", t, func() {
		localPrivate, err := MakeDualKey(c, keySize)
		So(err, ShouldBeNil)
		localPublic, err := localPrivate.MakePublicKey()
		So(err, ShouldBeNil)
		remotePrivate, err := MakeDualKey(c, keySize)
		So(err, ShouldBeNil)
		remotePublic, err := remotePrivate.MakePublicKey()
		So(err, ShouldBeNil)

		plaintext := []byte("this is some awesome plaintext, check out how awesome it is!!!")
		envelope, err := remotePrivate.SealEnvelope(c, localPublic, plaintext)
		So(err, ShouldBeNil)
		So(envelope, ShouldNotBeNil)
		decoded, err := localPrivate.OpenEnvelope(c, remotePublic, envelope)
		So(err, ShouldBeNil)
		So(decoded, ShouldResemble, plaintext)

		Convey("open envelope doesn't open malformed inputs", func() {
			otherPrivate, err := MakeDualKey(c, keySize)
			So(err, ShouldBeNil)
			otherPublic, err := otherPrivate.MakePublicKey()
			So(err, ShouldBeNil)

			// Shouldn't be able to verify with the wrong public key.
			_, err = localPrivate.OpenEnvelope(c, otherPublic, envelope)
			So(err, ShouldEqual, ErrUnableToVerify)

			// Shouldn't be able to verify if we're missing a byte.
			_, err = localPrivate.OpenEnvelope(c, remotePublic, envelope[1:])
			So(err, ShouldEqual, ErrUnableToVerify)
			_, err = localPrivate.OpenEnvelope(c, remotePublic, envelope[0:len(envelope)-1])
			So(err, ShouldEqual, ErrUnableToVerify)

			// Shouldn't be able to verify if a byte is corrupted.
			envelope[50]++
			_, err = localPrivate.OpenEnvelope(c, remotePublic, envelope)
			So(err, ShouldEqual, ErrUnableToVerify)
			envelope[50]--
		})
	})
}

func benchmarkSealEnvelope(msgSize, keySize int, b *testing.B) {
	b.StopTimer()
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)
	sender, err := MakeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	receiverPrivate, err := MakeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	receiver, err := receiverPrivate.MakePublicKey()
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, msgSize)
	if _, err := sender.SealEnvelope(c, receiver, plaintext); err != nil {
		panic(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sender.SealEnvelope(c, receiver, plaintext)
	}
}

func Benchmark1KSealEnvelope(b *testing.B) {
	benchmarkSealEnvelope(1<<10, 2048, b)
}

func Benchmark1MSealEnvelope(b *testing.B) {
	benchmarkSealEnvelope(1<<20, 2048, b)
}

func Benchmark10MSealEnvelope(b *testing.B) {
	benchmarkSealEnvelope(10<<20, 2048, b)
}

func benchmarkOpenEnvelope(msgSize, keySize int, b *testing.B) {
	b.StopTimer()
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)
	senderPrivate, err := MakeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	sender, err := senderPrivate.MakePublicKey()
	if err != nil {
		panic(err)
	}
	receiverPrivate, err := MakeDualKey(c, keySize)
	if err != nil {
		panic(err)
	}
	receiver, err := receiverPrivate.MakePublicKey()
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, msgSize)
	envelope, err := senderPrivate.SealEnvelope(c, receiver, plaintext)
	if err != nil {
		panic(err)
	}
	msg, err := receiverPrivate.OpenEnvelope(c, sender, envelope)
	if err != nil {
		panic(err)
	}
	if string(msg) != string(plaintext) {
		panic("messages didn't match")
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		receiverPrivate.OpenEnvelope(c, sender, envelope)
	}
}

func Benchmark1KOpenEnvelope(b *testing.B) {
	benchmarkOpenEnvelope(1<<10, 2048, b)
}

func Benchmark1MOpenEnvelope(b *testing.B) {
	benchmarkOpenEnvelope(1<<20, 2048, b)
}

func Benchmark10MOpenEnvelope(b *testing.B) {
	benchmarkOpenEnvelope(10<<20, 2048, b)
}
