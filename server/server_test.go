package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/rpc"
	"testing"

	"github.com/runningwild/cmwc"
	"github.com/runningwild/xault/shared/api"
	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
	. "github.com/smartystreets/goconvey/convey"
)

type fakeBlockingConn struct {
	reads  chan readRequest
	writes chan writeRequest
	done   chan struct{}
}

func makeFakeBlockingConn() *fakeBlockingConn {
	var fbc fakeBlockingConn
	fbc.reads = make(chan readRequest)
	fbc.writes = make(chan writeRequest)
	fbc.done = make(chan struct{})
	go fbc.run()
	return &fbc
}
func (fbc *fakeBlockingConn) run() {
	var buf bytes.Buffer
	var pending []readRequest
	writes := fbc.writes
	for writes != nil || buf.Len() > 0 {
		select {
		case req := <-fbc.reads:
			if buf.Len() == 0 {
				pending = append(pending, req)
			} else {
				var resp readResponse
				resp.n, _ = buf.Read(req.data)
				req.resp <- resp
			}
		case req, ok := <-writes:
			if !ok {
				writes = nil
				break
			}
			buf.Write(req.data)
			req.resp <- writeResponse{len(req.data), nil}
			for len(pending) > 0 && buf.Len() > 0 {
				req := pending[0]
				pending = pending[1:]
				var resp readResponse
				resp.n, _ = buf.Read(req.data)
				req.resp <- resp
			}
		}
	}
	close(fbc.done)
	for _, req := range pending {
		req.resp <- readResponse{0, io.EOF}
	}
}
func (fbc *fakeBlockingConn) Write(data []byte) (n int, err error) {
	d := make([]byte, len(data))
	copy(d, data)
	req := writeRequest{d, make(chan writeResponse)}
	fbc.writes <- req
	resp := <-req.resp
	return resp.n, resp.err
}

type readRequest struct {
	data []byte
	resp chan readResponse
}
type readResponse struct {
	n   int
	err error
}
type writeRequest struct {
	data []byte
	resp chan writeResponse
}
type writeResponse struct {
	n   int
	err error
}

func (fbc *fakeBlockingConn) Read(data []byte) (n int, err error) {
	req := readRequest{data, make(chan readResponse)}
	select {
	case <-fbc.done:
		return 0, io.EOF
	case fbc.reads <- req:
		resp := <-req.resp
		return resp.n, resp.err
	}
	return 0, nil
}
func (fbc *fakeBlockingConn) String() string {
	return fmt.Sprintf("FBC:%p", fbc)
}
func (fbc *fakeBlockingConn) Close() error {
	close(fbc.writes)
	return nil
}

func makeConnPair() (c0, c1 io.ReadWriteCloser) {
	a := makeFakeBlockingConn()
	b := makeFakeBlockingConn()
	return &twistedConn{a, b}, &twistedConn{b, a}
}

type twistedConn struct {
	a, b *fakeBlockingConn
}

func (tc *twistedConn) Read(buf []byte) (n int, err error) {
	return tc.a.Read(buf)
}
func (tc *twistedConn) Write(buf []byte) (n int, err error) {
	return tc.b.Write(buf)
}
func (tc *twistedConn) Close() error {
	return tc.b.Close()
}

func TestConn(t *testing.T) {
	Convey("Something", t, func() {
		a, b := makeConnPair()
		strA := "foobar wingding thundergun monkeyball Buttons!!!"
		strB := "nubnub"
		go func() {
			for i := 0; i < 10; i++ {
				a.Write([]byte(strA))
			}
			a.Close()
		}()
		go func() {
			for i := 0; i < 10; i++ {
				b.Write([]byte(strB))
			}
			b.Close()
		}()
		data, err := ioutil.ReadAll(a)
		So(err, ShouldBeNil)
		So(len(data), ShouldEqual, len(strB)*10)
		data, err = ioutil.ReadAll(b)
		So(err, ShouldBeNil)
		So(len(data), ShouldEqual, len(strA)*10)
	})
}

func doCallOnXaultServer(s *rpc.Server, method string, in, out interface{}) error {
	a, b := makeConnPair()
	client := rpc.NewClient(a)
	done := make(chan struct{})
	go func() {
		s.ServeConn(b)
		close(done)
	}()
	err := client.Call(method, in, out)
	a.Close()
	<-done
	return err
}

var keys []*xcrypt.DualKey

func init() {
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)
	for i := 0; i < 4; i++ {
		dk, err := xcrypt.MakeDualKey(c, 2048)
		if err != nil {
			panic(err)
		}
		keys = append(keys, dk)
	}
}

func TestServer(t *testing.T) {
	Convey("TestServer", t, func() {
		server := MakeXaultServer()
		dk := keys[0]
		dpk, err := dk.MakePublicKey()
		So(err, ShouldBeNil)
		wrongKeys := keys[1]

		req := api.MakeIdRequest{Id: "myid", Keys: dpk}
		var challenge api.MakeIdChallenge
		So(doCallOnXaultServer(server, "Xault.MakeId", req, &challenge), ShouldBeNil)
		So(len(challenge.EncryptedChallenge), ShouldBeGreaterThanOrEqualTo, 32)

		Convey("using the correct keys will successfully complete the challenge", func() {
			data, err := rsa.DecryptOAEP(sha256.New(), nil, dk.GetRSADecryptionKey(), challenge.EncryptedChallenge, []byte("challenge"))
			So(err, ShouldBeNil)
			hashed := sha256.Sum256(data)
			signature, err := rsa.SignPKCS1v15(nil, dk.GetRSASigniatureKey(), crypto.SHA256, hashed[:])
			So(err, ShouldBeNil)
			req := api.MakeIdChallengeResponse{Id: "myid", SignedChallenge: signature}
			var reply api.MakeIdResponse
			So(doCallOnXaultServer(server, "Xault.MakeIdCompleteChallenge", req, &reply), ShouldBeNil)

			Convey("cannot make the same id twice", func() {
				req := api.MakeIdRequest{Id: "myid", Keys: dpk}
				var challenge api.MakeIdChallenge
				So(doCallOnXaultServer(server, "Xault.MakeId", req, &challenge), ShouldNotBeNil)
			})
		})

		Convey("the wrong keys cannot complete the challenge", func() {
			_, err = rsa.DecryptOAEP(sha256.New(), nil, wrongKeys.GetRSADecryptionKey(), challenge.EncryptedChallenge, []byte("challenge"))
			So(err, ShouldNotBeNil)
		})

		Convey("sending the wrong challenge back signed with the right key does not complete the challenge", func() {
			hashed := sha256.Sum256([]byte("random data, not the correct challenge"))
			signature, err := rsa.SignPKCS1v15(nil, dk.GetRSASigniatureKey(), crypto.SHA256, hashed[:])
			So(err, ShouldBeNil)
			req := api.MakeIdChallengeResponse{Id: "myid", SignedChallenge: signature}
			var reply api.MakeIdResponse
			So(doCallOnXaultServer(server, "Xault.MakeIdCompleteChallenge", req, &reply), ShouldNotBeNil)
		})

		Convey("sending the right challenge back signed with the wrong key does not complete the challenge", func() {
			data, err := rsa.DecryptOAEP(sha256.New(), nil, dk.GetRSADecryptionKey(), challenge.EncryptedChallenge, []byte("challenge"))
			So(err, ShouldBeNil)
			hashed := sha256.Sum256(data)
			signature, err := rsa.SignPKCS1v15(nil, wrongKeys.GetRSASigniatureKey(), crypto.SHA256, hashed[:])
			So(err, ShouldBeNil)
			req := api.MakeIdChallengeResponse{Id: "myid", SignedChallenge: signature}
			var reply api.MakeIdResponse
			So(doCallOnXaultServer(server, "Xault.MakeIdCompleteChallenge", req, &reply), ShouldNotBeNil)
		})
	})
}
