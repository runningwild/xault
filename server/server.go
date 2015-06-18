package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net/rpc"
	"sync"
	"time"

	"github.com/runningwild/xault/shared/api"
	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
)

var foo api.MakeIdRequest

type userInfo struct {
	keys          *xcrypt.DualPublicKey
	verified      bool
	challenge     []byte
	challengeTime time.Time
}

type Xault struct {
	usersMutex sync.Mutex
	users      map[string]*userInfo
}

func (x *Xault) MakeId(req *api.MakeIdRequest, resp *api.MakeIdChallenge) error {
	x.usersMutex.Lock()
	defer x.usersMutex.Unlock()
	user, ok := x.users[req.Id]
	if ok {
		if time.Since(user.challengeTime).Seconds() > 10 {
			delete(x.users, req.Id)
		} else {
			return fmt.Errorf("user %q already exists", req.Id)
		}
	}

	challenge := make([]byte, 32)
	if n, err := rand.Reader.Read(challenge); n != len(challenge) || err != nil {
		return fmt.Errorf("unable to make challenge")
	}
	encryptedChallenge, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, req.Keys.GetRSAEncryptionKey(), challenge, []byte("challenge"))
	if err != nil {
		return fmt.Errorf("unable to make challenge")
	}

	x.users[req.Id] = &userInfo{
		keys:          req.Keys,
		challenge:     challenge,
		challengeTime: time.Now(),
	}
	resp.EncryptedChallenge = encryptedChallenge
	return nil
}

func (x *Xault) MakeIdCompleteChallenge(req *api.MakeIdChallengeResponse, resp *api.MakeIdResponse) error {
	x.usersMutex.Lock()
	defer x.usersMutex.Unlock()
	user, ok := x.users[req.Id]
	if !ok || time.Since(user.challengeTime).Seconds() > 10 {
		delete(x.users, req.Id)
		return fmt.Errorf("user %q does not exist", req.Id)
	}
	hashed := sha256.Sum256(user.challenge)
	if err := rsa.VerifyPKCS1v15(user.keys.GetRSAVerificationKey(), crypto.SHA256, hashed[:], req.SignedChallenge); err != nil {
		return fmt.Errorf("could not verify signiature")
	}

	user.verified = true
	return nil
}

func MakeXaultServer() *rpc.Server {
	x := &Xault{
		users: make(map[string]*userInfo),
	}
	server := rpc.NewServer()
	server.Register(x)
	return server
}
