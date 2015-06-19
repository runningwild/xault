package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
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

	contactsMutex sync.RWMutex
	contacts      map[string]bool
}

type Xault struct {
	usersMutex sync.Mutex
	users      map[string]*userInfo
	keys       *xcrypt.DualKey
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
		contacts:      make(map[string]bool),
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

func (x *Xault) AddContactRequest(req *api.AddContactRequest, resp *api.AddContactResponse) error {
	x.usersMutex.Lock()
	user, ok := x.users[req.Id]
	x.usersMutex.Unlock()
	if !ok {
		return fmt.Errorf("no such user")
	}
	contactIdBytes, err := x.keys.OpenEnvelope(random, user.keys, req.Envelope)
	if err != nil {
		return fmt.Errorf("internal error")
	}
	contactId := string(contactIdBytes)

	x.usersMutex.Lock()
	contact, ok := x.users[contactId]
	x.usersMutex.Unlock()
	if !ok {
		return fmt.Errorf("no such contact")
	}

	user.contactsMutex.Lock()
	user.contacts[contactId] = true
	user.contactsMutex.Unlock()
}

func MakeXaultServer(keys *xcrypt.DualKey, random io.Reader) *rpc.Server {
	x := &Xault{
		users:  make(map[string]*userInfo),
		keys:   keys,
		random: random,
	}
	server := rpc.NewServer()
	server.Register(x)
	return server
}
