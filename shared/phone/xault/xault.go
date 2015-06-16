package xault

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
)

type LifetimeState struct {
	// TODO: Hide keys in memory with a boojum when not in use.
	key *xcrypt.DualKey

	info *PublicInfo
}

type PublicInfo struct {
	// Human-readable name of the user, used when exchanging keys with a contact.
	name string

	// Server-unique id, this is the foo in foo@bar.com.
	id string

	// Server that stores this users info, this is the bar.com in foo@bar.com.
	serverName string
}

// MakeKeys constructs new private keys for encrypting and signing.
func (ls *LifetimeState) MakeKeys(info *PublicInfo, bits int) error {
	if ls.key != nil {
		return fmt.Errorf("already have keys")
	}
	if key, err := xcrypt.MakeDualKey(rand.Reader, bits); err != nil {
		return fmt.Errorf("unable to make keys: %v", err)
	} else {
		ls.key = key
	}
	return nil
}

func (ls *LifetimeState) Load(data []byte) error {
	if ls.key != nil {
		return fmt.Errorf("keys have already been loaded")
	}
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(ls.key)
}

func (ls *LifetimeState) Store() ([]byte, error) {
	if ls.key == nil {
		return nil, fmt.Errorf("keys have not been loaded")
	}
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(ls.key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var ls LifetimeState

func Test2(msg string) (string, error) {
	return ls.Test(msg)
}

func (ls *LifetimeState) Test(msg string) (string, error) {
	k1, err := xcrypt.MakeDualKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	k1pub, err := k1.MakePublicKey()
	if err != nil {
		return "", err
	}
	k2, err := xcrypt.MakeDualKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	k2pub, err := k2.MakePublicKey()
	if err != nil {
		return "", err
	}
	start := time.Now()
	envelope, err := k1.SealEnvelope(rand.Reader, k2pub, []byte(msg))
	sealTime := time.Since(start)
	if err != nil {
		return "", fmt.Errorf("failed to seal: %v", err)
	}
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte(fmt.Sprintf("%v", sealTime)))
	start = time.Now()
	msg2, err := k2.OpenEnvelope(rand.Reader, k1pub, envelope)
	openTime := time.Since(start)
	if err != nil {
		return "", fmt.Errorf("failed to open: %v", err)
	}
	if string(msg2) != msg {
		return "", fmt.Errorf("open garbage: %q", msg2)
	}
	buf.Write([]byte(fmt.Sprintf(" %v", openTime)))
	return string(buf.Bytes()), nil
}

// var globalState LifetimeState

// func MakeKeys(bits int) error {
// 	return globalState.MakeKeys(bits)
// }
// func Load(data []byte) error {
// 	return globalState.Load(data)
// }
// func Store() ([]byte, error) {
// 	return globalState.Store()
// }

func Hello(name string) string {
	return fmt.Sprintf("Hello thumb, %s!\n", name)
}
