package xault

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type LifetimeState struct {
	// TODO: Hide keys in memory with a boojum when not in use.
	key *DualKey

	info *PublicInfo
}

type PublicInfo struct {
	// Human-readable name of the user, used when exchanging keys with a contact.
	name string

	// Server-unique id, this is the foo in foo@bar.com.
	id []byte

	// Server that stores this users info, this is the bar.com in foo@bar.com.
	serverName string
}

// MakeKeys constructs new private keys for encrypting and signing.
func (ls *LifetimeState) MakeKeys(info *PublicInfo, bits int) error {
	// crypt, err := rsa.GenerateKey(rand.Reader, bits)
	// if err != nil {
	// 	return err
	// }
	// sign, err := rsa.GenerateKey(rand.Reader, bits)
	// if err != nil {
	// 	return err
	// }
	// id := make([]byte, 16)
	// if _, err := rand.Read(id); err != nil {
	// 	return err
	// }
	// ls.cryptKey = crypt
	// ls.signKey = sign
	// ls.name = name
	// ls.id = id
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
