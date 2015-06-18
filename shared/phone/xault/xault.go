package xault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"github.com/runningwild/xault/shared/phone/xault/xcrypt"
)

// Initial flow should be:
// Start up
// Load state, on failure, prompt for usename, then create and save state.

var ls LifetimeState

type LifetimeState struct {
	// TODO: Hide keys in memory with a boojum when not in use.
	key *xcrypt.DualKey

	info *publicInfo

	rootDir string
}

type publicInfo struct {
	// Human-readable name of the user, used when exchanging keys with a contact.
	Name string

	// Server-unique id, this is the foo in foo@bar.com.
	Id string

	// Server that stores this users info, this is the bar.com in foo@bar.com.
	Server string
}

// SetRootDir sets the directory under which all files will be read/written.  It should be called
// before any other function, and it should be called exactly once.
func (ls *LifetimeState) SetRootDir(path string) error {
	if ls.rootDir != "" {
		return fmt.Errorf("SetRootDir has already been called")
	}
	ls.rootDir = path
	return nil
}

func SetRootDir(path string) error {
	return ls.SetRootDir(path)
}

// This is the structure that is actually gobbed to disk to save a user's keys and id.
type keyFile struct {
	Key  *xcrypt.DualKey
	Info publicInfo
}

// MakeKeys generates an id and keys for that id and saves them to disk.
func (ls *LifetimeState) MakeKeys(name string) error {
	if err := ls.checkInitted(); err != nil {
		return err
	}
	// Make sure the name is reasonable.
	minNameLen := 5
	if len(name) < minNameLen {
		return fmt.Errorf("name must be at least %d characters long", minNameLen)
	}

	// Create a random id.
	idBits := make([]byte, 32)
	if n, err := rand.Read(idBits); n != len(idBits) || err != nil {
		return fmt.Errorf("unable to generate an id")
	}
	// Convert the id to base64 so it's human 'readable'.
	idBuf := bytes.NewBuffer(nil)
	enc := base64.NewEncoder(base64.URLEncoding, idBuf)
	enc.Write(idBits)
	enc.Close()

	// Create a new dual key
	dk, err := xcrypt.MakeDualKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Put all this file into a single struct so we can gob it to disk.
	fileData := keyFile{
		Key: dk,
		Info: publicInfo{
			Name:   name,
			Id:     string(idBuf.Bytes()),
			Server: "thisisaserver.com",
		},
	}

	// Save it to disk.
	path := filepath.Join(ls.rootDir, "keys")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("unable to open %q: %v", path, err)
	}
	defer f.Close()
	if err := gob.NewEncoder(f).Encode(fileData); err != nil {
		return fmt.Errorf("unable to save keys to disk: %v", err)
	}

	// Everything was successful, so set the global state and return successfully.
	ls.key = fileData.Key
	ls.info = &fileData.Info

	return nil
}

func MakeKeys(name string) error {
	return ls.MakeKeys(name)
}

func (ls *LifetimeState) checkInitted() error {
	if ls.rootDir == "" {
		return fmt.Errorf("must call SetRootDir() before anything else")
	}
	return nil
}

func (ls *LifetimeState) LoadKeys() error {
	if err := ls.checkInitted(); err != nil {
		return err
	}
	var kf keyFile
	path := filepath.Join(ls.rootDir, "keys")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open %q: %v", path, err)
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&kf); err != nil {
		return err
	}
	ls.key = kf.Key
	ls.info = &kf.Info
	return nil
}

func LoadKeys() error {
	return ls.LoadKeys()
}

func (ls *LifetimeState) DestroyKeys() error {
	if err := ls.checkInitted(); err != nil {
		return err
	}
	path := filepath.Join(ls.rootDir, "keys")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("Unable to remove %q: %v", path, err)
	}
	return nil
}

func DestroyKeys() error {
	return ls.DestroyKeys()
}
