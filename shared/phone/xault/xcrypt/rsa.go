package xcrypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// DualKey is a single RSA key with different exponents for encrypting and signing.
type DualKey struct {
	// D0 is the private exponent used for encryption, D1 is the same but for signiatures.
	D0, D1 *big.Int

	// P and Q are used for both exponents.
	P, Q *big.Int

	encKey, sigKey *rsa.PrivateKey
}

func (dk *DualKey) String() string {
	data, _ := json.MarshalIndent(dk, "", "  ")
	return string(data)
}

func DualKeyFromString(str string) (*DualKey, error) {
	var dk DualKey
	if err := json.Unmarshal([]byte(str), &dk); err != nil {
		return nil, err
	}
	return &dk, nil
}

type DualPublicKey struct {
	// E0 is the public exponent used for encryption, E1 is the same but for verification.
	E0, E1 int

	// N is the modulus for both exponents.
	N *big.Int

	encKey, sigKey *rsa.PublicKey
}

func (dpk *DualPublicKey) String() string {
	data, _ := json.MarshalIndent(dpk, "", "  ")
	return string(data)
}

func DualPublicKeyFromString(str string) (*DualPublicKey, error) {
	var dpk DualPublicKey
	if err := json.Unmarshal([]byte(str), &dpk); err != nil {
		return nil, err
	}
	return &dpk, nil
}

func (dk *DualKey) MakePublicKey() (*DualPublicKey, error) {
	enc := dk.GetRSADecryptionKey()
	sig := dk.GetRSASigniatureKey()
	if enc.N.Cmp(sig.N) != 0 {
		return nil, fmt.Errorf("keys are malformed")
	}
	dpk := &DualPublicKey{
		E0: enc.PublicKey.E,
		E1: sig.PublicKey.E,
		N:  enc.PublicKey.N,
	}
	return dpk, nil
}

func (dpk *DualPublicKey) GetRSAEncryptionKey() *rsa.PublicKey {
	return &rsa.PublicKey{E: dpk.E0, N: dpk.N}
}

func (dpk *DualPublicKey) GetRSAVerificationKey() *rsa.PublicKey {
	return &rsa.PublicKey{E: dpk.E1, N: dpk.N}
}

// MakeDualKey creates an RSA pair with two exponents, so that one set of keys can encrypt and sign
// safely because each gets its own exponent.
func MakeDualKey(random io.Reader, bits int) (*DualKey, error) {
	if bits%2 == 1 || bits < 128 {
		return nil, fmt.Errorf("bits must be even and greater than 128")
	}

	// We might generate a couple of primes that don't work on the first try, so we keep them around
	// for future attempts with new primes to avoid doing more primaily tests than we need to.
	var primes []*big.Int
	if prime, err := rand.Prime(random, bits/2); err != nil {
		return nil, err
	} else {
		primes = append(primes, prime)
	}
	// Make a prime, then try pairing it with any prime in primes to make a valid RSA key with two
	// exponents.  If that isn't possible then add that prime to primes and repeat.
	for sanity := 10; sanity > 0; sanity-- {
		Q, err := rand.Prime(random, bits/2)
		if err != nil {
			return nil, err
		}
		for _, P := range primes {
			if Q.Cmp(P) == 0 {
				continue
			}
			N := big.NewInt(0).Mul(P, Q)
			if N.BitLen() != bits {
				// We did our math wrong, or the behavior of rand.Prime() has changed.
				continue
			}
			pMinusOne := big.NewInt(0).Sub(P, bigOne)
			qMinusOne := big.NewInt(0).Sub(Q, bigOne)
			totient := big.NewInt(0).Mul(pMinusOne, qMinusOne)

			// Try a few small values for public exponents, as long as we get two that work then we
			// can finish the keys.
			var E, D []*big.Int
			for _, e := range []int64{3, 5, 9, 17, 33} {
				// Check if e and the totient are coprime by checking that the GCD is 1.  This also
				// grabs the inverse of e while we're at it.
				d := big.NewInt(0)
				if big.NewInt(0).GCD(d, big.NewInt(0), big.NewInt(e), totient).Cmp(bigOne) == 0 {
					E = append(E, big.NewInt(e))
					if d.Sign() < 0 {
						d.Add(d, totient)
					}
					D = append(D, d)
					if len(E) == 2 {
						break
					}
				}
			}
			if len(D) == 2 {
				dk := &DualKey{
					D0: D[0],
					D1: D[1],
					P:  P,
					Q:  Q,
				}
				return dk, nil
			}
		}
		primes = append(primes, Q)
	}
	return nil, fmt.Errorf("unable to create a valid DualKey")
}

func (dk *DualKey) makeRSAKey(D *big.Int) *rsa.PrivateKey {
	var pk rsa.PrivateKey
	pk.D = D
	pk.Primes = []*big.Int{dk.P, dk.Q}
	pk.N = big.NewInt(0).Mul(dk.P, dk.Q)
	pMinusOne := big.NewInt(0).Sub(dk.P, bigOne)
	qMinusOne := big.NewInt(0).Sub(dk.Q, bigOne)
	totient := big.NewInt(0).Mul(pMinusOne, qMinusOne)
	e := big.NewInt(0)
	big.NewInt(0).GCD(e, big.NewInt(0), pk.D, totient)
	pk.E = int(e.Int64())
	pk.Precompute()
	return &pk
}

func (dk *DualKey) GetRSADecryptionKey() *rsa.PrivateKey {
	if dk.encKey == nil {
		dk.encKey = dk.makeRSAKey(dk.D0)
	}
	return dk.encKey
}

func (dk *DualKey) GetRSASigniatureKey() *rsa.PrivateKey {
	if dk.sigKey == nil {
		dk.sigKey = dk.makeRSAKey(dk.D1)
	}
	return dk.sigKey
}

// Encrypts a large plaintext by using RSA encryption to encrypt a one-time-key that is used as an
// AES-256 key to encrypt the plaintext.  The encrypted key, ciphertext, and info are also signed.
// Format of the final envelope is:
// L3, 4 bytes, length of signiature
// L0, 4 bytes, length of internal info
// L1, 4 bytes, length of encrypted otk
// L2, 4 bytes, length of ciphertext
// internal info, L0 bytes
// encrypted otk, L1 bytes
// ciphertext, L2 bytes
// signiature, L3 bytes, the signiature covers everything from L0 through the ciphertext
func (dk *DualKey) SealEnvelope(random io.Reader, dst *DualPublicKey, plaintext []byte) (envelope []byte, err error) {
	info := []byte("version 1") // Not sure what to do with this for now

	// otk is a one-time-key, it will only ever be used to encrypt this plaintext
	otk := make([]byte, 32)
	if n, err := random.Read(otk); n != len(otk) || err != nil {
		return nil, fmt.Errorf("unable to read enough random bytes to make a otk: %v", err)
	}
	block, err := aes.NewCipher(otk)
	if err != nil {
		fmt.Errorf("unable to make cipher: %v\n", err)
		return
	}
	// Pad the plaintext by adding a 1, then adding 0s until the length is a multiple of blocks.
	plaintext = append(plaintext, 1)
	for len(plaintext)%block.BlockSize() != 0 {
		plaintext = append(plaintext, 0)
	}

	// Notice that the IV here is all zeroes, this is ok because this otk will never be used again.
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize())).CryptBlocks(ciphertext, plaintext)

	// Now encrypt the otk with the recipient's encryption key
	encryptedOtk, err := rsa.EncryptOAEP(sha256.New(), random, dst.GetRSAEncryptionKey(), otk, []byte("otk"))
	if err != nil {
		return nil, fmt.Errorf("unable to encrypt otk: %v", err)
	}
	for i := range otk {
		otk[i] = 0
	}

	// Start the buffer with 4 empty bytes, we'll fill these in later with the length of the signiature
	buf := bytes.NewBuffer(make([]byte, 4))
	chunks := [][]byte{info, encryptedOtk, ciphertext}
	for _, chunk := range chunks {
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(chunk))); err != nil {
			return nil, fmt.Errorf("unable to finish writing the envelope")
		}
	}
	for _, chunk := range chunks {
		if n, err := buf.Write(chunk); n != len(chunk) || err != nil {
			return nil, fmt.Errorf("unable to finish writing the envelope")
		}
	}

	// Now we hash and sign the envelope that we have so far so that it can't be tampered with.
	h := sha256.Sum256(buf.Bytes()[4:])
	signiature, err := rsa.SignPKCS1v15(random, dk.GetRSASigniatureKey(), crypto.SHA256, h[:])
	if err != nil {
		return nil, fmt.Errorf("unable to sign envelope: %v", err)
	}
	if n, err := buf.Write(signiature); n != len(signiature) || err != nil {
		return nil, fmt.Errorf("unable to sign envelope: %v", err)
	}
	envelope = buf.Bytes()
	buf.Truncate(0)
	binary.Write(buf, binary.LittleEndian, uint32(len(signiature)))

	return envelope, nil
}

var ErrUnableToVerify = fmt.Errorf("unable to verify envelope")
var ErrVerifiedBufMalformed = fmt.Errorf("envelope verified, but contents are malformed")

// OpenEnvelope opens an envelope created with SealEnvelope.  It verifies that the message is signed
// by src, then decrypts it using the enclosed key.
func (dk *DualKey) OpenEnvelope(random io.Reader, src *DualPublicKey, envelope []byte) (plaintext []byte, err error) {
	if len(envelope) < 32 {
		return nil, ErrUnableToVerify
	}

	// Strip off the length of the signiature from the front of the envelope
	var siglen uint32
	if err := binary.Read(bytes.NewBuffer(envelope[0:4]), binary.LittleEndian, &siglen); err != nil {
		return nil, ErrUnableToVerify
	}
	envelope = envelope[4:]
	if int(siglen) > len(envelope)+24 {
		return nil, ErrUnableToVerify
	}
	// Strip the signiature itself off the back of the envelope
	sig := envelope[len(envelope)-int(siglen):]
	envelope = envelope[0 : len(envelope)-int(siglen)]
	h := sha256.Sum256(envelope)
	if err := rsa.VerifyPKCS1v15(src.GetRSAVerificationKey(), crypto.SHA256, h[:], sig); err != nil {
		return nil, ErrUnableToVerify
	}

	// We can now trust that the envelope is from who we thought it was from.
	var infoLen, eotkLen, cipherLen uint32
	buf := bytes.NewBuffer(envelope)
	for _, val := range []*uint32{&infoLen, &eotkLen, &cipherLen} {
		if err := binary.Read(buf, binary.LittleEndian, val); err != nil {
			return nil, ErrVerifiedBufMalformed
		}
	}
	if int64(infoLen)+int64(eotkLen)+int64(cipherLen) != int64(len(buf.Bytes())) {
		return nil, ErrVerifiedBufMalformed
	}

	info := make([]byte, int(infoLen))
	eotk := make([]byte, int(eotkLen))
	ciphertext := make([]byte, int(cipherLen))
	for _, chunk := range [][]byte{info, eotk, ciphertext} {
		if n, err := buf.Read(chunk); n != len(chunk) || err != nil {
			return nil, ErrVerifiedBufMalformed
		}
	}

	otk, err := rsa.DecryptOAEP(sha256.New(), random, dk.GetRSADecryptionKey(), eotk, []byte("otk"))
	if err != nil {
		return nil, ErrVerifiedBufMalformed
	}

	block, err := aes.NewCipher(otk)
	if err != nil {
		return nil, ErrVerifiedBufMalformed
	}
	plaintext = ciphertext
	cipher.NewCBCDecrypter(block, make([]byte, block.BlockSize())).CryptBlocks(plaintext, ciphertext)
	for len(plaintext) > 0 {
		b := plaintext[len(plaintext)-1]
		plaintext = plaintext[0 : len(plaintext)-1]
		if b == 1 {
			break
		}
		if b != 0 {
			return nil, ErrVerifiedBufMalformed
		}
	}

	return plaintext, nil
}
