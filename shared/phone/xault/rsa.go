package xault

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// DualKey is a single RSA key with different exponents for encrypting and signing.
type DualKey struct {
	// D contains the two private exponents, D[0] is used for encryption, D[1] for signing.
	D [2]*big.Int

	// P and Q are used for both exponents.
	P, Q *big.Int
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
					D: [2]*big.Int{D[0], D[1]},
					P: P,
					Q: Q,
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
	return &pk
}

func (dk *DualKey) makeRSAEncryptionKey() *rsa.PrivateKey {
	return dk.makeRSAKey(dk.D[0])
}

func (dk *DualKey) makeRSASigniatureKey() *rsa.PrivateKey {
	return dk.makeRSAKey(dk.D[1])
}
