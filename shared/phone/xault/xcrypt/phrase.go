package xcrypt

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"sort"
	"strings"

	"github.com/seehuhn/fortuna"
)

type KeyMaker struct {
	// words is the set of words that can be used in the generated passphrase.  These words should
	// be chosen such that all pairs of words are at least edit distance two apart.
	words []string

	// versions is used to indicate the specs that were used to generate the key.  One of these
	// words will be included in the phrase and that decides both the algorithm and the parameters.
	// Right now only one, android, is used, but in the future these others might be used to
	// indicate other parameters, like longer key length or keys generated in a different way.
	versions versions
}

type versions struct {
	Current string
	Words   map[string]versionInfo
}
type versionInfo struct {
	KeyBits int
}

// MakeKeyMaker makes a KeyMaker object that can be used to generate DualKeys with associated
// phrases that can be used to regenerate those keys later.
func MakeKeyMaker(wordsPath, versionPath string) (*KeyMaker, error) {
	wordsData, err := ioutil.ReadFile(wordsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read words file %q: %v", wordsPath, err)
	}
	versionData, err := ioutil.ReadFile(versionPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read versions file %q: %v", versionPath, err)
	}
	var km KeyMaker
	if err := json.Unmarshal(versionData, &km.versions); err != nil {
		return nil, fmt.Errorf("unable to read version file %q: %v", versionPath, err)
	}
	km.words = strings.Fields(string(wordsData))
	if len(km.words) <= 1 {
		return nil, fmt.Errorf("not enough words supplied")
	}
	for i := range km.words {
		km.words[i] = strings.ToLower(km.words[i])
	}
	for word := range km.versions.Words {
		if strings.ToLower(word) != word {
			return nil, fmt.Errorf("versions contains %q which is not lower-cased", word)
		}
	}

	// Sanity checks
	// Make sure that the current version is a valid version
	if _, ok := km.versions.Words[km.versions.Current]; !ok {
		return nil, fmt.Errorf("current version %q is not a valid version", km.versions.Current)
	}
	// Make sure that no version words are present in the word list
	for _, word := range km.words {
		if _, ok := km.versions.Words[word]; ok {
			return nil, fmt.Errorf("%q was present in both the word list and in the version words", word)
		}
	}
	// Make sure that pair of words, including version words, have edit distance of one.
	before := km.words
	for versionWord := range km.versions.Words {
		km.words = append(km.words, versionWord)
	}
	if worst, dist := findWorstCaseWords(km.words); dist <= 1 {
		return nil, fmt.Errorf("these words have edit distance one or less: %v", worst)
	}
	km.words = before

	return &km, nil
}

// GenerateKeyAndPhrase generates a DualKey and an associated phrase that can be used to recreate
// the key.  The phrase is chosen such that it contains worddBits bits of entropy.  The phrase is
// used to seed a generator that will generate a DualKey.
func (km *KeyMaker) GenerateKeyAndPhrase(random io.Reader, wordBits int) (*DualKey, []string, error) {
	bitsPerWord := math.Log2(float64(len(km.words)))
	var phrase []string
	for bits := 0.0; bits+math.Log2(float64(len(phrase)+1)) < float64(wordBits); bits += bitsPerWord {
		num, err := rand.Int(random, big.NewInt(int64(len(km.words))))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to select a random set of words")
		}
		phrase = append(phrase, km.words[int(num.Int64())])
	}
	// Place the version word somewhere in the phrase
	num, err := rand.Int(random, big.NewInt(int64(len(phrase))))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to select a random set of words")
	}
	phrase = append(phrase, km.versions.Current)
	swap := int(num.Int64())
	last := len(phrase) - 1
	phrase[swap], phrase[last] = phrase[last], phrase[swap]
	key, _, err := km.RegenerateKeyFromPhrase(phrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to make key: %v", err)
	}
	return key, phrase, nil
}

// this is just so we can use a *fortuna.Generator as an io.Reader.
type fortunaReader struct {
	gen *fortuna.Generator
}

func (r *fortunaReader) Read(b []byte) (n int, err error) {
	copy(b, r.gen.PseudoRandomData(uint(len(b))))
	return len(b), nil
}

func makeFortunaReader(seed []byte) *fortunaReader {
	gen := fortuna.NewGenerator(aes.NewCipher)
	gen.Seed(0)
	gen.Reseed(seed)
	return &fortunaReader{gen: gen}
}

func loadWords(path string) ([]string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	words := strings.Fields(string(data))
	for i := range words {
		words[i] = strings.ToLower(words[i])
	}
	return words, nil
}

// editDistance computes the edit distance between a and b, where adding or deleting a character
// costs 1 and swapping two adjacent characters also costs 1.
func editDistance(a, b string) int {
	if len(b) < len(a) {
		a, b = b, a
	}
	score := make([][]int, len(a)+1)
	for i := range score {
		score[i] = make([]int, len(b)+1)
		for j := range score[i] {
			score[i][j] = -1
		}
	}
	return editDistanceHelper(a, b, 0, 0, score)
}

func editDistanceHelper(a, b string, i, j int, score [][]int) int {
	if i == len(a) {
		return len(b) - j
	}
	if j == len(b) {
		return len(a) - i
	}
	if score[i][j] != -1 {
		return score[i][j]
	}
	if a[i] == b[i] {
		return editDistanceHelper(a, b, i+1, j+1, score)
	}
	opts := []int{
		editDistanceHelper(a, b, i+1, j, score) + 1,
		editDistanceHelper(a, b, i, j+1, score) + 1,
		editDistanceHelper(a, b, i+1, j+1, score) + 1,
	}
	if i < len(a)-1 && j < len(b)-1 && a[i] == b[j+1] && b[j] == a[i+1] {
		opts = append(opts, editDistanceHelper(a, b, i+2, j+2, score)+1)
	}
	sort.Ints(opts)
	score[i][j] = opts[0]
	return score[i][j]
}

func findWorstCaseWords(words []string) ([]string, int) {
	m := make(map[string]int)
	for i := range words {
		a := words[i]
		for j := i + 1; j < len(words); j++ {
			b := words[j]
			ed := editDistance(a, b)
			if _, ok := m[a]; !ok {
				m[a] = ed
			}
			if _, ok := m[b]; !ok {
				m[b] = ed
			}
			if ed < m[a] {
				m[a] = ed
			}
			if ed < m[b] {
				m[b] = ed
			}
		}
	}
	m2 := make(map[int][]string)
	for word, ed := range m {
		m2[ed] = append(m2[ed], word)
	}
	worst := -1
	for dist := range m2 {
		if worst == -1 || dist < worst {
			worst = dist
		}
	}
	return m2[worst], worst
}

// RegenerateKeyFromPhrase takes a phrase that was returned from GenerateKeyAndPhrase and returns
// the same key that was previously returned with this phrase.  The phrase must contain the words in
// the same order, but minor misspellings will be corrected.  If successful, this function will
// return the key and the phrase with any corrections that were applied to it.
func (km *KeyMaker) RegenerateKeyFromPhrase(phrase []string) (dk *DualKey, corrected []string, err error) {
	corrected = make([]string, len(phrase))
	copy(corrected, phrase)
	// Correct phrase words if necessary
	for i := range corrected {
		corrected[i] = strings.ToLower(corrected[i])
	}
	words := km.words
	for versionWord := range km.versions.Words {
		words = append(words, versionWord)
	}
	var version string
	for i := range corrected {
		var bestWord string
		var bestScore int = 1000
		for _, word := range words {
			ed := editDistance(corrected[i], word)
			if ed < bestScore {
				bestScore = ed
				bestWord = word
				if ed == 0 {
					break
				}
			}
		}
		if bestScore >= 2 {
			return nil, nil, fmt.Errorf("%q is not a valid word", corrected[i])
		}
		if bestWord != corrected[i] {
			corrected[i] = bestWord
		}
		if _, ok := km.versions.Words[corrected[i]]; ok {
			if version != "" {
				return nil, nil, fmt.Errorf("%q and %q should not both be in the phrase", version, corrected[i])
			}
			version = corrected[i]
		}
	}
	if version == "" {
		return nil, nil, fmt.Errorf("phrase did not encode a version")
	}
	info := km.versions.Words[version]
	hash := sha256.New()
	for i := range corrected {
		hash.Write([]byte(corrected[i] + ":"))
	}
	reader := makeFortunaReader(hash.Sum(nil))
	dk, err = MakeDualKey(reader, info.KeyBits)
	if err != nil {
		return nil, nil, err
	}
	return dk, corrected, nil
}
