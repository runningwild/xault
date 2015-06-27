package xcrypt

import (
	"testing"

	"github.com/runningwild/cmwc"
	. "github.com/smartystreets/goconvey/convey"
)

func TestKeyMaker(t *testing.T) {
	c := cmwc.MakeGoodCmwc()
	c.Seed(123456789)

	Convey("each generated key and phrase is different", t, func() {
		km, err := MakeKeyMaker("words.txt", "versions_test.txt")
		So(err, ShouldBeNil)
		So(km, ShouldNotBeNil)
		var keys []*DualKey
		var phrases [][]string
		for i := 0; i < 3; i++ {
			key, phrase, err := km.GenerateKeyAndPhrase(c, 128)
			So(err, ShouldBeNil)
			So(key, ShouldNotBeNil)
			So(phrase, ShouldNotBeNil)
			So(len(phrase), ShouldBeGreaterThanOrEqualTo, 10)
			keys = append(keys, key)
			phrases = append(phrases, phrase)
		}
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				So(keys[i].String(), ShouldNotEqual, keys[j].String())
				So(phrases[i], ShouldNotResemble, phrases[j])
			}
		}
		Convey("phrases can be used to regenerate the original key", func() {
			for i := range phrases {
				key, corrected, err := km.RegenerateKeyFromPhrase(phrases[i])
				So(err, ShouldBeNil)
				So(corrected, ShouldResemble, phrases[i])
				So(key.String(), ShouldEqual, keys[i].String())
			}
		})
		Convey("phrases can have minor errors and still revenerate the original key", func() {
			for i := range phrases {
				phrase := make([]string, len(phrases[i]))
				copy(phrase, phrases[i])
				for j := range phrase {
					word := []byte(phrase[j])
					if c.Int63()%2 == 0 {
						word[int(c.Int63())%len(word)]++
					} else {
						swap := int(c.Int63()) % (len(word) - 1)
						word[swap], word[swap+1] = word[swap+1], word[swap]
					}
					phrase[j] = string(word)
				}
				key, corrected, err := km.RegenerateKeyFromPhrase(phrase)
				So(err, ShouldBeNil)
				So(key.String(), ShouldEqual, keys[i].String())
				So(corrected, ShouldResemble, phrases[i])
			}
		})
	})
}
