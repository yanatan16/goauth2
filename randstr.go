package goauth2

import (
	"crypto/sha1"
	"fmt"
	"time"
)

var RandStr <-chan string

func init() {
	RandStr = RandomStrings()
}

func RandomStrings() <-chan string {
	randstr := make(chan string, 0)
	go func() {
		hash := sha1.New()
		base := []byte(time.Now().String())
		for {
			hash.Write(base)
			randstr <- fmt.Sprintf("%x", hash.Sum(nil))
		}
	}()
	return randstr
}
