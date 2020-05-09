package e2eutil

import (
	"math/rand"
)

const letters = "abcdefghijklmnopqrstuvwxyz1234567890"

func MakeId() string {
	id := make([]byte, 8)
	for i := range id {
		id[i] = letters[rand.Intn(len(letters))]
	}

	return string(id)
}
