package crypto

import (
	"encoding/json"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

func Sign(object interface{}, signer jose.Signer) (string, error) {
	payload, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return SignPayload(payload, signer)
}

func SignPayload(payload []byte, signer jose.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("missing signer")
	}
	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return result.CompactSerialize()
}
