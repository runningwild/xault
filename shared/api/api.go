package api

import "github.com/runningwild/xault/shared/phone/xault/xcrypt"

type MakeIdRequest struct {
	Id   string
	Keys *xcrypt.DualPublicKey
}

type MakeIdChallenge struct {
	EncryptedChallenge []byte
}

type MakeIdChallengeResponse struct {
	Id              string
	SignedChallenge []byte
}

type MakeIdResponse struct {
}
