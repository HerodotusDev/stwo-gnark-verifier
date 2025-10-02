package verifier

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api         frontend.API `gnark:"-"`
	blake2sChip *blake2s.Blake2sChip
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	blake2sChip := blake2s.NewBlake2sChip(api)
	return &VerifierChip{
		api:         api,
		blake2sChip: blake2sChip,
	}
}

func (c *VerifierChip) Verify() {

}
