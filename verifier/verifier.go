package verifier

import (
	"github.com/consensys/gnark/frontend"
)

type VerifierChip struct {
	api frontend.API `gnark:"-"`
}

func NewVerifierChip(api frontend.API) *VerifierChip {
	return &VerifierChip{
		api: api,
	}
}

func (c *VerifierChip) Verify() {

}
