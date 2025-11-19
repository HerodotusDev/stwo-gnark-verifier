package verifier

import (
	"fmt"
	"os"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type VerifierCircuit struct {
	proof variables.Proof `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api)
	verifierChip.Verify(c.proof)

	return nil
}

func TestCairoComponentAtomicEvaluations(t *testing.T) {
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.HdpProofFixture))
	if err != nil {
		fmt.Println("Error in reading proof:", err)
		os.Exit(1)
	}

	cairoProof := variables.BuildProof(cairoProofRaw)
	witness := VerifierCircuit{
		proof: *cairoProof,
	}
	circuit := VerifierCircuit{
		proof: *cairoProof,
	}
	assert := test.NewAssert(t)

	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254),
	)
}
