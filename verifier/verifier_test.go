package verifier

import (
	"fmt"
	"os"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type VerifierCircuit struct {
	proof       variables.Proof       `gnark:"-"`
	circuitData variables.CircuitData `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api)
	verifierChip.Verify(c.proof, fri.DefaultPcsConfig(), c.circuitData)

	return nil
}

func TestVerifier(t *testing.T) {
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponentsHintsProofFixture))
	if err != nil {
		fmt.Println("Error in reading proof:", err)
		os.Exit(1)
	}

	cairoProof := variables.BuildProof(*cairoProofRaw)
	circuitData := variables.BuildCircuitData(cairoProofRaw)
	witness := VerifierCircuit{
		proof:       cairoProof,
		circuitData: circuitData,
	}
	circuit := VerifierCircuit{
		proof:       cairoProof,
		circuitData: circuitData,
	}
	assert := test.NewAssert(t)

	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254),
	)
}
