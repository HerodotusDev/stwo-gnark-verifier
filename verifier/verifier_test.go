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
	Proof       variables.Proof       `gnark:",public"`
	circuitData variables.CircuitData `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := NewVerifierChip(api)
	verifierChip.Verify(c.Proof, fri.DefaultPcsConfig(), c.circuitData)

	return nil
}

func TestVerifier(t *testing.T) {
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponentsHintsProofFixture))
	if err != nil {
		fmt.Println("Error in reading proof:", err)
		os.Exit(1)
	}
	shapeRaw, err := variables.ReadCircuitShape(variables.ShapeFixturePath(variables.AllComponentsHintsProofFixture))
	if err != nil {
		fmt.Println("Error in reading circuit shape:", err)
		os.Exit(1)
	}

	cairoProof := variables.BuildProof(*cairoProofRaw)
	circuitData := variables.BuildCircuitData(shapeRaw)

	witness := VerifierCircuit{
		Proof:       cairoProof,
		circuitData: circuitData,
	}
	circuit := VerifierCircuit{
		Proof:       cairoProof,
		circuitData: circuitData,
	}
	assert := test.NewAssert(t)

	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&witness),
		test.WithCurves(ecc.BN254),
	)
}
