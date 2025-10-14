package components

import (
	"fmt"
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type componentsEvaluateCircuit struct{}

func (c *componentsEvaluateCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	interactionElements := variables.CairoInteractionElements{
		MemoryAddressToId: m31.DummyInteractionElements(2),
	}
	claim := variables.CairoClaim{
		MemoryAddressToId: 4,
	}
	interactionClaim := variables.CairoInteractionClaim{
		MemoryAddressToId: qm31Chip.Zero(),
	}
	oodsPoint := qm31Chip.One()

	component := NewComponents(api, qm31Chip, interactionElements, claim, interactionClaim, oodsPoint)
	sampledValues := dummySampledValues(qm31Chip)
	randomCoeff := qm31Chip.One()

	result := component.Evaluate(sampledValues, randomCoeff)
	qm31Chip.AssertEqual(result, qm31Chip.Zero())
	return nil
}

func dummySampledValues(qm31Chip *m31.QM31Chip) [][][]m31.QM31 {
	// Layout mirrors the slices consumed inside MemoryAddressToIdComponent.Evaluate.
	sampledValues := make([][][]m31.QM31, variables.CP_IDX+1)

	main := make([][]m31.QM31, 16)
	interaction := make([][]m31.QM31, 16)
	zero := qm31Chip.Zero()

	for i := range main {
		main[i] = []m31.QM31{zero}
	}
	for i := range interaction {
		if i >= 12 {
			interaction[i] = []m31.QM31{zero, zero}
			continue
		}
		interaction[i] = []m31.QM31{zero}
	}

	sampledValues[variables.MAIN_IDX] = main
	sampledValues[variables.INTERACTION_IDX] = interaction
	return sampledValues
}

func TestComponentsEvaluateCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &componentsEvaluateCircuit{}
	witness := &componentsEvaluateCircuit{}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	count := cs.GetNbConstraints()
	fmt.Printf("TestComponentsEvaluateCircuit constraints: %d\n", count)

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}
