package variables

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type interactionElementsCircuit struct{}

func (c *interactionElementsCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	channelChip := channel.NewChannel(api)

	var cairoInteractionElements CairoInteractionElements
	cairoInteractionElements.Draw(channelChip, qm31Chip)

	// Test value for last draw from reference rust verifier implementation
	expectedLastAlphaPower := m31.NewQM31(531627891, 1021520239, 943124418, 505435657)
	qm31Chip.AssertEqual(cairoInteractionElements.VerifyBitwiseXor12.LastAlphaPower(), expectedLastAlphaPower)
	return nil
}

func TestInteractionElements(t *testing.T){
	assert := test.NewAssert(t)

	circuit := &interactionElementsCircuit{}
	witness := &interactionElementsCircuit{}

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}
