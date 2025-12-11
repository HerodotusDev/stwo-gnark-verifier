package variables

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// ╔══════════════════════════════════╗
// ║       Interaction Elements       ║
// ╚══════════════════════════════════╝

type interactionElementsCircuit struct{}

func (c *interactionElementsCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	channelChip := channel.NewChannel(api)

	var cairoInteractionElements CairoInteractionElements
	cairoInteractionElements.Draw(channelChip, qm31Chip)

	// Test value for last draw from reference rust verifier implementation
	expectedLastAlphaPower := m31.NewQM31Unchecked(531627891, 1021520239, 943124418, 505435657)
	qm31Chip.AssertEqual(cairoInteractionElements.VerifyBitwiseXor12.LastAlphaPower(), expectedLastAlphaPower)
	return nil
}

// TestInteractionElements checks that the interaction elements are correctly drawn by checking the last alpha power.
func TestInteractionElements(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &interactionElementsCircuit{}
	witness := &interactionElementsCircuit{}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// ╔══════════════════════════════════╗
// ║          Deserialization         ║
// ╚══════════════════════════════════╝

// TestReadHDPProof tests that the HDP proof can be read.
func TestReadHDPProof(t *testing.T) {
	_, err := ReadCairoProof(ProofFixturePath(HdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}
}

// TestReadAllComponentsHintsProof tests that the all components hints proof can be read.
func TestReadAllComponentsHintsProof(t *testing.T) {
	_, err := ReadCairoProof(ProofFixturePath(AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}
}

// TestBuildProofHDP tests that the HDP proof and shape can be built.
func TestBuildProofHDP(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(HdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}
	shape, err := ReadCircuitShape(ShapeFixturePath(HdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read shape: %v", err)
	}

	_ = BuildProof(*raw)
	_ = BuildCircuitData(shape)
}

// TestBuildProofAllComponentsHints tests that the all components hints proof and shape can be built.
func TestBuildProofAllComponentsHints(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}
	shape, err := ReadCircuitShape(ShapeFixturePath(AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read shape: %v", err)
	}

	_ = BuildProof(*raw)
	_ = BuildCircuitData(shape)
}
