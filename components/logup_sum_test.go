package components

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var (
	testLogupSumQM31         = m31.NewQM31Unchecked(138003185, 504981591, 1541318630, 538197314)
	logupSumClaim            variables.CairoClaim
	logupSumInteractionClaim variables.CairoInteractionClaim
	logupSumCircuitData      variables.CircuitData
)

// ╔══════════════════════════════════╗
// ║         Logup Sum Test           ║
// ╚══════════════════════════════════╝

type logupSumCircuit struct{}

func (c *logupSumCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	sum := LogupSum(qm31Chip, logupSumClaim, dummyInteractionLookupElements(qm31Chip), logupSumInteractionClaim, logupSumCircuitData)
	qm31Chip.AssertEqual(sum, testLogupSumQM31)
	return nil
}

func TestLogupSum(t *testing.T) {
	assert := test.NewAssert(t)
	raw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponentsHintsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	proof := variables.BuildProof(*raw)
	logupSumCircuitData = variables.BuildCircuitData(raw)
	logupSumClaim = proof.Claim
	logupSumInteractionClaim = proof.InteractionClaim

	circuit := &logupSumCircuit{}
	witness := &logupSumCircuit{}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// Creates dummy interaction elements for the logup sum circuit following dummy values in:
// https://github.com/starkware-libs/stwo-cairo/blob/62c3c4a94546b274d20123cc5f22044bcbe7104e/stwo_cairo_verifier/crates/cairo_air/src/lib.cairo#L6135
func dummyInteractionLookupElements(qm31Chip *m31.QM31Chip) variables.CairoInteractionElements {
	return variables.CairoInteractionElements{
		Opcodes:                     qm31Chip.DummyInteractionElements(3),
		VerifyInstruction:           qm31Chip.DummyInteractionElements(7),
		BlakeRound:                  qm31Chip.DummyInteractionElements(35),
		BlakeG:                      qm31Chip.DummyInteractionElements(20),
		BlakeRoundSigma:             qm31Chip.DummyInteractionElements(17),
		TripleXor32:                 qm31Chip.DummyInteractionElements(8),
		PartialEcMul:                qm31Chip.DummyInteractionElements(73),
		PedersenPointsTable:         qm31Chip.DummyInteractionElements(57),
		PoseidonFullRoundChain:      qm31Chip.DummyInteractionElements(32),
		Poseidon3PartialRoundsChain: qm31Chip.DummyInteractionElements(42),
		Cube252:                     qm31Chip.DummyInteractionElements(20),
		PoseidonRoundKeys:           qm31Chip.DummyInteractionElements(31),
		RangeCheckFelt252Width27:    qm31Chip.DummyInteractionElements(10),
		MemoryAddressToID:           qm31Chip.DummyInteractionElements(2),
		MemoryIDToValue:             qm31Chip.DummyInteractionElements(29),
		RangeChecks: variables.RangeChecksInteractionElements{
			RC6:     qm31Chip.DummyInteractionElements(1),
			RC8:     qm31Chip.DummyInteractionElements(1),
			RC11:    qm31Chip.DummyInteractionElements(1),
			RC12:    qm31Chip.DummyInteractionElements(1),
			RC18:    qm31Chip.DummyInteractionElements(1),
			RC19:    qm31Chip.DummyInteractionElements(1),
			RC43:    qm31Chip.DummyInteractionElements(2),
			RC44:    qm31Chip.DummyInteractionElements(2),
			RC54:    qm31Chip.DummyInteractionElements(2),
			RC99:    qm31Chip.DummyInteractionElements(2),
			RC725:   qm31Chip.DummyInteractionElements(3),
			RC3663:  qm31Chip.DummyInteractionElements(4),
			RC4444:  qm31Chip.DummyInteractionElements(4),
			RC33333: qm31Chip.DummyInteractionElements(5),
		},
		VerifyBitwiseXor4:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor7:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor8:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor9:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor12: qm31Chip.DummyInteractionElements(3),
	}
}
