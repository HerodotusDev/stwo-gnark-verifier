package components

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

var (
	testPublicData        = buildTestPublicData()
	testPublicDataSumQM31 = m31.NewQM31Unchecked(971792689, 636659210, 1237675822, 245392094)
	testLogupSumQM31      = m31.NewQM31Unchecked(1114783544, 427659254, 2083455222, 465542323)
)

// ╔══════════════════════════════════╗
// ║         Public Data Logup        ║
// ╚══════════════════════════════════╝

type publicDataLogupSumCircuit struct{}

func (c *publicDataLogupSumCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	sum := publicDataLogupSum(qm31Chip, dummyInteractionLookupElements(qm31Chip), testPublicData)
	qm31Chip.AssertEqual(sum, testPublicDataSumQM31)
	return nil
}

func TestPublicDataLogupSum(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &publicDataLogupSumCircuit{}
	witness := &publicDataLogupSumCircuit{}

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// Builds the public data deserialized from:
// https://github.com/starkware-libs/stwo-cairo/blob/62c3c4a94546b274d20123cc5f22044bcbe7104e/stwo_cairo_verifier/crates/cairo_air/src/lib.cairo#L6042
func buildTestPublicData() variables.PublicData {
	segment := func(id, value uint32) variables.SegmentRange {
		return variables.SegmentRange{
			StartPtr: variables.SegmentPointer{ID: m31.NewM31Unchecked(id), Value: variables.SplitFeltWords([8]uint32{value, 0, 0, 0, 0, 0, 0, 0})},
			StopPtr:  variables.SegmentPointer{ID: m31.NewM31Unchecked(id), Value: variables.SplitFeltWords([8]uint32{value, 0, 0, 0, 0, 0, 0, 0})},
		}
	}

	segmentPtr := func(id, value uint32) *variables.SegmentRange {
		s := segment(id, value)
		return &s
	}

	felt := func(words ...uint32) variables.Felt252Value {
		var packed [8]uint32
		for i := 0; i < len(packed) && i < len(words); i++ {
			packed[i] = words[i]
		}
		return variables.SplitFeltWords(packed)
	}

	return variables.PublicData{
		PublicMemory: variables.PublicMemory{
			Program: nil,
			PublicSegments: variables.PublicSegmentRanges{
				Output:        segment(228, 2520),
				Pedersen:      segmentPtr(228, 2520),
				RangeCheck128: segmentPtr(228, 2520),
				Ecdsa:         segmentPtr(5, 0),
				Bitwise:       segmentPtr(228, 2520),
				EcOp:          segmentPtr(5, 0),
				Keccak:        segmentPtr(5, 0),
				Poseidon:      segmentPtr(228, 2520),
				RangeCheck96:  segmentPtr(228, 2520),
				AddMod:        segmentPtr(228, 2520),
				MulMod:        segmentPtr(228, 2520),
			},
			Output: nil,
			SafeCall: []variables.PubMemoryValue{
				{ID: m31.NewM31Unchecked(227), Value: felt(1336)},
				{ID: m31.NewM31Unchecked(5), Value: felt()},
			},
		},
		InitialState: variables.CasmState{
			PC: m31.NewM31Unchecked(1),
			AP: m31.NewM31Unchecked(1336),
			FP: m31.NewM31Unchecked(1336),
		},
		FinalState: variables.CasmState{
			PC: m31.NewM31Unchecked(5),
			AP: m31.NewM31Unchecked(2520),
			FP: m31.NewM31Unchecked(1336),
		},
	}
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
		MemoryAddressToId:           qm31Chip.DummyInteractionElements(2),
		MemoryIDToValue:             qm31Chip.DummyInteractionElements(29),
		RangeChecks: variables.RangeChecksInteractionElements{
			RC6:         qm31Chip.DummyInteractionElements(1),
			RC8:         qm31Chip.DummyInteractionElements(1),
			RC1_1:       qm31Chip.DummyInteractionElements(1),
			RC1_2:       qm31Chip.DummyInteractionElements(1),
			RC1_8:       qm31Chip.DummyInteractionElements(1),
			RC1_9:       qm31Chip.DummyInteractionElements(1),
			RC4_3:       qm31Chip.DummyInteractionElements(2),
			RC4_4:       qm31Chip.DummyInteractionElements(2),
			RC5_4:       qm31Chip.DummyInteractionElements(2),
			RC9_9:       qm31Chip.DummyInteractionElements(2),
			RC7_2_5:     qm31Chip.DummyInteractionElements(3),
			RC3_6_6_3:   qm31Chip.DummyInteractionElements(4),
			RC4_4_4_4:   qm31Chip.DummyInteractionElements(4),
			RC3_3_3_3_3: qm31Chip.DummyInteractionElements(5),
		},
		VerifyBitwiseXor4:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor7:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor8:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor9:  qm31Chip.DummyInteractionElements(3),
		VerifyBitwiseXor12: qm31Chip.DummyInteractionElements(3),
	}
}

// ╔══════════════════════════════════╗
// ║         Logup Sum Test           ║
// ╚══════════════════════════════════╝

type logupSumCircuit struct {
	Claim            variables.CairoClaim
	InteractionClaim variables.CairoInteractionClaim
}

func (c *logupSumCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	sum := LogupSum(qm31Chip, c.Claim, dummyInteractionLookupElements(qm31Chip), c.InteractionClaim)
	qm31Chip.AssertEqual(sum, testLogupSumQM31)
	return nil
}

func TestLogupSum(t *testing.T) {
	assert := test.NewAssert(t)
	raw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	proof := variables.BuildProof(raw)

	circuit := &logupSumCircuit{
		Claim:            proof.Claim,
		InteractionClaim: proof.InteractionClaim,
	}
	witness := &logupSumCircuit{
		Claim:            proof.Claim,
		InteractionClaim: proof.InteractionClaim,
	}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}
