package components

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

var (
	testPublicData        = buildTestPublicData()
	testPublicDataSumQM31 = m31.NewQM31(971792689, 636659210, 1237675822, 245392094)
	testLogupSumQM31      = m31.NewQM31(1114783544, 427659254, 2083455222, 465542323)
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

	assert.ProverSucceeded(circuit, witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
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
	dummy := func(count int) m31.InteractionElements {
		z := m31.NewQM31(1, 2, 3, 4)
		alpha := m31.NewQM31(1, 0, 0, 0)
		powers := make([]m31.QM31, count)
		for i := range powers {
			powers[i] = alpha
		}
		return qm31Chip.NewInteractionElements(z, alpha, powers)
	}

	return variables.CairoInteractionElements{
		Opcodes:                     dummy(3),
		VerifyInstruction:           dummy(7),
		BlakeRound:                  dummy(35),
		BlakeG:                      dummy(20),
		BlakeRoundSigma:             dummy(17),
		TripleXor32:                 dummy(8),
		PartialEcMul:                dummy(73),
		PedersenPointsTable:         dummy(57),
		PoseidonFullRoundChain:      dummy(32),
		Poseidon3PartialRoundsChain: dummy(42),
		Cube252:                     dummy(20),
		PoseidonRoundKeys:           dummy(31),
		RangeCheckFelt252Width27:    dummy(10),
		MemoryAddressToId:           dummy(2),
		MemoryIDToValue:             dummy(29),
		RangeChecks: variables.RangeChecksInteractionElements{
			RC6:         dummy(1),
			RC8:         dummy(1),
			RC1_1:       dummy(1),
			RC1_2:       dummy(1),
			RC1_8:       dummy(1),
			RC1_9:       dummy(1),
			RC4_3:       dummy(2),
			RC4_4:       dummy(2),
			RC5_4:       dummy(2),
			RC9_9:       dummy(2),
			RC7_2_5:     dummy(3),
			RC3_6_6_3:   dummy(4),
			RC4_4_4_4:   dummy(4),
			RC3_3_3_3_3: dummy(5),
		},
		VerifyBitwiseXor4:  dummy(3),
		VerifyBitwiseXor7:  dummy(3),
		VerifyBitwiseXor8:  dummy(3),
		VerifyBitwiseXor9:  dummy(3),
		VerifyBitwiseXor12: dummy(3),
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

	err = test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("test is solved: %v", err)
	}
}
