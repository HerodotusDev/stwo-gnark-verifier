package components

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type dummyLogupSumCircuit struct{}

func (c *dummyLogupSumCircuit) Define(api frontend.API) error {
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)

	one := qm31Chip.One()

	interactionClaim := variables.CairoInteractionClaim{
		Opcodes: variables.OpcodeInteractionClaim{
			Add: []cairo_components.AddOpcodeInteractionClaim{{ClaimedSum: one}},
			Mul: []cairo_components.MulOpcodeInteractionClaim{{ClaimedSum: one}},
		},
		VerifyInstruction: cairo_components.VerifyInstructionInteractionClaim{ClaimedSum: one},
		BlakeContext: variables.BlakeContextInteractionClaim{
			InteractionClaim: &variables.BlakeInteractionClaim{
				BlakeRound: cairo_components.BlakeRoundInteractionClaim{ClaimedSum: one},
			},
		},
		Builtins: variables.BuiltinsInteractionClaim{
			AddModBuiltin: &cairo_components.AddModBuiltinInteractionClaim{ClaimedSum: one},
		},
		PedersenContext: variables.PedersenContextInteractionClaim{
			InteractionClaim: &variables.PedersenInteractionClaim{
				PartialEcMul: cairo_components.PartialEcMulInteractionClaim{ClaimedSum: one},
			},
		},
		PoseidonContext: variables.PoseidonContextInteractionClaim{
			InteractionClaim: &variables.PoseidonInteractionClaim{
				PoseidonFullRoundChain: cairo_components.PoseidonFullRoundChainInteractionClaim{ClaimedSum: one},
			},
		},
		MemoryAddressToId: cairo_components.MemoryAddressToIdInteractionClaim{ClaimedSum: one},
		MemoryIDToValue: cairo_components.MemoryIdToValueInteractionClaim{
			BigClaimedSums:  []m31.QM31{one},
			SmallClaimedSum: one,
		},
		RangeChecks: variables.RangeChecksInteractionClaim{
			RC6: cairo_components.RangeCheck6InteractionClaim{ClaimedSum: one},
		},
		VerifyBitwiseXor4: cairo_components.VerifyBitwiseXor4InteractionClaim{ClaimedSum: one},
		VerifyBitwiseXor7: cairo_components.VerifyBitwiseXor7InteractionClaim{ClaimedSum: one},
		VerifyBitwiseXor8: cairo_components.VerifyBitwiseXor8InteractionClaim{ClaimedSum: one},
		VerifyBitwiseXor9: cairo_components.VerifyBitwiseXor9InteractionClaim{ClaimedSum: one},
	}

	claim := variables.CairoClaim{}
	elements := variables.CairoInteractionElements{}

	total := LogupSum(qm31Chip, claim, elements, interactionClaim)

	expected := qm31Chip.Zero()
	contributions := []m31.QM31{
		one, // opcode add
		one, // opcode mul
		one, // verify instruction
		one, // blake round
		one, // builtin add_mod
		one, // pedersen partial ec mul
		one, // poseidon full round chain
		one, // memory address to id
		one, // memory id to value big
		one, // memory id to value small
		one, // range check rc6
		one, // verify xor 4
		one, // verify xor 7
		one, // verify xor 8
		one, // verify xor 9
	}

	for _, contrib := range contributions {
		expected = qm31Chip.Add(expected, contrib)
	}

	qm31Chip.AssertEqual(total, expected)
	return nil
}

func TestDummyLogupSumCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &dummyLogupSumCircuit{}
	witness := &dummyLogupSumCircuit{}

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
