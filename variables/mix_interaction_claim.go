package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

// MixInto absorbs the Cairo interaction claim into the transcript channel.
func (claim CairoInteractionClaim) MixInto(ch *channel.Channel, circuitData CircuitData) {

	// Mix opcodes
	if circuitData.ComponentConfig[0] {
		ch.MixFelts([]m31.QM31{claim.Add.ClaimedSum})
	}
	if circuitData.ComponentConfig[1] {
		ch.MixFelts([]m31.QM31{claim.AddSmall.ClaimedSum})
	}
	if circuitData.ComponentConfig[2] {
		ch.MixFelts([]m31.QM31{claim.AddAp.ClaimedSum})
	}
	if circuitData.ComponentConfig[3] {
		ch.MixFelts([]m31.QM31{claim.AssertEq.ClaimedSum})
	}
	if circuitData.ComponentConfig[4] {
		ch.MixFelts([]m31.QM31{claim.AssertEqImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[5] {
		ch.MixFelts([]m31.QM31{claim.AssertEqDoubleDeref.ClaimedSum})
	}
	if circuitData.ComponentConfig[6] {
		ch.MixFelts([]m31.QM31{claim.Blake.ClaimedSum})
	}
	if circuitData.ComponentConfig[7] {
		ch.MixFelts([]m31.QM31{claim.Call.ClaimedSum})
	}
	if circuitData.ComponentConfig[8] {
		ch.MixFelts([]m31.QM31{claim.CallRelImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[9] {
		ch.MixFelts([]m31.QM31{claim.Generic.ClaimedSum})
	}
	if circuitData.ComponentConfig[10] {
		ch.MixFelts([]m31.QM31{claim.Jnz.ClaimedSum})
	}
	if circuitData.ComponentConfig[11] {
		ch.MixFelts([]m31.QM31{claim.JnzTaken.ClaimedSum})
	}
	if circuitData.ComponentConfig[12] {
		ch.MixFelts([]m31.QM31{claim.Jump.ClaimedSum})
	}
	if circuitData.ComponentConfig[13] {
		ch.MixFelts([]m31.QM31{claim.JumpDoubleDeref.ClaimedSum})
	}
	if circuitData.ComponentConfig[14] {
		ch.MixFelts([]m31.QM31{claim.JumpRel.ClaimedSum})
	}
	if circuitData.ComponentConfig[15] {
		ch.MixFelts([]m31.QM31{claim.JumpRelImm.ClaimedSum})
	}
	if circuitData.ComponentConfig[16] {
		ch.MixFelts([]m31.QM31{claim.Mul.ClaimedSum})
	}
	if circuitData.ComponentConfig[17] {
		ch.MixFelts([]m31.QM31{claim.MulSmall.ClaimedSum})
	}
	if circuitData.ComponentConfig[18] {
		ch.MixFelts([]m31.QM31{claim.Qm31.ClaimedSum})
	}
	if circuitData.ComponentConfig[19] {
		ch.MixFelts([]m31.QM31{claim.Ret.ClaimedSum})
	}

	// Mix verify instruction
	if circuitData.ComponentConfig[20] {
		ch.MixFelts([]m31.QM31{claim.VerifyInstruction.ClaimedSum})
	}

	// Mix Blake context
	if circuitData.ComponentConfig[21] {
		ch.MixFelts([]m31.QM31{claim.BlakeRound.ClaimedSum})
	}
	if circuitData.ComponentConfig[22] {
		ch.MixFelts([]m31.QM31{claim.BlakeG.ClaimedSum})
	}
	if circuitData.ComponentConfig[23] {
		ch.MixFelts([]m31.QM31{claim.BlakeRoundSigma.ClaimedSum})
	}
	if circuitData.ComponentConfig[24] {
		ch.MixFelts([]m31.QM31{claim.TripleXor32.ClaimedSum})
	}
	if circuitData.ComponentConfig[25] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor12.ClaimedSum})
	}

	// Mix builtins
	if circuitData.ComponentConfig[26] {
		ch.MixFelts([]m31.QM31{claim.AddModBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[27] {
		ch.MixFelts([]m31.QM31{claim.BitwiseBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[28] {
		ch.MixFelts([]m31.QM31{claim.MulModBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[29] {
		ch.MixFelts([]m31.QM31{claim.PedersenBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[30] {
		ch.MixFelts([]m31.QM31{claim.PoseidonBuiltin.ClaimedSum})
	}
	if circuitData.ComponentConfig[31] {
		ch.MixFelts([]m31.QM31{claim.RangeCheck96.ClaimedSum})
	}
	if circuitData.ComponentConfig[32] {
		ch.MixFelts([]m31.QM31{claim.RangeCheck128.ClaimedSum})
	}

	// Mix pedersen context
	if circuitData.ComponentConfig[33] {
		ch.MixFelts([]m31.QM31{claim.PartialEcMul.ClaimedSum})
	}
	if circuitData.ComponentConfig[34] {
		ch.MixFelts([]m31.QM31{claim.PedersenPointsTable.ClaimedSum})
	}

	// Mix poseidon context
	if circuitData.ComponentConfig[35] {
		ch.MixFelts([]m31.QM31{claim.Poseidon3PartialRoundsChain.ClaimedSum})
	}
	if circuitData.ComponentConfig[36] {
		ch.MixFelts([]m31.QM31{claim.PoseidonFullRoundChain.ClaimedSum})
	}
	if circuitData.ComponentConfig[37] {
		ch.MixFelts([]m31.QM31{claim.Cube252.ClaimedSum})
	}
	if circuitData.ComponentConfig[38] {
		ch.MixFelts([]m31.QM31{claim.PoseidonRoundKeys.ClaimedSum})
	}
	if circuitData.ComponentConfig[39] {
		ch.MixFelts([]m31.QM31{claim.RangeCheckFelt252Width27.ClaimedSum})
	}

	// Mix memory components
	if circuitData.ComponentConfig[40] {
		ch.MixFelts([]m31.QM31{claim.MemoryAddressToID.ClaimedSum})
	}
	if circuitData.ComponentConfig[41] {
		ch.MixFelts([]m31.QM31{claim.MemoryIDToBigBig.ClaimedSum})
	}
	if circuitData.ComponentConfig[42] {
		ch.MixFelts([]m31.QM31{claim.MemoryIDToBigSmall.ClaimedSum})
	}

	// Mix range checks
	if circuitData.ComponentConfig[43] {
		ch.MixFelts([]m31.QM31{claim.RC6.ClaimedSum})
	}
	if circuitData.ComponentConfig[44] {
		ch.MixFelts([]m31.QM31{claim.RC8.ClaimedSum})
	}
	if circuitData.ComponentConfig[45] {
		ch.MixFelts([]m31.QM31{claim.RC11.ClaimedSum})
	}
	if circuitData.ComponentConfig[46] {
		ch.MixFelts([]m31.QM31{claim.RC12.ClaimedSum})
	}
	if circuitData.ComponentConfig[47] {
		ch.MixFelts([]m31.QM31{claim.RC18.ClaimedSum})
	}
	if circuitData.ComponentConfig[48] {
		ch.MixFelts([]m31.QM31{claim.RC19.ClaimedSum})
	}
	if circuitData.ComponentConfig[49] {
		ch.MixFelts([]m31.QM31{claim.RC43.ClaimedSum})
	}
	if circuitData.ComponentConfig[50] {
		ch.MixFelts([]m31.QM31{claim.RC44.ClaimedSum})
	}
	if circuitData.ComponentConfig[51] {
		ch.MixFelts([]m31.QM31{claim.RC54.ClaimedSum})
	}
	if circuitData.ComponentConfig[52] {
		ch.MixFelts([]m31.QM31{claim.RC99.ClaimedSum})
	}
	if circuitData.ComponentConfig[53] {
		ch.MixFelts([]m31.QM31{claim.RC725.ClaimedSum})
	}
	if circuitData.ComponentConfig[54] {
		ch.MixFelts([]m31.QM31{claim.RC3663.ClaimedSum})
	}
	if circuitData.ComponentConfig[55] {
		ch.MixFelts([]m31.QM31{claim.RC4444.ClaimedSum})
	}
	if circuitData.ComponentConfig[56] {
		ch.MixFelts([]m31.QM31{claim.RC33333.ClaimedSum})
	}

	// Mix verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor4.ClaimedSum})
	}
	if circuitData.ComponentConfig[58] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor7.ClaimedSum})
	}
	if circuitData.ComponentConfig[59] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor8.ClaimedSum})
	}
	if circuitData.ComponentConfig[60] {
		ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor9.ClaimedSum})
	}
}
