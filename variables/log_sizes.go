package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
)

// LogSizes returns the per-tree column log sizes for the Cairo claim.
func (claim CairoClaim) LogSizes(circuitData CircuitData) cairo_components.TreeLogSizes {
	var parts []cairo_components.TreeLogSizes

	// Opcodes
	if circuitData.ComponentConfig[0] {
		parts = append(parts, claim.Add.LogSizes())
	}
	if circuitData.ComponentConfig[1] {
		parts = append(parts, claim.AddSmall.LogSizes())
	}
	if circuitData.ComponentConfig[2] {
		parts = append(parts, claim.AddAp.LogSizes())
	}
	if circuitData.ComponentConfig[3] {
		parts = append(parts, claim.AssertEq.LogSizes())
	}
	if circuitData.ComponentConfig[4] {
		parts = append(parts, claim.AssertEqImm.LogSizes())
	}
	if circuitData.ComponentConfig[5] {
		parts = append(parts, claim.AssertEqDoubleDeref.LogSizes())
	}
	if circuitData.ComponentConfig[6] {
		parts = append(parts, claim.Blake.LogSizes())
	}
	if circuitData.ComponentConfig[7] {
		parts = append(parts, claim.Call.LogSizes())
	}
	if circuitData.ComponentConfig[8] {
		parts = append(parts, claim.CallRelImm.LogSizes())
	}
	if circuitData.ComponentConfig[9] {
		parts = append(parts, claim.Generic.LogSizes())
	}
	if circuitData.ComponentConfig[10] {
		parts = append(parts, claim.Jnz.LogSizes())
	}
	if circuitData.ComponentConfig[11] {
		parts = append(parts, claim.JnzTaken.LogSizes())
	}
	if circuitData.ComponentConfig[12] {
		parts = append(parts, claim.Jump.LogSizes())
	}
	if circuitData.ComponentConfig[13] {
		parts = append(parts, claim.JumpDoubleDeref.LogSizes())
	}
	if circuitData.ComponentConfig[14] {
		parts = append(parts, claim.JumpRel.LogSizes())
	}
	if circuitData.ComponentConfig[15] {
		parts = append(parts, claim.JumpRelImm.LogSizes())
	}
	if circuitData.ComponentConfig[16] {
		parts = append(parts, claim.Mul.LogSizes())
	}
	if circuitData.ComponentConfig[17] {
		parts = append(parts, claim.MulSmall.LogSizes())
	}
	if circuitData.ComponentConfig[18] {
		parts = append(parts, claim.Qm31.LogSizes())
	}
	if circuitData.ComponentConfig[19] {
		parts = append(parts, claim.Ret.LogSizes())
	}

	// Verify instruction
	if circuitData.ComponentConfig[20] {
		parts = append(parts, claim.VerifyInstruction.LogSizes())
	}

	// Blake context
	if circuitData.ComponentConfig[21] {
		parts = append(parts, claim.BlakeRound.LogSizes())
	}
	if circuitData.ComponentConfig[22] {
		parts = append(parts, claim.BlakeG.LogSizes())
	}
	if circuitData.ComponentConfig[23] {
		parts = append(parts, claim.BlakeRoundSigma.LogSizes())
	}
	if circuitData.ComponentConfig[24] {
		parts = append(parts, claim.TripleXor32.LogSizes())
	}
	if circuitData.ComponentConfig[25] {
		parts = append(parts, claim.VerifyBitwiseXor12.LogSizes())
	}

	// Builtins
	if circuitData.ComponentConfig[26] {
		parts = append(parts, claim.AddModBuiltin.LogSizes())
	}
	if circuitData.ComponentConfig[27] {
		parts = append(parts, claim.BitwiseBuiltin.LogSizes())
	}
	if circuitData.ComponentConfig[28] {
		parts = append(parts, claim.MulModBuiltin.LogSizes())
	}
	if circuitData.ComponentConfig[29] {
		parts = append(parts, claim.PedersenBuiltin.LogSizes())
	}
	if circuitData.ComponentConfig[30] {
		parts = append(parts, claim.PoseidonBuiltin.LogSizes())
	}
	if circuitData.ComponentConfig[31] {
		parts = append(parts, claim.RangeCheck96.LogSizes())
	}
	if circuitData.ComponentConfig[32] {
		parts = append(parts, claim.RangeCheck128.LogSizes())
	}

	// Pedersen context
	if circuitData.ComponentConfig[33] {
		parts = append(parts, claim.PartialEcMul.LogSizes())
	}
	if circuitData.ComponentConfig[34] {
		parts = append(parts, claim.PedersenPointsTable.LogSizes())
	}

	// Poseidon context
	if circuitData.ComponentConfig[35] {
		parts = append(parts, claim.Poseidon3PartialRoundsChain.LogSizes())
	}
	if circuitData.ComponentConfig[36] {
		parts = append(parts, claim.PoseidonFullRoundChain.LogSizes())
	}
	if circuitData.ComponentConfig[37] {
		parts = append(parts, claim.Cube252.LogSizes())
	}
	if circuitData.ComponentConfig[38] {
		parts = append(parts, claim.PoseidonRoundKeys.LogSizes())
	}
	if circuitData.ComponentConfig[39] {
		parts = append(parts, claim.RangeCheckFelt252Width27.LogSizes())
	}

	// Memory relations
	if circuitData.ComponentConfig[40] {
		parts = append(parts, claim.MemoryAddressToID.LogSizes())
	}
	if circuitData.ComponentConfig[41] {
		parts = append(parts, claim.MemoryIDToBigBig.LogSizes())
	}
	if circuitData.ComponentConfig[42] {
		parts = append(parts, claim.MemoryIDToBigSmall.LogSizes())
	}

	// Range checks
	if circuitData.ComponentConfig[43] {
		parts = append(parts, claim.RC6.LogSizes())
	}
	if circuitData.ComponentConfig[44] {
		parts = append(parts, claim.RC8.LogSizes())
	}
	if circuitData.ComponentConfig[45] {
		parts = append(parts, claim.RC11.LogSizes())
	}
	if circuitData.ComponentConfig[46] {
		parts = append(parts, claim.RC12.LogSizes())
	}
	if circuitData.ComponentConfig[47] {
		parts = append(parts, claim.RC18.LogSizes())
	}
	if circuitData.ComponentConfig[48] {
		parts = append(parts, claim.RC19.LogSizes())
	}
	if circuitData.ComponentConfig[49] {
		parts = append(parts, claim.RC43.LogSizes())
	}
	if circuitData.ComponentConfig[50] {
		parts = append(parts, claim.RC44.LogSizes())
	}
	if circuitData.ComponentConfig[51] {
		parts = append(parts, claim.RC54.LogSizes())
	}
	if circuitData.ComponentConfig[52] {
		parts = append(parts, claim.RC99.LogSizes())
	}
	if circuitData.ComponentConfig[53] {
		parts = append(parts, claim.RC725.LogSizes())
	}
	if circuitData.ComponentConfig[54] {
		parts = append(parts, claim.RC3663.LogSizes())
	}
	if circuitData.ComponentConfig[55] {
		parts = append(parts, claim.RC4444.LogSizes())
	}
	if circuitData.ComponentConfig[56] {
		parts = append(parts, claim.RC33333.LogSizes())
	}

	// Verify bitwise XOR components
	if circuitData.ComponentConfig[57] {
		parts = append(parts, claim.VerifyBitwiseXor4.LogSizes())
	}
	if circuitData.ComponentConfig[58] {
		parts = append(parts, claim.VerifyBitwiseXor7.LogSizes())
	}
	if circuitData.ComponentConfig[59] {
		parts = append(parts, claim.VerifyBitwiseXor8.LogSizes())
	}
	if circuitData.ComponentConfig[60] {
		parts = append(parts, claim.VerifyBitwiseXor9.LogSizes())
	}

	return cairo_components.ConcatTreeLogSizes(parts...)
}
