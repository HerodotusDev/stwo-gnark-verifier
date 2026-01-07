package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var zero = uints.NewU8(0)

var feltChunkMasks = [BitsPerM31 + 1]uints.U32{
	uints.NewU32(0),
	uints.NewU32(1),
	uints.NewU32(3),
	uints.NewU32(7),
	uints.NewU32(15),
	uints.NewU32(31),
	uints.NewU32(63),
	uints.NewU32(127),
	uints.NewU32(255),
	uints.NewU32(511),
}

// MixInto absorbs the Cairo claim into the transcript channel.
func (claim CairoClaim) MixInto(ch *channel.Channel, api frontend.API, circuitData CircuitData) {
	// Used for uint conversions (M31, frontend.Variable, u32, u64, etc.)
	// TODO: for each new api, a lookup table is created so it would be better to have a unique uapi over the entire verifier circuit
	uapi32, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	uapi64, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}

	// Mix public data
	claim.PublicData.mixInto(ch, uapi32, uapi64, circuitData)

	// Mix opcodes
	if circuitData.ComponentConfig[0] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Add.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[1] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddSmall.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[2] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddAp.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[3] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEq.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[4] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEqImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[5] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AssertEqDoubleDeref.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[6] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Blake.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[7] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Call.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[8] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.CallRelImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[9] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Generic.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[10] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Jnz.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[11] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JnzTaken.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[12] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Jump.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[13] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpDoubleDeref.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[14] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpRel.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[15] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.JumpRelImm.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[16] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Mul.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[17] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulSmall.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[18] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Qm31.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}
	if circuitData.ComponentConfig[19] {
		ch.MixU64(uints.NewU64(1))
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Ret.LogSize), uints.NewU32(0)})
	} else {
		ch.MixU64(uints.NewU64(0))
	}

	// Mix verify instruction
	if circuitData.ComponentConfig[20] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.VerifyInstruction.LogSize), uints.NewU32(0)})
	}

	// Mix Blake context
	if circuitData.ComponentConfig[21] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BlakeRound.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[22] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BlakeG.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[24] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.TripleXor32.LogSize), uints.NewU32(0)})
	}

	// Mix builtins
	if circuitData.ComponentConfig[26] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddModBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.AddModBuiltin.AddModBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[27] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BitwiseBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.BitwiseBuiltin.BitwiseBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[28] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulModBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MulModBuiltin.MulModBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[29] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PedersenBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PedersenBuiltin.PedersenBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[30] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonBuiltin.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonBuiltin.PoseidonBuiltinSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[31] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck96.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck96.RangeCheckSegmentStart), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[32] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck128.LogSize), uints.NewU32(0)})
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheck128.RangeCheckSegmentStart), uints.NewU32(0)})
	}

	// Mix pedersen context
	if circuitData.ComponentConfig[33] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PartialEcMul.LogSize), uints.NewU32(0)})
	}

	// Mix poseidon context
	if circuitData.ComponentConfig[35] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Poseidon3PartialRoundsChain.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[36] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.PoseidonFullRoundChain.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[37] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.Cube252.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[39] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.RangeCheckFelt252Width27.LogSize), uints.NewU32(0)})
	}

	// Mix memory components
	if circuitData.ComponentConfig[40] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryAddressToID.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[41] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryIDToBigBig.LogSize), uints.NewU32(0)})
	}
	if circuitData.ComponentConfig[42] {
		ch.MixU32s([]uints.U32{uapi32.ValueOf(claim.MemoryIDToBigSmall.LogSize), uints.NewU32(0)})
	}

	// Mix range checks (never mixed)

	// Mix verify bitwise XOR components (same as RC)
}

// ╔══════════════════════════════════╗
// ║            Public Data           ║
// ╚══════════════════════════════════╝

func (data PublicData) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64], circuitData CircuitData) {
	data.PublicMemory.mixInto(ch, uapi32, uapi64, circuitData)
	data.InitialState.mixInto(ch, uapi64)
	data.FinalState.mixInto(ch, uapi64)
}

func (memory PublicMemory) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64], circuitData CircuitData) {
	memory.PublicSegments.mixInto(ch, uapi32, uapi64, circuitData)

	var outputWords []uints.U32
	for _, entry := range memory.Output {
		entryWords := feltValueToU32Words(entry.Value, uapi32)
		for _, word := range entryWords {
			outputWords = append(outputWords, word)
		}
	}
	ch.MixU32s(outputWords)

	ch.MixU64(uints.NewU64(2))
	for _, entry := range memory.SafeCall {
		ch.MixU64(uapi64.ValueOf(entry.ID.Limb))
		entryWords := feltValueToU32Words(entry.Value, uapi32)
		for _, word := range entryWords {
			ch.MixU64(uints.U64{word[0], word[1], word[2], word[3], zero, zero, zero, zero})
		}
	}
}

func (ranges PublicSegmentRanges) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64], circuitData CircuitData) {
	ranges.Output.mixInto(ch, uapi32, uapi64)
	if ranges.Pedersen != nil {
		ranges.Pedersen.mixInto(ch, uapi32, uapi64)
	}
	if ranges.RangeCheck128 != nil {
		ranges.RangeCheck128.mixInto(ch, uapi32, uapi64)
	}
	if ranges.Ecdsa != nil {
		ranges.Ecdsa.mixInto(ch, uapi32, uapi64)
	}
	if ranges.Bitwise != nil {
		ranges.Bitwise.mixInto(ch, uapi32, uapi64)
	}
	if ranges.EcOp != nil {
		ranges.EcOp.mixInto(ch, uapi32, uapi64)
	}
	if ranges.Keccak != nil {
		ranges.Keccak.mixInto(ch, uapi32, uapi64)
	}
	if ranges.Poseidon != nil {
		ranges.Poseidon.mixInto(ch, uapi32, uapi64)
	}
	if ranges.RangeCheck96 != nil {
		ranges.RangeCheck96.mixInto(ch, uapi32, uapi64)
	}
	if ranges.AddMod != nil {
		ranges.AddMod.mixInto(ch, uapi32, uapi64)
	}
	if ranges.MulMod != nil {
		ranges.MulMod.mixInto(ch, uapi32, uapi64)
	}
}

func (segment SegmentRange) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	segment.StartPtr.mixInto(ch, uapi32, uapi64)
	segment.StopPtr.mixInto(ch, uapi32, uapi64)
}

func (pointer SegmentPointer) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	ch.MixU64(uapi64.ValueOf(pointer.ID.Limb))
	valueU32 := feltValueToU32Words(pointer.Value, uapi32)[0]
	valueU64 := uints.U64{valueU32[0], valueU32[1], valueU32[2], valueU32[3], zero, zero, zero, zero}
	ch.MixU64(valueU64)
}

func (state CasmState) mixInto(ch *channel.Channel, uapi64 *uints.BinaryField[uints.U64]) {
	ch.MixU64(uapi64.ValueOf(state.PC.Limb))
	ch.MixU64(uapi64.ValueOf(state.AP.Limb))
	ch.MixU64(uapi64.ValueOf(state.FP.Limb))
}

// ╔══════════════════════════════════╗
// ║             Helpers              ║
// ╚══════════════════════════════════╝

func feltValueToU32Words(value Felt252Value, uapi32 *uints.BinaryField[uints.U32]) [8]uints.U32 {
	const bitsPerWord = 32

	var words [8]uints.U32
	current := uints.NewU32(0)
	bitsFilled := 0
	wordIdx := 0
	limbMask := feltChunkMasks[BitsPerM31]

	for i := 0; i < NM31InFelt252 && wordIdx < len(words); i++ {
		limb := uapi32.And(uapi32.ValueOf(value[i].Limb), limbMask)
		bitsLeft := BitsPerM31
		offset := 0

		for bitsLeft > 0 && wordIdx < len(words) {
			room := bitsPerWord - bitsFilled
			take := bitsLeft
			if take > room {
				take = room
			}

			chunk := limb
			if offset != 0 {
				chunk = uapi32.Rshift(limb, offset)
			}
			chunk = uapi32.And(chunk, feltChunkMasks[take])
			if bitsFilled != 0 {
				chunk = uapi32.Lrot(chunk, bitsFilled)
			}

			current = uapi32.Add(current, chunk)

			bitsLeft -= take
			offset += take
			bitsFilled += take

			if bitsFilled == bitsPerWord {
				words[wordIdx] = current
				wordIdx++
				current = uints.NewU32(0)
				bitsFilled = 0
			}
		}
	}

	if bitsFilled > 0 && wordIdx < len(words) {
		words[wordIdx] = current
	}

	return words
}
