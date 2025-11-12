package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var zero = uints.NewU8(0)

var feltChunkMasks = [BitsPerFelt252 + 1]uints.U32{
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
func (claim CairoClaim) MixInto(ch *channel.Channel, api frontend.API) {
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

	claim.PublicData.mixInto(ch, uapi32, uapi64)
	claim.Opcodes.mixInto(ch)
	if claim.VerifyInstruction != nil {
		ch.MixU64(uints.U64{claim.VerifyInstruction.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	claim.BlakeContext.mixInto(ch)
	claim.Builtins.mixInto(ch)
	if claim.PedersenContext.Claim != nil && claim.PedersenContext.Claim.PartialEcMul != nil {
		ch.MixU64(uints.U64{claim.PedersenContext.Claim.PartialEcMul.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	claim.PoseidonContext.mixInto(ch)
	ch.MixU64(uints.U64{claim.MemoryAddressToId.LogSize, zero, zero, zero, zero, zero, zero, zero})
	claim.MemoryIDToValue.mixInto(ch)
}

// ╔══════════════════════════════════╗
// ║            Public Data           ║
// ╚══════════════════════════════════╝

func (data PublicData) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	data.PublicMemory.mixInto(ch, uapi32, uapi64)
	data.InitialState.mixInto(ch, uapi64)
	data.FinalState.mixInto(ch, uapi64)
}

func (memory PublicMemory) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	memory.PublicSegments.mixInto(ch, uapi32, uapi64)

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

func (ranges PublicSegmentRanges) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	for _, segment := range ranges.PresentSegments() {
		segment.mixInto(ch, uapi32, uapi64)
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
// ║             Opcodes              ║
// ╚══════════════════════════════════╝

func (claims OpcodeClaims) mixInto(ch *channel.Channel) {
	// TODO: this mixing depends on the proof (and wether we have certain opcodes or not). Make it static.
	ch.MixU64(uints.NewU64(uint64(len(claims.Add))))
	for _, entry := range claims.Add {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.AddSmall))))
	for _, entry := range claims.AddSmall {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.AddAp))))
	for _, entry := range claims.AddAp {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.AssertEq))))
	for _, entry := range claims.AssertEq {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.AssertEqImm))))
	for _, entry := range claims.AssertEqImm {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.AssertEqDoubleDeref))))
	for _, entry := range claims.AssertEqDoubleDeref {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Blake))))
	for _, entry := range claims.Blake {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Call))))
	for _, entry := range claims.Call {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.CallRelImm))))
	for _, entry := range claims.CallRelImm {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Generic))))
	for _, entry := range claims.Generic {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Jnz))))
	for _, entry := range claims.Jnz {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.JnzTaken))))
	for _, entry := range claims.JnzTaken {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Jump))))
	for _, entry := range claims.Jump {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.JumpDoubleDeref))))
	for _, entry := range claims.JumpDoubleDeref {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.JumpRel))))
	for _, entry := range claims.JumpRel {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.JumpRelImm))))
	for _, entry := range claims.JumpRelImm {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Mul))))
	for _, entry := range claims.Mul {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.MulSmall))))
	for _, entry := range claims.MulSmall {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.NewU64(uint64(len(claims.Qm31))))
	for _, entry := range claims.Qm31 {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	for _, entry := range claims.Ret {
		ch.MixU64(uints.NewU64(uint64(len(claims.Ret))))
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
}

// ╔══════════════════════════════════╗
// ║            Contexts              ║
// ╚══════════════════════════════════╝

func (claim BlakeContextClaim) mixInto(ch *channel.Channel) {
	if claim.Claim == nil {
		return
	}
	sub := claim.Claim
	ch.MixU64(uints.U64{sub.BlakeRound.LogSize, zero, zero, zero, zero, zero, zero, zero})
	ch.MixU64(uints.U64{sub.BlakeG.LogSize, zero, zero, zero, zero, zero, zero, zero})
	ch.MixU64(uints.NewU64(uint64(sub.TripleXor32.LogSize)))
}

func (claim BuiltinsClaim) mixInto(ch *channel.Channel) {
	if claim.AddModBuiltin != nil {
		mixBuiltinWithSegment(ch, claim.AddModBuiltin.LogSize, claim.AddModBuiltin.AddModBuiltinSegmentStart)
	}
	if claim.BitwiseBuiltin != nil {
		mixBuiltinWithSegment(ch, claim.BitwiseBuiltin.LogSize, claim.BitwiseBuiltin.BitwiseBuiltinSegmentStart)
	}
	if claim.MulModBuiltin != nil {
		mixBuiltinWithSegment(ch, claim.MulModBuiltin.LogSize, claim.MulModBuiltin.MulModBuiltinSegmentStart)
	}
	if claim.PedersenBuiltin != nil {
		mixBuiltinWithSegment(ch, claim.PedersenBuiltin.LogSize, claim.PedersenBuiltin.PedersenBuiltinSegmentStart)
	}
	if claim.PoseidonBuiltin != nil {
		mixBuiltinWithSegment(ch, claim.PoseidonBuiltin.LogSize, claim.PoseidonBuiltin.PoseidonBuiltinSegmentStart)
	}
	if claim.RangeCheck96 != nil {
		mixBuiltinWithSegment(ch, claim.RangeCheck96.LogSize, claim.RangeCheck96.RangeCheckSegmentStart)
	}
	if claim.RangeCheck128 != nil {
		mixBuiltinWithSegment(ch, claim.RangeCheck128.LogSize, claim.RangeCheck128.RangeCheckSegmentStart)
	}
}

func mixBuiltinWithSegment(ch *channel.Channel, logSize uints.U8, segmentStart uint32) {
	ch.MixU64(uints.U64{logSize, zero, zero, zero, zero, zero, zero, zero})
	ch.MixU64(uints.NewU64(uint64(segmentStart)))
}

func (claim PoseidonContextClaim) mixInto(ch *channel.Channel) {
	if claim.Claim == nil {
		return
	}
	sub := claim.Claim
	if sub.Poseidon3PartialRoundsChain != nil {
		ch.MixU64(uints.U64{sub.Poseidon3PartialRoundsChain.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	if sub.PoseidonFullRoundChain != nil {
		ch.MixU64(uints.U64{sub.PoseidonFullRoundChain.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	if sub.Cube252 != nil {
		ch.MixU64(uints.U64{sub.Cube252.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	if sub.RangeCheckFelt252Width27 != nil {
		ch.MixU64(uints.U64{sub.RangeCheckFelt252Width27.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
}

// ╔══════════════════════════════════╗
// ║        Memory & Range Checks     ║
// ╚══════════════════════════════════╝

func (claim MemoryIDToValueClaim) mixInto(ch *channel.Channel) {
	for _, entry := range claim.Big {
		ch.MixU64(uints.U64{entry.LogSize, zero, zero, zero, zero, zero, zero, zero})
	}
	ch.MixU64(uints.U64{claim.Small.LogSize, zero, zero, zero, zero, zero, zero, zero})
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
	limbMask := feltChunkMasks[BitsPerFelt252]

	for i := 0; i < NM31InFelt252 && wordIdx < len(words); i++ {
		limb := uapi32.And(uapi32.ValueOf(value[i].Limb), limbMask)
		bitsLeft := BitsPerFelt252
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
