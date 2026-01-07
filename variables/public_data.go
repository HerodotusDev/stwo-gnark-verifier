package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

var zero = uints.NewU8(0)

// Felt252Value contains the value of a Felt252
type Felt252Value [NM31InFelt252]m31.M31

// The PublicData is emitted and used through lookups and it this makes more sense to store
// it directly as M31s (instead of u32 in stwo-cairo) although this is less efficient for channel mixing which requires mixing u32s.
type PublicData struct {
	PublicMemory PublicMemory
	InitialState CasmState
	FinalState   CasmState
}

// CasmState contains the PC, AP and FP register values
type CasmState struct {
	PC m31.M31
	AP m31.M31
	FP m31.M31
}

// PublicMemory contains the program, output and auxiliary memory segments
type PublicMemory struct {
	Program        []PubMemoryValue
	PublicSegments PublicSegmentRanges
	Output         []PubMemoryValue
	SafeCall       []PubMemoryValue
}

// PubMemoryValue contains the ID and value of a public memory cell
type PubMemoryValue struct {
	ID    m31.M31
	Value Felt252Value
}

// PublicMemoryEntry contains the address, ID and value of a public memory cell
type PublicMemoryEntry struct {
	Address m31.M31
	ID      m31.M31
	Value   Felt252Value
}

// PublicSegmentRanges contains the start and stop pointers of builtin segments
type PublicSegmentRanges struct {
	Output        SegmentRange
	Pedersen      *SegmentRange
	RangeCheck128 *SegmentRange
	Ecdsa         *SegmentRange
	Bitwise       *SegmentRange
	EcOp          *SegmentRange
	Keccak        *SegmentRange
	Poseidon      *SegmentRange
	RangeCheck96  *SegmentRange
	AddMod        *SegmentRange
	MulMod        *SegmentRange
}

// SegmentRange contains the start and stop pointers of a builtin segment
type SegmentRange struct {
	StartPtr SegmentPointer
	StopPtr  SegmentPointer
}

// SegmentPointer contains the segment identifier and value
type SegmentPointer struct {
	ID    m31.M31
	Value Felt252Value
}

// Segments returns the present segments in the public memory.
func (p *PublicSegmentRanges) Segments() []SegmentRange {
	segments := make([]SegmentRange, 0)
	segments = append(segments, p.Output)
	if p.Pedersen != nil {
		segments = append(segments, *p.Pedersen)
	}
	if p.RangeCheck128 != nil {
		segments = append(segments, *p.RangeCheck128)
	}
	if p.Ecdsa != nil {
		segments = append(segments, *p.Ecdsa)
	}
	if p.Bitwise != nil {
		segments = append(segments, *p.Bitwise)
	}
	if p.EcOp != nil {
		segments = append(segments, *p.EcOp)
	}
	if p.Keccak != nil {
		segments = append(segments, *p.Keccak)
	}
	if p.Poseidon != nil {
		segments = append(segments, *p.Poseidon)
	}
	if p.RangeCheck96 != nil {
		segments = append(segments, *p.RangeCheck96)
	}
	if p.AddMod != nil {
		segments = append(segments, *p.AddMod)
	}
	if p.MulMod != nil {
		segments = append(segments, *p.MulMod)
	}
	return segments
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildPublicData builds a PublicData from its raw representation.
func BuildPublicData(publicDataRaw *PublicDataRaw) PublicData {
	if publicDataRaw == nil {
		return PublicData{}
	}

	publicMemory := buildPublicMemory(publicDataRaw.PublicMemory)
	initialState := buildCasmState(publicDataRaw.InitialState)
	finalState := buildCasmState(publicDataRaw.FinalState)

	return PublicData{
		PublicMemory: publicMemory,
		InitialState: initialState,
		FinalState:   finalState,
	}
}

func buildCasmState(raw RegisterStateRaw) CasmState {
	return CasmState{
		PC: m31.NewM31Unchecked(raw.PC),
		AP: m31.NewM31Unchecked(raw.AP),
		FP: m31.NewM31Unchecked(raw.FP),
	}
}

func buildPublicMemory(raw PublicMemoryRaw) PublicMemory {
	return PublicMemory{
		Program:        convertMemorySection(raw.Program),
		PublicSegments: buildPublicSegmentRanges(raw.PublicSegments),
		Output:         convertMemorySection(raw.Output),
		SafeCall:       convertMemorySection(raw.SafeCall),
	}
}

func convertMemorySection(cells []MemoryCellRaw) []PubMemoryValue {
	if len(cells) == 0 {
		return nil
	}

	section := make([]PubMemoryValue, 0, len(cells))
	for _, cell := range cells {
		section = append(section, PubMemoryValue{
			ID:    m31.NewM31Unchecked(cell.Address),
			Value: SplitFeltWords(*(*[8]uint32)(cell.Value)), // values are necessarily 8 limbs of 32 bits
		})
	}
	return section
}

func buildPublicSegmentRanges(raw map[string]*SegmentRangeRaw) PublicSegmentRanges {
	if raw == nil {
		return PublicSegmentRanges{}
	}

	var ranges PublicSegmentRanges

	ranges.Output = buildSegmentRange(raw["output"])

	if segment := raw["pedersen"]; segment != nil {
		ranges.Pedersen = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["range_check_128"]; segment != nil {
		ranges.RangeCheck128 = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["ecdsa"]; segment != nil {
		ranges.Ecdsa = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["bitwise"]; segment != nil {
		ranges.Bitwise = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["ec_op"]; segment != nil {
		ranges.EcOp = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["keccak"]; segment != nil {
		ranges.Keccak = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["poseidon"]; segment != nil {
		ranges.Poseidon = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["range_check_96"]; segment != nil {
		ranges.RangeCheck96 = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["add_mod"]; segment != nil {
		ranges.AddMod = ptrSegmentRange(buildSegmentRange(segment))
	}
	if segment := raw["mul_mod"]; segment != nil {
		ranges.MulMod = ptrSegmentRange(buildSegmentRange(segment))
	}

	return ranges
}

func buildSegmentRange(raw *SegmentRangeRaw) SegmentRange {
	if raw == nil {
		return SegmentRange{}
	}

	return SegmentRange{
		StartPtr: buildSegmentPointer(raw.StartPtr),
		StopPtr:  buildSegmentPointer(raw.StopPtr),
	}
}

func buildSegmentPointer(raw *SegmentPointerRaw) SegmentPointer {
	if raw == nil {
		return SegmentPointer{}
	}
	value := [8]uint32{raw.Value, 0, 0, 0, 0, 0, 0, 0}
	return SegmentPointer{
		ID:    m31.NewM31Unchecked(raw.ID),
		Value: SplitFeltWords(value),
	}
}

// Creates a copy from which we can take the address
func ptrSegmentRange(segment SegmentRange) *SegmentRange {
	seg := segment
	return &seg
}

// ╔══════════════════════════════════╗
// ║              Mixing              ║
// ╚══════════════════════════════════╝

// mixInto absorbs the PublicData into the transcript channel.
func (data PublicData) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	data.PublicMemory.mixInto(ch, uapi32, uapi64)
	data.InitialState.mixInto(ch, uapi64)
	data.FinalState.mixInto(ch, uapi64)
}

// mixInto absorbs the PublicMemory into the transcript channel.
func (memory PublicMemory) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	memory.PublicSegments.mixInto(ch, uapi32, uapi64)

	var outputWords []uints.U32
	for _, entry := range memory.Output {
		// NOTE: not storing values as u32s but as M31s adds some overhead here but saves gates during public data logup sum computation
		entryWords := feltValueToU32Words(entry.Value, uapi32)
		for _, word := range entryWords {
			outputWords = append(outputWords, word)
		}
	}

	ch.MixU32s(outputWords)

	ch.MixU64(uints.NewU64(2))
	for _, entry := range memory.SafeCall {
		ch.MixU64(uapi64.ValueOf(entry.ID.Limb))
		// NOTE: same as above.
		entryWords := feltValueToU32Words(entry.Value, uapi32)
		for _, word := range entryWords {
			ch.MixU64(uints.U64{word[0], word[1], word[2], word[3], zero, zero, zero, zero})
		}
	}
}

// mixInto absorbs the PublicSegmentRanges into the transcript channel.
func (p PublicSegmentRanges) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	p.Output.mixInto(ch, uapi32, uapi64)
	if p.Pedersen != nil {
		p.Pedersen.mixInto(ch, uapi32, uapi64)
	}
	if p.RangeCheck128 != nil {
		p.RangeCheck128.mixInto(ch, uapi32, uapi64)
	}
	if p.Ecdsa != nil {
		p.Ecdsa.mixInto(ch, uapi32, uapi64)
	}
	if p.Bitwise != nil {
		p.Bitwise.mixInto(ch, uapi32, uapi64)
	}
	if p.EcOp != nil {
		p.EcOp.mixInto(ch, uapi32, uapi64)
	}
	if p.Keccak != nil {
		p.Keccak.mixInto(ch, uapi32, uapi64)
	}
	if p.Poseidon != nil {
		p.Poseidon.mixInto(ch, uapi32, uapi64)
	}
	if p.RangeCheck96 != nil {
		p.RangeCheck96.mixInto(ch, uapi32, uapi64)
	}
	if p.AddMod != nil {
		p.AddMod.mixInto(ch, uapi32, uapi64)
	}
	if p.MulMod != nil {
		p.MulMod.mixInto(ch, uapi32, uapi64)
	}
}

// mixInto absorbs the SegmentRange into the transcript channel.
func (segment SegmentRange) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	segment.StartPtr.mixInto(ch, uapi32, uapi64)
	segment.StopPtr.mixInto(ch, uapi32, uapi64)
}

// mixInto absorbs the SegmentPointer into the transcript channel.
func (pointer SegmentPointer) mixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32], uapi64 *uints.BinaryField[uints.U64]) {
	ch.MixU64(uapi64.ValueOf(pointer.ID.Limb))
	valueU32 := feltValueToU32Words(pointer.Value, uapi32)[0]
	valueU64 := uints.U64{valueU32[0], valueU32[1], valueU32[2], valueU32[3], zero, zero, zero, zero}
	ch.MixU64(valueU64)
}

// mixInto absorbs the CasmState into the transcript channel.
func (state CasmState) mixInto(ch *channel.Channel, uapi64 *uints.BinaryField[uints.U64]) {
	ch.MixU64(uapi64.ValueOf(state.PC.Limb))
	ch.MixU64(uapi64.ValueOf(state.AP.Limb))
	ch.MixU64(uapi64.ValueOf(state.FP.Limb))
}
