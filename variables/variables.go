package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	BitsPerFelt252 = 9
	NM31InFelt252  = 28
)

type Proof struct {
	Claim            CairoClaim
	InteractionClaim CairoInteractionClaim
	StarkProof       StarkProof
}

type StarkProof struct {
	SampledValues [][][]m31.QM31
}

// ╔══════════════════════════════════╗
// ║        Interaction Elements      ║
// ╚══════════════════════════════════╝

type CairoInteractionElements struct {
	Opcodes                     m31.InteractionElements
	VerifyInstruction           m31.InteractionElements
	BlakeRound                  m31.InteractionElements
	BlakeG                      m31.InteractionElements
	BlakeRoundSigma             m31.InteractionElements
	TripleXor32                 m31.InteractionElements
	PartialEcMul                m31.InteractionElements
	PedersenPointsTable         m31.InteractionElements
	PoseidonFullRoundChain      m31.InteractionElements
	Poseidon3PartialRoundsChain m31.InteractionElements
	Cube252                     m31.InteractionElements
	PoseidonRoundKeys           m31.InteractionElements
	RangeCheckFelt252Width27    m31.InteractionElements
	MemoryAddressToId           m31.InteractionElements
	MemoryIDToValue             m31.InteractionElements
	RangeChecks                 RangeChecksInteractionElements
	VerifyBitwiseXor4           m31.InteractionElements
	VerifyBitwiseXor7           m31.InteractionElements
	VerifyBitwiseXor8           m31.InteractionElements
	VerifyBitwiseXor9           m31.InteractionElements
	VerifyBitwiseXor12          m31.InteractionElements
}

type RangeChecksInteractionElements struct {
	RC6         m31.InteractionElements
	RC8         m31.InteractionElements
	RC1_1       m31.InteractionElements
	RC1_2       m31.InteractionElements
	RC1_8       m31.InteractionElements
	RC1_9       m31.InteractionElements
	RC4_3       m31.InteractionElements
	RC4_4       m31.InteractionElements
	RC5_4       m31.InteractionElements
	RC9_9       m31.InteractionElements
	RC7_2_5     m31.InteractionElements
	RC3_6_6_3   m31.InteractionElements
	RC4_4_4_4   m31.InteractionElements
	RC3_3_3_3_3 m31.InteractionElements
}

// Draw populates CairoInteractionElements with logup elements sampled from the Fiat-Shamir channel.
func (elements *CairoInteractionElements) Draw(ch *channel.Channel, qm31Chip *m31.QM31Chip) {
	if elements == nil {
		panic("CairoInteractionElements.Draw called on nil receiver")
	}
	if ch == nil {
		panic("channel must not be nil")
	}
	if qm31Chip == nil {
		panic("qm31 chip must not be nil")
	}

	elements.Opcodes = drawInteractionElements(ch, qm31Chip, opcodesRelationSize)
	elements.VerifyInstruction = drawInteractionElements(ch, qm31Chip, verifyInstructionRelationSize)
	elements.BlakeRound = drawInteractionElements(ch, qm31Chip, blakeRoundRelationSize)
	elements.BlakeG = drawInteractionElements(ch, qm31Chip, blakeGRelationSize)
	elements.BlakeRoundSigma = drawInteractionElements(ch, qm31Chip, blakeRoundSigmaRelationSize)
	elements.TripleXor32 = drawInteractionElements(ch, qm31Chip, tripleXor32RelationSize)
	elements.Poseidon3PartialRoundsChain = drawInteractionElements(ch, qm31Chip, poseidon3PartialRoundsChainRelationSize)
	elements.PoseidonFullRoundChain = drawInteractionElements(ch, qm31Chip, poseidonFullRoundChainRelationSize)
	elements.Cube252 = drawInteractionElements(ch, qm31Chip, cube252RelationSize)
	elements.PoseidonRoundKeys = drawInteractionElements(ch, qm31Chip, poseidonRoundKeysRelationSize)
	elements.RangeCheckFelt252Width27 = drawInteractionElements(ch, qm31Chip, rangeCheckFelt252Width27RelationSize)
	elements.PartialEcMul = drawInteractionElements(ch, qm31Chip, partialEcMulRelationSize)
	elements.PedersenPointsTable = drawInteractionElements(ch, qm31Chip, pedersenPointsTableRelationSize)
	elements.MemoryAddressToId = drawInteractionElements(ch, qm31Chip, memoryAddressToIdRelationSize)
	elements.MemoryIDToValue = drawInteractionElements(ch, qm31Chip, memoryIdToValueRelationSize)

	elements.RangeChecks = RangeChecksInteractionElements{
		RC6:         drawInteractionElements(ch, qm31Chip, rangeCheck6RelationSize),
		RC8:         drawInteractionElements(ch, qm31Chip, rangeCheck8RelationSize),
		RC1_1:       drawInteractionElements(ch, qm31Chip, rangeCheck11RelationSize),
		RC1_2:       drawInteractionElements(ch, qm31Chip, rangeCheck12RelationSize),
		RC1_8:       drawInteractionElements(ch, qm31Chip, rangeCheck18RelationSize),
		RC1_9:       drawInteractionElements(ch, qm31Chip, rangeCheck19RelationSize),
		RC4_3:       drawInteractionElements(ch, qm31Chip, rangeCheck4_3RelationSize),
		RC4_4:       drawInteractionElements(ch, qm31Chip, rangeCheck4_4RelationSize),
		RC5_4:       drawInteractionElements(ch, qm31Chip, rangeCheck5_4RelationSize),
		RC9_9:       drawInteractionElements(ch, qm31Chip, rangeCheck9_9RelationSize),
		RC7_2_5:     drawInteractionElements(ch, qm31Chip, rangeCheck7_2_5RelationSize),
		RC3_6_6_3:   drawInteractionElements(ch, qm31Chip, rangeCheck3_6_6_3RelationSize),
		RC4_4_4_4:   drawInteractionElements(ch, qm31Chip, rangeCheck4_4_4_4RelationSize),
		RC3_3_3_3_3: drawInteractionElements(ch, qm31Chip, rangeCheck3_3_3_3_3RelationSize),
	}

	elements.VerifyBitwiseXor4 = drawInteractionElements(ch, qm31Chip, verifyBitwiseXor4RelationSize)
	elements.VerifyBitwiseXor7 = drawInteractionElements(ch, qm31Chip, verifyBitwiseXor7RelationSize)
	elements.VerifyBitwiseXor8 = drawInteractionElements(ch, qm31Chip, verifyBitwiseXor8RelationSize)
	elements.VerifyBitwiseXor9 = drawInteractionElements(ch, qm31Chip, verifyBitwiseXor9RelationSize)
	elements.VerifyBitwiseXor12 = drawInteractionElements(ch, qm31Chip, verifyBitwiseXor12RelationSize)
}

func drawInteractionElements(ch *channel.Channel, qm31Chip *m31.QM31Chip, powerCount int) m31.InteractionElements {
	if powerCount <= 0 {
		panic("powerCount must be positive")
	}

	felts := ch.DrawFelts(2)
	if len(felts) != 2 {
		panic("channel.DrawFelts(2) returned unexpected number of elements")
	}
	z := felts[0]
	alpha := felts[1]

	alphaPowers := make([]m31.QM31, powerCount)
	acc := qm31Chip.One()
	for i := 0; i < powerCount; i++ {
		if i > 0 {
			acc = qm31Chip.Mul(acc, alpha)
		}
		alphaPowers[i] = acc
	}

	return qm31Chip.NewInteractionElements(z, alpha, alphaPowers)
}

// ╔══════════════════════════════════╗
// ║               Claim              ║
// ╚══════════════════════════════════╝

type CairoClaim struct {
	PublicData        PublicData
	Opcodes           OpcodeClaims
	VerifyInstruction *cairo_components.VerifyInstructionClaim
	BlakeContext      BlakeContextClaim
	Builtins          BuiltinsClaim
	PedersenContext   PedersenContextClaim
	PoseidonContext   PoseidonContextClaim
	MemoryAddressToId cairo_components.MemoryAddressToIdClaim
	MemoryIDToValue   MemoryIDToValueClaim
	RangeChecks       RangeChecksClaim
	VerifyBitwiseXor4 *SimpleLogSizeClaim
	VerifyBitwiseXor7 *SimpleLogSizeClaim
	VerifyBitwiseXor8 *SimpleLogSizeClaim
	VerifyBitwiseXor9 *SimpleLogSizeClaim
}

type OpcodeClaims struct {
	Add                 []cairo_components.AddOpcodeClaim
	AddSmall            []cairo_components.AddSmallOpcodeClaim
	AddAp               []cairo_components.AddApOpcodeClaim
	AssertEq            []cairo_components.AssertEqOpcodeClaim
	AssertEqImm         []cairo_components.AssertEqImmOpcodeClaim
	AssertEqDoubleDeref []cairo_components.AssertEqDoubleDerefOpcodeClaim
	Blake               []cairo_components.BlakeCompressOpcodeClaim
	Call                []cairo_components.CallOpcodeClaim
	CallRelImm          []cairo_components.CallRelImmOpcodeClaim
	Generic             []cairo_components.GenericOpcodeClaim
	Jnz                 []cairo_components.JnzOpcodeClaim
	JnzTaken            []cairo_components.JnzTakenOpcodeClaim
	Jump                []cairo_components.JumpOpcodeClaim
	JumpDoubleDeref     []cairo_components.JumpDoubleDerefOpcodeClaim
	JumpRel             []cairo_components.JumpRelOpcodeClaim
	JumpRelImm          []cairo_components.JumpRelImmOpcodeClaim
	Mul                 []cairo_components.MulOpcodeClaim
	MulSmall            []cairo_components.MulSmallOpcodeClaim
	Qm31                []cairo_components.Qm31OpcodeClaim
	Ret                 []cairo_components.RetOpcodeClaim
}

type BlakeContextClaim struct {
	Claim *BlakeClaim
}

type BlakeClaim struct {
	BlakeRound         *cairo_components.BlakeRoundClaim
	BlakeG             *cairo_components.BlakeGClaim
	BlakeRoundSigma    *cairo_components.BlakeRoundSigmaClaim
	TripleXor32        *cairo_components.TripleXor32Claim
	VerifyBitwiseXor12 *SimpleLogSizeClaim
}

type BuiltinsClaim struct {
	AddModBuiltin   *cairo_components.AddModBuiltinClaim
	BitwiseBuiltin  *cairo_components.BitwiseBuiltinClaim
	MulModBuiltin   *cairo_components.MulModBuiltinClaim
	PedersenBuiltin *cairo_components.PedersenBuiltinClaim
	PoseidonBuiltin *cairo_components.PoseidonBuiltinClaim
	RangeCheck96    *cairo_components.RangeCheck96BuiltinClaim
	RangeCheck128   *cairo_components.RangeCheck128BuiltinClaim
}

type PedersenContextClaim struct {
	Claim *PedersenClaim
}

type PedersenClaim struct {
	PartialEcMul        *cairo_components.PartialEcMulClaim
	PedersenPointsTable *cairo_components.PedersenPointsTableClaim
}

type PoseidonContextClaim struct {
	Claim *PoseidonClaim
}

type PoseidonClaim struct {
	Poseidon3PartialRoundsChain *cairo_components.Poseidon3PartialRoundsChainClaim
	PoseidonFullRoundChain      *cairo_components.PoseidonFullRoundChainClaim
	Cube252                     *cairo_components.Cube252Claim
	PoseidonRoundKeys           *cairo_components.PoseidonRoundKeysClaim
	RangeCheckFelt252Width27    *cairo_components.RangeCheckFelt252Width27Claim
}

type MemoryIDToValueClaim struct {
	Big   []cairo_components.MemoryIdToBigBigClaim
	Small *cairo_components.MemoryIdToBigSmallClaim
}

type RangeChecksClaim struct {
	RC6         *SimpleLogSizeClaim
	RC8         *SimpleLogSizeClaim
	RC11        *SimpleLogSizeClaim
	RC12        *SimpleLogSizeClaim
	RC18        *SimpleLogSizeClaim
	RC19        *SimpleLogSizeClaim
	RC4_3       *SimpleLogSizeClaim
	RC4_4       *SimpleLogSizeClaim
	RC5_4       *SimpleLogSizeClaim
	RC9_9       *SimpleLogSizeClaim
	RC7_2_5     *SimpleLogSizeClaim
	RC3_6_6_3   *SimpleLogSizeClaim
	RC4_4_4_4   *SimpleLogSizeClaim
	RC3_3_3_3_3 *SimpleLogSizeClaim
}

type SimpleLogSizeClaim struct {
	LogSize uint32
}

// ╔══════════════════════════════════╗
// ║            Public Data           ║
// ╚══════════════════════════════════╝

// The PublicData is emitted and used through lookups and it this makes more sense to store
// it directly as M31s (instead of u32 in stwo-cairo).
type PublicData struct {
	PublicMemory PublicMemory
	InitialState CasmState
	FinalState   CasmState
}

type CasmState struct {
	PC m31.M31
	AP m31.M31
	FP m31.M31
}

type PublicMemory struct {
	Program        []PubMemoryValue
	PublicSegments PublicSegmentRanges
	Output         []PubMemoryValue
	SafeCall       []PubMemoryValue
}

type PubMemoryValue struct {
	ID    m31.M31
	Value Felt252Value
}

type PublicMemoryEntry struct {
	Address m31.M31
	ID      m31.M31
	Value   Felt252Value
}

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

type SegmentRange struct {
	StartPtr SegmentPointer
	StopPtr  SegmentPointer
}

type SegmentPointer struct {
	ID    m31.M31
	Value Felt252Value
}

type Felt252Value [NM31InFelt252]m31.M31

// ╔══════════════════════════════════╗
// ║        Interaction Claim         ║
// ╚══════════════════════════════════╝

type CairoInteractionClaim struct {
	Opcodes           OpcodeInteractionClaim
	VerifyInstruction cairo_components.VerifyInstructionInteractionClaim
	BlakeContext      BlakeContextInteractionClaim
	Builtins          BuiltinsInteractionClaim
	PedersenContext   PedersenContextInteractionClaim
	PoseidonContext   PoseidonContextInteractionClaim
	MemoryAddressToId cairo_components.MemoryAddressToIdInteractionClaim
	MemoryIDToValue   cairo_components.MemoryIdToValueInteractionClaim
	RangeChecks       RangeChecksInteractionClaim
	VerifyBitwiseXor4 cairo_components.VerifyBitwiseXor4InteractionClaim
	VerifyBitwiseXor7 cairo_components.VerifyBitwiseXor7InteractionClaim
	VerifyBitwiseXor8 cairo_components.VerifyBitwiseXor8InteractionClaim
	VerifyBitwiseXor9 cairo_components.VerifyBitwiseXor9InteractionClaim
}

type OpcodeInteractionClaim struct {
	Add                 []cairo_components.AddOpcodeInteractionClaim
	AddSmall            []cairo_components.AddSmallOpcodeInteractionClaim
	AddAp               []cairo_components.AddApOpcodeInteractionClaim
	AssertEq            []cairo_components.AssertEqOpcodeInteractionClaim
	AssertEqImm         []cairo_components.AssertEqImmOpcodeInteractionClaim
	AssertEqDoubleDeref []cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim
	Blake               []cairo_components.BlakeCompressOpcodeInteractionClaim
	Call                []cairo_components.CallOpcodeInteractionClaim
	CallRelImm          []cairo_components.CallRelImmOpcodeInteractionClaim
	Generic             []cairo_components.GenericOpcodeInteractionClaim
	Jnz                 []cairo_components.JnzOpcodeInteractionClaim
	JnzTaken            []cairo_components.JnzTakenOpcodeInteractionClaim
	Jump                []cairo_components.JumpOpcodeInteractionClaim
	JumpDoubleDeref     []cairo_components.JumpDoubleDerefOpcodeInteractionClaim
	JumpRel             []cairo_components.JumpRelOpcodeInteractionClaim
	JumpRelImm          []cairo_components.JumpRelImmOpcodeInteractionClaim
	Mul                 []cairo_components.MulOpcodeInteractionClaim
	MulSmall            []cairo_components.MulSmallOpcodeInteractionClaim
	Qm31                []cairo_components.Qm31OpcodeInteractionClaim
	Ret                 []cairo_components.RetOpcodeInteractionClaim
}

type BlakeContextInteractionClaim struct {
	InteractionClaim *BlakeInteractionClaim
}

type BlakeInteractionClaim struct {
	BlakeRound         cairo_components.BlakeRoundInteractionClaim
	BlakeG             cairo_components.BlakeGInteractionClaim
	BlakeRoundSigma    cairo_components.BlakeRoundSigmaInteractionClaim
	TripleXor32        cairo_components.TripleXor32InteractionClaim
	VerifyBitwiseXor12 cairo_components.VerifyBitwiseXor12InteractionClaim
}

type BuiltinsInteractionClaim struct {
	AddModBuiltin   *cairo_components.AddModBuiltinInteractionClaim
	BitwiseBuiltin  *cairo_components.BitwiseBuiltinInteractionClaim
	MulModBuiltin   *cairo_components.MulModBuiltinInteractionClaim
	PedersenBuiltin *cairo_components.PedersenBuiltinInteractionClaim
	PoseidonBuiltin *cairo_components.PoseidonBuiltinInteractionClaim
	RangeCheck96    *cairo_components.RangeCheck96BuiltinInteractionClaim
	RangeCheck128   *cairo_components.RangeCheck128BuiltinInteractionClaim
}

type PedersenContextInteractionClaim struct {
	InteractionClaim *PedersenInteractionClaim
}

type PedersenInteractionClaim struct {
	PartialEcMul        cairo_components.PartialEcMulInteractionClaim
	PedersenPointsTable cairo_components.PedersenPointsTableInteractionClaim
}

type PoseidonContextInteractionClaim struct {
	InteractionClaim *PoseidonInteractionClaim
}

type PoseidonInteractionClaim struct {
	Poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainInteractionClaim
	PoseidonFullRoundChain      cairo_components.PoseidonFullRoundChainInteractionClaim
	Cube252                     cairo_components.Cube252InteractionClaim
	PoseidonRoundKeys           cairo_components.PoseidonRoundKeysInteractionClaim
	RangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27InteractionClaim
}

type RangeChecksInteractionClaim struct {
	RC6         cairo_components.RangeCheck6InteractionClaim
	RC8         cairo_components.RangeCheck8InteractionClaim
	RC11        cairo_components.RangeCheck11InteractionClaim
	RC12        cairo_components.RangeCheck12InteractionClaim
	RC18        cairo_components.RangeCheck18InteractionClaim
	RC19        cairo_components.RangeCheck19InteractionClaim
	RC4_3       cairo_components.RangeCheck4_3InteractionClaim
	RC4_4       cairo_components.RangeCheck4_4InteractionClaim
	RC5_4       cairo_components.RangeCheck5_4InteractionClaim
	RC9_9       cairo_components.RangeCheck9_9InteractionClaim
	RC7_2_5     cairo_components.RangeCheck7_2_5InteractionClaim
	RC3_6_6_3   cairo_components.RangeCheck3_6_6_3InteractionClaim
	RC4_4_4_4   cairo_components.RangeCheck4_4_4_4InteractionClaim
	RC3_3_3_3_3 cairo_components.RangeCheck3_3_3_3_3InteractionClaim
}
