package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	// BitsPerM31 is the number of bits in a M31
	BitsPerM31 = 9
	// NM31InFelt252 is the number of M31s in a Felt252
	NM31InFelt252 = 28

	// HdpProofFixture : hdp proof (no hints so the circuit can't be used)
	HdpProofFixture = "hdp_proof.json"
	// AllComponentsHintsProofFixture : uses all the components (current test fixture)
	AllComponentsHintsProofFixture = "all_components_proof_with_hints.json"
)

// Felt252Value contains the value of a Felt252
type Felt252Value [NM31InFelt252]m31.M31

// Proof is the proof emitted by the Stwo-Cairo
type Proof struct {
	Claim            CairoClaim
	InteractionPow   uints.U64
	InteractionClaim CairoInteractionClaim
	StarkProof       StarkProof
	CircuitHints     CircuitHints
}

// StarkProof is the proof emitted by the Stwo Backend
type StarkProof struct {
	Commitments   [][32]uints.U8
	SampledValues [][][]m31.QM31
	QueriedValues [][]m31.M31
	Decommitments []MerkleDecommitment
	FriProof      FriProof
	ProofOfWork   uints.U64
}

// CircuitHints is the data provided to the circuit by the Stwo Prover
type CircuitHints struct {
	Queries [][]int
}

// ╔══════════════════════════════════╗
// ║           Circuit Data           ║
// ╚══════════════════════════════════╝

// CircuitData is the data used to compile the circuit
type CircuitData struct {
	NColumnsPerLogSize  [][]int
	ColumnLogSizes      [][]int
	ColumnBounds        []int
	DedupedQueriesShape []int
	ComponentConfig     ComponentConfig
	PreprocessedConfig  PreprocessedConfig
	BoundsLength        int
	MaxLogSize          uint8
}

// ComponentConfig is the configuration of the components used in the circuit
type ComponentConfig [61]bool

// PreprocessedConfig is the configuration of the preprocessed columns used in the circuit
type PreprocessedConfig [cairo_components.NPreprocessedColumns]bool

// ╔══════════════════════════════════╗
// ║        Interaction Elements      ║
// ╚══════════════════════════════════╝

// CairoInteractionElements containts the interaction elements for the lookups
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
	MemoryAddressToID           m31.InteractionElements
	MemoryIDToValue             m31.InteractionElements
	RangeChecks                 RangeChecksInteractionElements
	VerifyBitwiseXor4           m31.InteractionElements
	VerifyBitwiseXor7           m31.InteractionElements
	VerifyBitwiseXor8           m31.InteractionElements
	VerifyBitwiseXor9           m31.InteractionElements
	VerifyBitwiseXor12          m31.InteractionElements
}

// RangeChecksInteractionElements containts the interaction elements for the range checks lookups
type RangeChecksInteractionElements struct {
	RC6     m31.InteractionElements
	RC8     m31.InteractionElements
	RC11    m31.InteractionElements
	RC12    m31.InteractionElements
	RC18    m31.InteractionElements
	RC19    m31.InteractionElements
	RC43    m31.InteractionElements
	RC44    m31.InteractionElements
	RC54    m31.InteractionElements
	RC99    m31.InteractionElements
	RC725   m31.InteractionElements
	RC3663  m31.InteractionElements
	RC4444  m31.InteractionElements
	RC33333 m31.InteractionElements
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
	elements.MemoryAddressToID = drawInteractionElements(ch, qm31Chip, memoryAddressToIdRelationSize)
	elements.MemoryIDToValue = drawInteractionElements(ch, qm31Chip, memoryIdToValueRelationSize)

	elements.RangeChecks = RangeChecksInteractionElements{
		RC6:     drawInteractionElements(ch, qm31Chip, rangeCheck6RelationSize),
		RC8:     drawInteractionElements(ch, qm31Chip, rangeCheck8RelationSize),
		RC11:    drawInteractionElements(ch, qm31Chip, rangeCheck11RelationSize),
		RC12:    drawInteractionElements(ch, qm31Chip, rangeCheck12RelationSize),
		RC18:    drawInteractionElements(ch, qm31Chip, rangeCheck18RelationSize),
		RC19:    drawInteractionElements(ch, qm31Chip, rangeCheck19RelationSize),
		RC43:    drawInteractionElements(ch, qm31Chip, rangeCheck43RelationSize),
		RC44:    drawInteractionElements(ch, qm31Chip, rangeCheck44RelationSize),
		RC54:    drawInteractionElements(ch, qm31Chip, rangeCheck54RelationSize),
		RC99:    drawInteractionElements(ch, qm31Chip, rangeCheck99RelationSize),
		RC725:   drawInteractionElements(ch, qm31Chip, rangeCheck725RelationSize),
		RC3663:  drawInteractionElements(ch, qm31Chip, rangeCheck3663RelationSize),
		RC4444:  drawInteractionElements(ch, qm31Chip, rangeCheck4444RelationSize),
		RC33333: drawInteractionElements(ch, qm31Chip, rangeCheck33333RelationSize),
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

// CairoClaim contains the public data and the log sizes for each component
type CairoClaim struct {
	PublicData PublicData

	// Opcodes
	Add                 cairo_components.AddOpcodeClaim
	AddSmall            cairo_components.AddSmallOpcodeClaim
	AddAp               cairo_components.AddApOpcodeClaim
	AssertEq            cairo_components.AssertEqOpcodeClaim
	AssertEqImm         cairo_components.AssertEqImmOpcodeClaim
	AssertEqDoubleDeref cairo_components.AssertEqDoubleDerefOpcodeClaim
	Blake               cairo_components.BlakeCompressOpcodeClaim
	Call                cairo_components.CallOpcodeClaim
	CallRelImm          cairo_components.CallRelImmOpcodeClaim
	Generic             cairo_components.GenericOpcodeClaim
	Jnz                 cairo_components.JnzOpcodeClaim
	JnzTaken            cairo_components.JnzTakenOpcodeClaim
	Jump                cairo_components.JumpOpcodeClaim
	JumpDoubleDeref     cairo_components.JumpDoubleDerefOpcodeClaim
	JumpRel             cairo_components.JumpRelOpcodeClaim
	JumpRelImm          cairo_components.JumpRelImmOpcodeClaim
	Mul                 cairo_components.MulOpcodeClaim
	MulSmall            cairo_components.MulSmallOpcodeClaim
	Qm31                cairo_components.Qm31OpcodeClaim
	Ret                 cairo_components.RetOpcodeClaim

	// Verify Instruction
	VerifyInstruction cairo_components.VerifyInstructionClaim

	// Blake context
	BlakeRound         cairo_components.BlakeRoundClaim
	BlakeG             cairo_components.BlakeGClaim
	BlakeRoundSigma    cairo_components.BlakeRoundSigmaClaim
	TripleXor32        cairo_components.TripleXor32Claim
	VerifyBitwiseXor12 cairo_components.VerifyBitwiseXor12Claim

	// Builtins
	AddModBuiltin   cairo_components.AddModBuiltinClaim
	BitwiseBuiltin  cairo_components.BitwiseBuiltinClaim
	MulModBuiltin   cairo_components.MulModBuiltinClaim
	PedersenBuiltin cairo_components.PedersenBuiltinClaim
	PoseidonBuiltin cairo_components.PoseidonBuiltinClaim
	RangeCheck96    cairo_components.RangeCheck96BuiltinClaim
	RangeCheck128   cairo_components.RangeCheck128BuiltinClaim

	// Pedersen context
	PartialEcMul        cairo_components.PartialEcMulClaim
	PedersenPointsTable cairo_components.PedersenPointsTableClaim

	// Poseidon context
	Poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainClaim
	PoseidonFullRoundChain      cairo_components.PoseidonFullRoundChainClaim
	Cube252                     cairo_components.Cube252Claim
	PoseidonRoundKeys           cairo_components.PoseidonRoundKeysClaim
	RangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27Claim

	// Memory
	MemoryAddressToID  cairo_components.MemoryAddressToIDClaim
	MemoryIDToBigBig   cairo_components.MemoryIdToBigBigClaim
	MemoryIDToBigSmall cairo_components.MemoryIdToBigSmallClaim

	// Range checks
	RC6     cairo_components.RangeCheck6Claim
	RC8     cairo_components.RangeCheck8Claim
	RC11    cairo_components.RangeCheck11Claim
	RC12    cairo_components.RangeCheck12Claim
	RC18    cairo_components.RangeCheck18Claim
	RC19    cairo_components.RangeCheck19Claim
	RC43    cairo_components.RangeCheck43Claim
	RC44    cairo_components.RangeCheck44Claim
	RC54    cairo_components.RangeCheck54Claim
	RC99    cairo_components.RangeCheck99Claim
	RC725   cairo_components.RangeCheck725Claim
	RC3663  cairo_components.RangeCheck3663Claim
	RC4444  cairo_components.RangeCheck4444Claim
	RC33333 cairo_components.RangeCheck33333Claim

	// Bitwise XOR
	VerifyBitwiseXor4 cairo_components.VerifyBitwiseXor4Claim
	VerifyBitwiseXor7 cairo_components.VerifyBitwiseXor7Claim
	VerifyBitwiseXor8 cairo_components.VerifyBitwiseXor8Claim
	VerifyBitwiseXor9 cairo_components.VerifyBitwiseXor9Claim
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
	return []SegmentRange{
		p.Output,
		*p.Pedersen,
		*p.RangeCheck128,
		*p.Ecdsa,
		*p.Bitwise,
		*p.EcOp,
		*p.Keccak,
		*p.Poseidon,
		*p.RangeCheck96,
		*p.AddMod,
		*p.MulMod,
	}
}

// ╔══════════════════════════════════╗
// ║        Interaction Claim         ║
// ╚══════════════════════════════════╝

// CairoInteractionClaim contains the claimed sums for each component
type CairoInteractionClaim struct {
	// Opcodes
	Add                 cairo_components.AddOpcodeInteractionClaim
	AddSmall            cairo_components.AddSmallOpcodeInteractionClaim
	AddAp               cairo_components.AddApOpcodeInteractionClaim
	AssertEq            cairo_components.AssertEqOpcodeInteractionClaim
	AssertEqImm         cairo_components.AssertEqImmOpcodeInteractionClaim
	AssertEqDoubleDeref cairo_components.AssertEqDoubleDerefOpcodeInteractionClaim
	Blake               cairo_components.BlakeCompressOpcodeInteractionClaim
	Call                cairo_components.CallOpcodeInteractionClaim
	CallRelImm          cairo_components.CallRelImmOpcodeInteractionClaim
	Generic             cairo_components.GenericOpcodeInteractionClaim
	Jnz                 cairo_components.JnzOpcodeInteractionClaim
	JnzTaken            cairo_components.JnzTakenOpcodeInteractionClaim
	Jump                cairo_components.JumpOpcodeInteractionClaim
	JumpDoubleDeref     cairo_components.JumpDoubleDerefOpcodeInteractionClaim
	JumpRel             cairo_components.JumpRelOpcodeInteractionClaim
	JumpRelImm          cairo_components.JumpRelImmOpcodeInteractionClaim
	Mul                 cairo_components.MulOpcodeInteractionClaim
	MulSmall            cairo_components.MulSmallOpcodeInteractionClaim
	Qm31                cairo_components.Qm31OpcodeInteractionClaim
	Ret                 cairo_components.RetOpcodeInteractionClaim

	// Verify Instruction
	VerifyInstruction cairo_components.VerifyInstructionInteractionClaim

	// Blake context
	BlakeRound         cairo_components.BlakeRoundInteractionClaim
	BlakeG             cairo_components.BlakeGInteractionClaim
	BlakeRoundSigma    cairo_components.BlakeRoundSigmaInteractionClaim
	TripleXor32        cairo_components.TripleXor32InteractionClaim
	VerifyBitwiseXor12 cairo_components.VerifyBitwiseXor12InteractionClaim

	// Builtins
	AddModBuiltin   cairo_components.AddModBuiltinInteractionClaim
	BitwiseBuiltin  cairo_components.BitwiseBuiltinInteractionClaim
	MulModBuiltin   cairo_components.MulModBuiltinInteractionClaim
	PedersenBuiltin cairo_components.PedersenBuiltinInteractionClaim
	PoseidonBuiltin cairo_components.PoseidonBuiltinInteractionClaim
	RangeCheck96    cairo_components.RangeCheck96BuiltinInteractionClaim
	RangeCheck128   cairo_components.RangeCheck128BuiltinInteractionClaim

	// Pedersen context
	PartialEcMul        cairo_components.PartialEcMulInteractionClaim
	PedersenPointsTable cairo_components.PedersenPointsTableInteractionClaim

	// Poseidon context
	Poseidon3PartialRoundsChain cairo_components.Poseidon3PartialRoundsChainInteractionClaim
	PoseidonFullRoundChain      cairo_components.PoseidonFullRoundChainInteractionClaim
	Cube252                     cairo_components.Cube252InteractionClaim
	PoseidonRoundKeys           cairo_components.PoseidonRoundKeysInteractionClaim
	RangeCheckFelt252Width27    cairo_components.RangeCheckFelt252Width27InteractionClaim

	// Memory
	MemoryAddressToID  cairo_components.MemoryAddressToIDInteractionClaim
	MemoryIDToBigBig   cairo_components.MemoryIdToBigBigInteractionClaim
	MemoryIDToBigSmall cairo_components.MemoryIdToBigSmallInteractionClaim

	// Range checks
	RC6     cairo_components.RangeCheck6InteractionClaim
	RC8     cairo_components.RangeCheck8InteractionClaim
	RC11    cairo_components.RangeCheck11InteractionClaim
	RC12    cairo_components.RangeCheck12InteractionClaim
	RC18    cairo_components.RangeCheck18InteractionClaim
	RC19    cairo_components.RangeCheck19InteractionClaim
	RC43    cairo_components.RangeCheck43InteractionClaim
	RC44    cairo_components.RangeCheck44InteractionClaim
	RC54    cairo_components.RangeCheck54InteractionClaim
	RC99    cairo_components.RangeCheck99InteractionClaim
	RC725   cairo_components.RangeCheck725InteractionClaim
	RC3663  cairo_components.RangeCheck3663InteractionClaim
	RC4444  cairo_components.RangeCheck4444InteractionClaim
	RC33333 cairo_components.RangeCheck33333InteractionClaim

	// Bitwise XOR
	VerifyBitwiseXor4 cairo_components.VerifyBitwiseXor4InteractionClaim
	VerifyBitwiseXor7 cairo_components.VerifyBitwiseXor7InteractionClaim
	VerifyBitwiseXor8 cairo_components.VerifyBitwiseXor8InteractionClaim
	VerifyBitwiseXor9 cairo_components.VerifyBitwiseXor9InteractionClaim
}

// ╔══════════════════════════════════╗
// ║            Stark Proof           ║
// ╚══════════════════════════════════╝

// MerkleDecommitment stores the witness bytes and column values emitted by the prover.
type MerkleDecommitment struct {
	HashWitness   [][32]uints.U8
	ColumnWitness []m31.M31
}

// FriProof stores the FRI proof data
type FriProof struct {
	FirstLayerProof  FriLayerProof
	InnerLayerProofs []FriLayerProof
	LastLayerPoly    circle.LinePoly
}

// FriLayerProof stores the FRI layer proof data
type FriLayerProof struct {
	FriWitness   []m31.QM31
	Decommitment MerkleDecommitment
	Commitment   [32]uints.U8
}
