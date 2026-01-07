package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	opcodesRelationSize                     = 3
	verifyInstructionRelationSize           = 7
	blakeRoundRelationSize                  = 35
	blakeGRelationSize                      = 20
	blakeRoundSigmaRelationSize             = 17
	tripleXor32RelationSize                 = 8
	partialEcMulRelationSize                = 73
	pedersenPointsTableRelationSize         = 57
	poseidonFullRoundChainRelationSize      = 32
	poseidon3PartialRoundsChainRelationSize = 42
	cube252RelationSize                     = 20
	poseidonRoundKeysRelationSize           = 31
	rangeCheckFelt252Width27RelationSize    = 10
	memoryAddressToIDRelationSize           = 2
	memoryIDToValueRelationSize             = 29
	verifyBitwiseXor4RelationSize           = 3
	verifyBitwiseXor7RelationSize           = 3
	verifyBitwiseXor8RelationSize           = 3
	verifyBitwiseXor9RelationSize           = 3
	verifyBitwiseXor12RelationSize          = 3

	rangeCheck6RelationSize     = 1
	rangeCheck8RelationSize     = 1
	rangeCheck11RelationSize    = 1
	rangeCheck12RelationSize    = 1
	rangeCheck18RelationSize    = 1
	rangeCheck19RelationSize    = 1
	rangeCheck43RelationSize    = 2
	rangeCheck44RelationSize    = 2
	rangeCheck54RelationSize    = 2
	rangeCheck99RelationSize    = 2
	rangeCheck725RelationSize   = 3
	rangeCheck3663RelationSize  = 4
	rangeCheck4444RelationSize  = 4
	rangeCheck33333RelationSize = 5
)

// ╔══════════════════════════════════╗
// ║        Interaction Elements      ║
// ╚══════════════════════════════════╝

// CairoInteractionElements contains the interaction elements for the lookups
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

// RangeChecksInteractionElements contains the interaction elements for the range checks lookups
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
	elements.MemoryAddressToID = drawInteractionElements(ch, qm31Chip, memoryAddressToIDRelationSize)
	elements.MemoryIDToValue = drawInteractionElements(ch, qm31Chip, memoryIDToValueRelationSize)

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
