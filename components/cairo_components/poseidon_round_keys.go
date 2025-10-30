package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	poseidonRoundKeysLogSize = uint32(6)
	poseidonRoundKeysColumns = 30
)

type PoseidonRoundKeysClaim struct{}

type PoseidonRoundKeysInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PoseidonRoundKeysComponent struct {
	qm31 *m31.QM31Chip

	lookupElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31

	seqColumn  PreprocessedColumn
	keyColumns []PreprocessedColumn
}

func NewPoseidonRoundKeys(
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	interactionClaim PoseidonRoundKeysInteractionClaim,
) *PoseidonRoundKeysComponent {
	columnSize := uint32(1) << poseidonRoundKeysLogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	keyColumns := make([]PreprocessedColumn, poseidonRoundKeysColumns)
	for i := 0; i < poseidonRoundKeysColumns; i++ {
		keyColumns[i] = NewPreprocessedColumnPoseidonRoundKeys(uints.NewU8(uint8(i)))
	}

	return &PoseidonRoundKeysComponent{
		qm31:           qm31,
		lookupElements: lookupElements,
		claimedSum:     interactionClaim.ClaimedSum,
		columnSizeInv:  qm31.Inverse(columnSizeQM),
		vanishEvalInv:  qm31.One(),
		seqColumn:      NewPreprocessedColumnSeq(uints.NewU8(uint8(poseidonRoundKeysLogSize))),
		keyColumns:     keyColumns,
	}
}

func (c *PoseidonRoundKeysComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	seq := preprocessedSampledValues.Get(c.seqColumn)

	values := make([]m31.QM31, 1+len(c.keyColumns))
	values[0] = seq
	for i, column := range c.keyColumns {
		values[i+1] = preprocessedSampledValues.Get(column)
	}

	lookupSum, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	enabler := traceSampledValues[0][0]

	curr := c.qm31.FromPartialEvals(
		interactionSampledValues[0][1],
		interactionSampledValues[1][1],
		interactionSampledValues[2][1],
		interactionSampledValues[3][1],
	)
	prev := c.qm31.FromPartialEvals(
		interactionSampledValues[0][0],
		interactionSampledValues[1][0],
		interactionSampledValues[2][0],
		interactionSampledValues[3][0],
	)

	diff := c.qm31.Sub(curr, prev)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint := c.qm31.Mul(diff, lookupSum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)

	return accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
}
