package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

type lookupConstraintComponent struct {
	qm31 *m31.QM31Chip

	interactionElements m31.InteractionElements
	claimedSum          m31.QM31
	columnSizeInv       m31.QM31
	vanishEvalInv       m31.QM31
	preprocessed        []PreprocessedColumn
}

func newLookupConstraintComponent(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claimedSum m31.QM31,
	logSize uint8,
	preprocessed []PreprocessedColumn,
) *lookupConstraintComponent {
	columnSize := m31.NewM31Unchecked(uint32(1) << logSize)
	columnSizeQM31 := m31.NewQM31FromM31(columnSize)
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	clone := make([]PreprocessedColumn, len(preprocessed))
	copy(clone, preprocessed)

	return &lookupConstraintComponent{
		qm31:                qm31,
		interactionElements: interactionElements,
		claimedSum:          claimedSum,
		columnSizeInv:       columnSizeInv,
		vanishEvalInv:       qm31.One(), // TODO: wire actual vanishing polynomial evaluation.
		preprocessed:        clone,
	}
}

func (c *lookupConstraintComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	values := make([]m31.QM31, len(c.preprocessed))
	for i, column := range c.preprocessed {
		values[i] = preprocessedSampledValues.Get(column)
	}

	rangeCheckSum, err := c.qm31.Combine(c.interactionElements, values)
	if err != nil {
		panic(err)
	}

	enabler := traceSampledValues[0][0]

	tr0 := interactionSampledValues[0]
	tr1 := interactionSampledValues[1]
	tr2 := interactionSampledValues[2]
	tr3 := interactionSampledValues[3]

	curr := c.qm31.FromPartialEvals(tr0[1], tr1[1], tr2[1], tr3[1])
	prev := c.qm31.FromPartialEvals(tr0[0], tr1[0], tr2[0], tr3[0])
	diff := c.qm31.Sub(curr, prev)

	sumTerm := c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint := c.qm31.Add(c.qm31.Mul(sumTerm, rangeCheckSum), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)

	sum = c.qm31.Add(c.qm31.Mul(sum, randomCoeff), constraint)
	return sum
}

func sequencePreprocessedColumn(logSize uint8) PreprocessedColumn {
	return NewPreprocessedColumnSeq(uints.NewU8(logSize))
}
