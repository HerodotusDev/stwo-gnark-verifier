package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
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
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claimedSum m31.QM31,
	logSize uints.U8,
	preprocessed []PreprocessedColumn,
) *lookupConstraintComponent {
	columnSize := computeColumnSize(api, logSize)
	columnSizeInv := qm31.Inverse(columnSize)

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

const (
	LookupTraceColumns       = 1
	LookupInteractionColumns = 4
)

func (c *lookupConstraintComponent) Evaluate(
	sum m31.QM31,
	traces *Traces,
	randomCoeff m31.QM31,
) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(LookupTraceColumns, LookupInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	values := make([]m31.QM31, len(c.preprocessed))
	for i, column := range c.preprocessed {
		values[i] = traces.Get(column)
	}

	rangeCheckSum, err := c.qm31.Combine(c.interactionElements, values)
	if err != nil {
		panic(err)
	}

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	enabler := traceSampledValues.Get(0)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	curr := interactionSampledValues.Partial(c.qm31, 0, 1)
	prev := interactionSampledValues.Partial(c.qm31, 0, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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
