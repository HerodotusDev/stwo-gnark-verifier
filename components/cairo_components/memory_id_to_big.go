package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	memoryIdToBigSeqShift                = uint64(1073741824) // 2^30
	memoryIdToBigBigTraceCols            = 29
	memoryIdToBigSmallTraceCols          = 9
	memoryIdToBigBigInteractionColumns   = 32
	memoryIdToBigSmallInteractionColumns = 20
)

// ╔══════════════════════════════════╗
// ║      Memory Id To Big (Big)      ║
// ╚══════════════════════════════════╝

type MemoryIdToBigBigClaim struct {
	LogSize frontend.Variable
	Offset  uint32
}

type MemoryIdToBigBigInteractionClaim struct {
	ClaimedSum m31.QM31
}

type MemoryIdToBigBigComponent struct {
	qm31 *m31.QM31Chip

	lookupElements     m31.InteractionElements
	rangeCheckElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31

	logSize   frontend.Variable
	seqAddend m31.QM31
}

func NewMemoryIdToBigBigComponent(
	api frontend.API,
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim MemoryIdToBigBigClaim,
	interactionClaim MemoryIdToBigBigInteractionClaim,
) MemoryIdToBigBigComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	offsetQM := m31.NewQM31FromM31(m31.NewM31Unchecked(claim.Offset))
	seqAddend := qm31.Add(qm31Const(memoryIdToBigSeqShift), offsetQM)

	return MemoryIdToBigBigComponent{
		qm31:               qm31,
		lookupElements:     lookupElements,
		rangeCheckElements: rangeCheckElements,
		claimedSum:         interactionClaim.ClaimedSum,
		columnSizeInv:      columnSizeInv,
		vanishEvalInv:      vanishEvalInv,
		logSize:            claim.LogSize,
		seqAddend:          seqAddend,
	}
}

func (c MemoryIdToBigBigComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(memoryIdToBigBigTraceCols, memoryIdToBigBigInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seq := traces.Get(NewPreprocessedColumnSeq(c.logSize))
	seqWithOffset := c.qm31.Add(seq, c.seqAddend)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	// Range-check intermediates come in pairs of limbs.
	rangeComb := func(first, second int) m31.QM31 {
		res, err := c.qm31.Combine(c.rangeCheckElements, []m31.QM31{traceSampledValues.Get(first), traceSampledValues.Get(second)})
		if err != nil {
			panic(err)
		}
		return res
	}

	rangeIntermediates := []m31.QM31{
		rangeComb(0, 1),
		rangeComb(2, 3),
		rangeComb(4, 5),
		rangeComb(6, 7),
		rangeComb(8, 9),
		rangeComb(10, 11),
		rangeComb(12, 13),
		rangeComb(14, 15),
		rangeComb(16, 17),
		rangeComb(18, 19),
		rangeComb(20, 21),
		rangeComb(22, 23),
		rangeComb(24, 25),
		rangeComb(26, 27),
	}

	// Memory lookup combination (alpha linear combination).
	values := make([]m31.QM31, 1+28)
	values[0] = seqWithOffset
	copy(values[1:], traceSampledValues.Slice(0, 28))

	lookupCombination, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := []m31.QM31{
		interactionSampledValues.Partial(c.qm31, 0, 0),
		interactionSampledValues.Partial(c.qm31, 4, 0),
		interactionSampledValues.Partial(c.qm31, 8, 0),
		interactionSampledValues.Partial(c.qm31, 12, 0),
		interactionSampledValues.Partial(c.qm31, 16, 0),
		interactionSampledValues.Partial(c.qm31, 20, 0),
		interactionSampledValues.Partial(c.qm31, 24, 0),
	}
	partialCurrent := interactionSampledValues.Partial(c.qm31, 28, 1)
	partialPrevious := interactionSampledValues.Partial(c.qm31, 28, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	// Constraint 0
	term := c.qm31.Mul(rangeIntermediates[0], rangeIntermediates[1])
	constraint := c.qm31.Mul(partials[0], term)
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rangeIntermediates[1], rangeIntermediates[0]))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraints 1-6 follow the same pattern.
	for i := 1; i < 7; i++ {
		left := 2 * i
		right := left + 1

		diff := c.qm31.Sub(partials[i], partials[i-1])
		term = c.qm31.Mul(rangeIntermediates[left], rangeIntermediates[right])
		constraint = c.qm31.Mul(diff, term)
		constraint = c.qm31.Sub(constraint, c.qm31.Add(rangeIntermediates[right], rangeIntermediates[left]))
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	// Constraint 7
	diff := c.qm31.Sub(partialCurrent, partialPrevious)
	diff = c.qm31.Sub(diff, partials[len(partials)-1])
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint = c.qm31.Mul(diff, lookupCombination)
	constraint = c.qm31.Add(constraint, traceSampledValues.Get(28))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}

// ╔══════════════════════════════════╗
// ║     Memory Id To Big (Small)     ║
// ╚══════════════════════════════════╝

type MemoryIdToBigSmallClaim struct {
	LogSize frontend.Variable
}

type MemoryIdToBigSmallInteractionClaim struct {
	ClaimedSum m31.QM31
}

type MemoryIdToBigSmallComponent struct {
	qm31 *m31.QM31Chip

	lookupElements     m31.InteractionElements
	rangeCheckElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31

	logSize frontend.Variable
}

func NewMemoryIdToBigSmallComponent(
	api frontend.API,
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim MemoryIdToBigSmallClaim,
	interactionClaim MemoryIdToBigSmallInteractionClaim,
) MemoryIdToBigSmallComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return MemoryIdToBigSmallComponent{
		qm31:               qm31,
		lookupElements:     lookupElements,
		rangeCheckElements: rangeCheckElements,
		claimedSum:         interactionClaim.ClaimedSum,
		columnSizeInv:      columnSizeInv,
		vanishEvalInv:      vanishEvalInv,
		logSize:            claim.LogSize,
	}
}

func (c MemoryIdToBigSmallComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(memoryIdToBigSmallTraceCols, memoryIdToBigSmallInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seq := traces.Get(NewPreprocessedColumnSeq(c.logSize))

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	one := c.qm31.One()

	rangeComb := func(first, second int) m31.QM31 {
		res, err := c.qm31.Combine(c.rangeCheckElements, []m31.QM31{traceSampledValues.Get(first), traceSampledValues.Get(second)})
		if err != nil {
			panic(err)
		}
		return res
	}

	rangeIntermediates := []m31.QM31{
		rangeComb(0, 1),
		rangeComb(2, 3),
		rangeComb(4, 5),
		rangeComb(6, 7),
	}

	values := make([]m31.QM31, 9)
	values[0] = seq
	copy(values[1:], traceSampledValues.Slice(0, 8))
	lookupCombination, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 0)
	part4 := interactionSampledValues.Partial(c.qm31, 16, 1)
	part4Prev := interactionSampledValues.Partial(c.qm31, 16, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	// Constraint 0
	constraint := c.qm31.Mul(part0, rangeIntermediates[0])
	constraint = c.qm31.Sub(constraint, one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 1
	diff := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff, rangeIntermediates[1])
	constraint = c.qm31.Sub(constraint, one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 2
	diff = c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff, rangeIntermediates[2])
	constraint = c.qm31.Sub(constraint, one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 3
	diff = c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff, rangeIntermediates[3])
	constraint = c.qm31.Sub(constraint, one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// Constraint 4
	diff = c.qm31.Sub(part4, part4Prev)
	diff = c.qm31.Sub(diff, part3)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	constraint = c.qm31.Mul(diff, lookupCombination)
	constraint = c.qm31.Add(constraint, traceSampledValues.Get(8))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
