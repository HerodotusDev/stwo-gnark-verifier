package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	memoryIdToBigSeqShift       = uint64(1073741824) // 2^30
	memoryIdToBigBigTraceCols   = 29
	memoryIdToBigSmallTraceCols = 9
)

// ╔══════════════════════════════════╗
// ║      Memory Id To Big (Big)      ║
// ╚══════════════════════════════════╝

type MemoryIdToBigBigClaim struct {
	LogSize uint32
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

	logSize   uint32
	logSizeU  uints.U8
	seqAddend m31.QM31
}

func NewMemoryIdToBigBigComponent(
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	claim MemoryIdToBigBigClaim,
	interactionClaim MemoryIdToBigBigInteractionClaim,
) *MemoryIdToBigBigComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM)

	offsetQM := m31.NewQM31FromM31(m31.NewM31Unchecked(claim.Offset))
	seqAddend := qm31.Add(qm31Const(memoryIdToBigSeqShift), offsetQM)

	return &MemoryIdToBigBigComponent{
		qm31:               qm31,
		lookupElements:     lookupElements,
		rangeCheckElements: rangeCheckElements,
		claimedSum:         interactionClaim.ClaimedSum,
		columnSizeInv:      columnSizeInv,
		vanishEvalInv:      qm31.One(),
		logSize:            claim.LogSize,
		logSizeU:           uints.NewU8(uint8(claim.LogSize)),
		seqAddend:          seqAddend,
	}
}

func (c *MemoryIdToBigBigComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(29, 32)

	seq := traces.Get(NewPreprocessedColumnSeq(c.logSizeU))
	seqWithOffset := c.qm31.Add(seq, c.seqAddend)

	trace := make([]m31.QM31, memoryIdToBigBigTraceCols)
	for i := 0; i < memoryIdToBigBigTraceCols; i++ {
		trace[i] = traceSampledValues[i][0]
	}

	// Range-check intermediates come in pairs of limbs.
	rangeComb := func(first, second int) m31.QM31 {
		res, err := c.qm31.Combine(c.rangeCheckElements, []m31.QM31{trace[first], trace[second]})
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
	copy(values[1:], trace[:28])

	lookupCombination, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	// Partial evaluations from interaction columns.
	partial := func(start int, offset int) m31.QM31 {
		return c.qm31.FromPartialEvals(
			interactionSampledValues[start][offset],
			interactionSampledValues[start+1][offset],
			interactionSampledValues[start+2][offset],
			interactionSampledValues[start+3][offset],
		)
	}

	partials := []m31.QM31{
		partial(0, 0),
		partial(4, 0),
		partial(8, 0),
		partial(12, 0),
		partial(16, 0),
		partial(20, 0),
		partial(24, 0),
	}
	partialCurrent := partial(28, 1)
	partialPrevious := partial(28, 0)

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
	constraint = c.qm31.Add(constraint, trace[28])
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}

// ╔══════════════════════════════════╗
// ║     Memory Id To Big (Small)     ║
// ╚══════════════════════════════════╝

type MemoryIdToBigSmallClaim struct {
	LogSize uint32
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

	logSize  uint32
	logSizeU uints.U8
}

func NewMemoryIdToBigSmallComponent(
	qm31 *m31.QM31Chip,
	lookupElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	claim MemoryIdToBigSmallClaim,
	interactionClaim MemoryIdToBigSmallInteractionClaim,
) *MemoryIdToBigSmallComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM)

	return &MemoryIdToBigSmallComponent{
		qm31:               qm31,
		lookupElements:     lookupElements,
		rangeCheckElements: rangeCheckElements,
		claimedSum:         interactionClaim.ClaimedSum,
		columnSizeInv:      columnSizeInv,
		vanishEvalInv:      qm31.One(),
		logSize:            claim.LogSize,
		logSizeU:           uints.NewU8(uint8(claim.LogSize)),
	}
}

func (c *MemoryIdToBigSmallComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(9, 20)

	seq := traces.Get(NewPreprocessedColumnSeq(c.logSizeU))

	trace := make([]m31.QM31, memoryIdToBigSmallTraceCols)
	for i := 0; i < memoryIdToBigSmallTraceCols; i++ {
		trace[i] = traceSampledValues[i][0]
	}

	rangeComb := func(first, second int) m31.QM31 {
		res, err := c.qm31.Combine(c.rangeCheckElements, []m31.QM31{trace[first], trace[second]})
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
	copy(values[1:], trace[:8])
	lookupCombination, err := c.qm31.Combine(c.lookupElements, values)
	if err != nil {
		panic(err)
	}

	partial := func(start int, offset int) m31.QM31 {
		return c.qm31.FromPartialEvals(
			interactionSampledValues[start][offset],
			interactionSampledValues[start+1][offset],
			interactionSampledValues[start+2][offset],
			interactionSampledValues[start+3][offset],
		)
	}

	part0 := partial(0, 0)
	part1 := partial(4, 0)
	part2 := partial(8, 0)
	part3 := partial(12, 0)
	part4 := partial(16, 1)
	part4Prev := partial(16, 0)

	one := c.qm31.One()

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
	constraint = c.qm31.Add(constraint, trace[8])
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
