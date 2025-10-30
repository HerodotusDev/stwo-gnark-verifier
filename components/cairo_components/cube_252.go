package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	cube252TraceColumns       = 141
	cube252InteractionColumns = 200
)

var (
	qm31Const512    = m31.NewQM31FromM31(m31.NewM31Unchecked(512))
	qm31Const262144 = m31.NewQM31FromM31(m31.NewM31Unchecked(262144))
)

type Cube252Claim struct {
	LogSize uint32
}

type Cube252InteractionClaim struct {
	ClaimedSum m31.QM31
}

type Cube252Component struct {
	qm31 *m31.QM31Chip

	rangeCheck9Elements  m31.InteractionElements
	rangeCheck19Elements m31.InteractionElements
	cube252Elements      m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewCube252(
	qm31 *m31.QM31Chip,
	rangeCheck9Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	cube252Elements m31.InteractionElements,
	claim Cube252Claim,
	interactionClaim Cube252InteractionClaim,
) *Cube252Component {
	columnSize := uint64(1) << claim.LogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &Cube252Component{
		qm31:                 qm31,
		rangeCheck9Elements:  rangeCheck9Elements,
		rangeCheck19Elements: rangeCheck19Elements,
		cube252Elements:      cube252Elements,
		claimedSum:           interactionClaim.ClaimedSum,
		columnSizeInv:        qm31.Inverse(columnSizeQM),
		vanishEvalInv:        qm31.One(),
	}
}

func (c *Cube252Component) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	if len(traceSampledValues) != cube252TraceColumns {
		panic("cube_252 expects 141 trace columns")
	}
	if len(interactionSampledValues) != cube252InteractionColumns {
		panic("cube_252 expects 200 interaction columns")
	}

	traceVal := func(index int) m31.QM31 {
		col := traceSampledValues[index]
		if len(col) == 0 {
			panic("missing trace sample")
		}
		return col[0]
	}

	gatherTraceRange := func(start, count int) []m31.QM31 {
		values := make([]m31.QM31, count)
		for i := 0; i < count; i++ {
			values[i] = traceVal(start + i)
		}
		return values
	}

	getInteractionCurr := func(index int) m31.QM31 {
		col := interactionSampledValues[index]
		if len(col) == 0 {
			panic("missing interaction sample")
		}
		return col[len(col)-1]
	}

	getInteractionPrev := func(index int) m31.QM31 {
		col := interactionSampledValues[index]
		if len(col) == 0 {
			panic("missing interaction sample")
		}
		if len(col) < 2 {
			return c.qm31.Zero()
		}
		return col[0]
	}

	var inputLimbs [10]m31.QM31
	for i := 0; i < 10; i++ {
		inputLimbs[i] = traceVal(i)
	}

	var lowLimbs [9]m31.QM31
	var highLimbs [9]m31.QM31
	for i := 0; i < 9; i++ {
		lowLimbs[i] = traceVal(10 + 2*i)
		highLimbs[i] = traceVal(11 + 2*i)
	}

	mulResSquared := gatherTraceRange(28, 28)
	kSquared := traceVal(56)
	carriesSquared := gatherTraceRange(57, 27)

	mulResCubed := gatherTraceRange(84, 28)
	kCubed := traceVal(112)
	carriesCubed := gatherTraceRange(113, 27)

	enabler := traceVal(140)

	enablerConstraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	unpackInputs := inputLimbs
	unpackLow := lowLimbs
	unpackHigh := highLimbs

	unpackRes := sub.Felt252UnpackFrom27RangeCheckOutputEvaluate(
		c.qm31,
		unpackInputs,
		unpackLow,
		unpackHigh,
		c.rangeCheck9Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = unpackRes.Sum

	var rangeCheck9Sums [70]m31.QM31
	copy(rangeCheck9Sums[:], unpackRes.RangeCheckSums[:])

	baseLimbs := make([]m31.QM31, 0, 28)
	for i := 0; i < 9; i++ {
		baseLimbs = append(baseLimbs, lowLimbs[i], highLimbs[i], unpackRes.Outputs[i])
	}
	baseLimbs = append(baseLimbs, inputLimbs[9])

	mulSquaredRes := sub.Mul252Evaluate(
		c.qm31,
		baseLimbs,
		baseLimbs,
		mulResSquared,
		kSquared,
		carriesSquared,
		c.rangeCheck9Elements,
		c.rangeCheck19Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = mulSquaredRes.Sum

	copy(rangeCheck9Sums[14:], mulSquaredRes.ResultRangeSums[:])

	var rangeCheck19Sums [98]m31.QM31
	copy(rangeCheck19Sums[28:], mulSquaredRes.CarryRangeSums[:])

	mulCubedRes := sub.Mul252Evaluate(
		c.qm31,
		baseLimbs,
		mulResSquared,
		mulResCubed,
		kCubed,
		carriesCubed,
		c.rangeCheck9Elements,
		c.rangeCheck19Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = mulCubedRes.Sum

	copy(rangeCheck9Sums[56:], mulCubedRes.ResultRangeSums[:])
	copy(rangeCheck19Sums[70:], mulCubedRes.CarryRangeSums[:])

	cubeValues := make([]m31.QM31, 0, 20)
	cubeValues = append(cubeValues, inputLimbs[:]...)
	for i := 0; i < 9; i++ {
		base := 3 * i
		value := mulResCubed[base]
		value = c.qm31.Add(value, c.qm31.Mul(mulResCubed[base+1], qm31Const512))
		value = c.qm31.Add(value, c.qm31.Mul(mulResCubed[base+2], qm31Const262144))
		cubeValues = append(cubeValues, value)
	}
	cubeValues = append(cubeValues, mulResCubed[27])

	cubeSum, err := c.qm31.Combine(c.cube252Elements, cubeValues)
	if err != nil {
		panic(err)
	}

	partials := make([]m31.QM31, 50)
	for block := 0; block < 50; block++ {
		base := block * 4
		partials[block] = c.qm31.FromPartialEvals(
			getInteractionCurr(base),
			getInteractionCurr(base+1),
			getInteractionCurr(base+2),
			getInteractionCurr(base+3),
		)
	}

	prevNeg := c.qm31.FromPartialEvals(
		getInteractionPrev(196),
		getInteractionPrev(197),
		getInteractionPrev(198),
		getInteractionPrev(199),
	)

	applyConstraint := func(total, sumA, sumB m31.QM31) {
		constraint := c.qm31.Mul(total, c.qm31.Mul(sumA, sumB))
		constraint = c.qm31.Sub(constraint, sumA)
		constraint = c.qm31.Sub(constraint, sumB)
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	sumA := rangeCheck9Sums[0]
	sumB := rangeCheck9Sums[1]
	applyConstraint(partials[0], sumA, sumB)

	getRangeSums := func(block int) (m31.QM31, m31.QM31) {
		idx := block * 2
		switch {
		case block >= 1 && block <= 13:
			return rangeCheck9Sums[idx], rangeCheck9Sums[idx+1]
		case block >= 14 && block <= 27:
			return rangeCheck19Sums[idx], rangeCheck19Sums[idx+1]
		case block >= 28 && block <= 34:
			return rangeCheck9Sums[idx], rangeCheck9Sums[idx+1]
		case block >= 35 && block <= 48:
			return rangeCheck19Sums[idx], rangeCheck19Sums[idx+1]
		default:
			panic("invalid block index")
		}
	}

	for block := 1; block < 49; block++ {
		curr := partials[block]
		prev := partials[block-1]
		sumA, sumB := getRangeSums(block)
		diff := c.qm31.Sub(curr, prev)
		applyConstraint(diff, sumA, sumB)
	}

	finalDiff := c.qm31.Sub(partials[49], partials[48])
	finalDiff = c.qm31.Sub(finalDiff, prevNeg)
	finalDiff = c.qm31.Add(finalDiff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	finalConstraint := c.qm31.Mul(finalDiff, cubeSum)
	finalConstraint = c.qm31.Add(finalConstraint, enabler)
	finalConstraint = c.qm31.Mul(finalConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, finalConstraint)

	return sum
}
