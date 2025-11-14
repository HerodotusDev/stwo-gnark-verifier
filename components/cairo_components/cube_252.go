package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
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
	LogSize uints.U8
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
	api frontend.API,
	qm31 *m31.QM31Chip,
	rangeCheck9Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	cube252Elements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim Cube252Claim,
	interactionClaim Cube252InteractionClaim,
) *Cube252Component {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &Cube252Component{
		qm31:                 qm31,
		rangeCheck9Elements:  rangeCheck9Elements,
		rangeCheck19Elements: rangeCheck19Elements,
		cube252Elements:      cube252Elements,
		claimedSum:           interactionClaim.ClaimedSum,
		columnSizeInv:        qm31.Inverse(columnSize),
		vanishEvalInv:        vanishEvalInv,
	}
}

func (c *Cube252Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(cube252TraceColumns, cube252InteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	var inputLimbs [10]m31.QM31
	for i := 0; i < 10; i++ {
		inputLimbs[i] = traceSampledValues.Get(i)
	}

	var lowLimbs [9]m31.QM31
	var highLimbs [9]m31.QM31
	for i := 0; i < 9; i++ {
		lowLimbs[i] = traceSampledValues.Get(10 + 2*i)
		highLimbs[i] = traceSampledValues.Get(11 + 2*i)
	}

	mulResSquared := traceSampledValues.Slice(28, 28)
	kSquared := traceSampledValues.Get(56)
	carriesSquared := traceSampledValues.Slice(57, 27)

	mulResCubed := traceSampledValues.Slice(84, 28)
	kCubed := traceSampledValues.Get(112)
	carriesCubed := traceSampledValues.Slice(113, 27)

	enabler := traceSampledValues.Get(140)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 50)
	for block := 0; block < 49; block++ {
		partials[block] = interactionSampledValues.Partial(c.qm31, block*4, 0)
	}
	// Last block (start=196) has previous/current samples.
	partials[49] = interactionSampledValues.Partial(c.qm31, 196, 1)
	prevNeg := interactionSampledValues.Partial(c.qm31, 196, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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
