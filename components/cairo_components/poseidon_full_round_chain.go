package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	poseidonFullRoundTraceColumns       = 126
	poseidonFullRoundInteractionColumns = 24
)

type PoseidonFullRoundChainClaim struct {
	LogSize uints.U8
}

type PoseidonFullRoundChainInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PoseidonFullRoundChainComponent struct {
	qm31 *m31.QM31Chip

	cube252Elements           m31.InteractionElements
	poseidonRoundKeysElements m31.InteractionElements
	range33333Elements        m31.InteractionElements
	fullRoundChainElements    m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewPoseidonFullRoundChain(
	api frontend.API,
	qm31 *m31.QM31Chip,
	cube252Elements m31.InteractionElements,
	poseidonRoundKeysElements m31.InteractionElements,
	range33333Elements m31.InteractionElements,
	fullRoundChainElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim PoseidonFullRoundChainClaim,
	interactionClaim PoseidonFullRoundChainInteractionClaim,
) *PoseidonFullRoundChainComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &PoseidonFullRoundChainComponent{
		qm31:                      qm31,
		cube252Elements:           cube252Elements,
		poseidonRoundKeysElements: poseidonRoundKeysElements,
		range33333Elements:        range33333Elements,
		fullRoundChainElements:    fullRoundChainElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSize),
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c *PoseidonFullRoundChainComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(poseidonFullRoundTraceColumns, poseidonFullRoundInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputLimbs := traceSampledValues.Slice(0, 32)
	cubeOutputs0 := traceSampledValues.Slice(32, 10)
	cubeOutputs1 := traceSampledValues.Slice(42, 10)
	cubeOutputs2 := traceSampledValues.Slice(52, 10)
	poseidonRoundKeys := traceSampledValues.Slice(62, 30)
	combination0 := traceSampledValues.Slice(92, 10)
	pCoef0 := traceSampledValues.Get(102)
	combination1 := traceSampledValues.Slice(103, 10)
	pCoef1 := traceSampledValues.Get(113)
	combination2 := traceSampledValues.Slice(114, 10)
	pCoef2 := traceSampledValues.Get(124)
	enabler := traceSampledValues.Get(125)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 6)
	for i := 0; i < 5; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	// Last block (start=20) has previous/current samples.
	partials[5] = interactionSampledValues.Partial(c.qm31, 20, 1)
	prevPartial := interactionSampledValues.Partial(c.qm31, 20, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	enablerConstraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	values := make([]m31.QM31, 0, 20)
	values = append(values, inputLimbs[2:12]...)
	values = append(values, cubeOutputs0...)
	cubeSum0, err := c.qm31.Combine(c.cube252Elements, values)
	if err != nil {
		panic(err)
	}

	values = values[:0]
	values = append(values, inputLimbs[12:22]...)
	values = append(values, cubeOutputs1...)
	cubeSum1, err := c.qm31.Combine(c.cube252Elements, values)
	if err != nil {
		panic(err)
	}

	values = values[:0]
	values = append(values, inputLimbs[22:32]...)
	values = append(values, cubeOutputs2...)
	cubeSum2, err := c.qm31.Combine(c.cube252Elements, values)
	if err != nil {
		panic(err)
	}

	values = values[:0]
	values = append(values, inputLimbs[1])
	values = append(values, poseidonRoundKeys...)
	roundKeysSum, err := c.qm31.Combine(c.poseidonRoundKeysElements, values)
	if err != nil {
		panic(err)
	}

	var lcInput0, lcInput1, lcInput2 [40]m31.QM31
	for i := 0; i < 10; i++ {
		lcInput0[i] = cubeOutputs0[i]
		lcInput0[i+10] = cubeOutputs1[i]
		lcInput0[i+20] = cubeOutputs2[i]
		lcInput0[i+30] = poseidonRoundKeys[i]

		lcInput1[i] = cubeOutputs0[i]
		lcInput1[i+10] = cubeOutputs1[i]
		lcInput1[i+20] = cubeOutputs2[i]
		lcInput1[i+30] = poseidonRoundKeys[i+10]

		lcInput2[i] = cubeOutputs0[i]
		lcInput2[i+10] = cubeOutputs1[i]
		lcInput2[i+20] = cubeOutputs2[i]
		lcInput2[i+30] = poseidonRoundKeys[i+20]
	}

	var combArr0 [10]m31.QM31
	var combArr1 [10]m31.QM31
	var combArr2 [10]m31.QM31
	copy(combArr0[:], combination0)
	copy(combArr1[:], combination1)
	copy(combArr2[:], combination2)

	res0 := sub.LinearCombinationN4Coefs3111Evaluate(
		c.qm31,
		lcInput0,
		combArr0,
		pCoef0,
		c.range33333Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = res0.Sum

	res1 := sub.LinearCombinationN4Coefs1M1_1_1Evaluate(
		c.qm31,
		lcInput1,
		combArr1,
		pCoef1,
		c.range33333Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = res1.Sum

	res2 := sub.LinearCombinationN4Coefs11M2_1Evaluate(
		c.qm31,
		lcInput2,
		combArr2,
		pCoef2,
		c.range33333Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = res2.Sum

	values = values[:0]
	values = append(values, inputLimbs...)
	sum10, err := c.qm31.Combine(c.fullRoundChainElements, values)
	if err != nil {
		panic(err)
	}

	values = values[:0]
	values = append(values, inputLimbs[0])
	values = append(values, c.qm31.Add(inputLimbs[1], c.qm31.One()))
	values = append(values, combination0...)
	values = append(values, combination1...)
	values = append(values, combination2...)
	sum11, err := c.qm31.Combine(c.fullRoundChainElements, values)
	if err != nil {
		panic(err)
	}

	sum = c.lookupConstraints(
		sum,
		randomCoeff,
		partials,
		prevPartial,
		cubeSum0,
		cubeSum1,
		cubeSum2,
		roundKeysSum,
		res0.RangeSum0,
		res0.RangeSum1,
		res1.RangeSum0,
		res1.RangeSum1,
		res2.RangeSum0,
		res2.RangeSum1,
		sum10,
		sum11,
		enabler,
	)

	return sum
}

func (c *PoseidonFullRoundChainComponent) lookupConstraints(
	sum m31.QM31,
	randomCoeff m31.QM31,
	partials []m31.QM31,
	prevPartial m31.QM31,
	cubeSum0 m31.QM31,
	cubeSum1 m31.QM31,
	cubeSum2 m31.QM31,
	roundKeysSum m31.QM31,
	rangeSum4 m31.QM31,
	rangeSum5 m31.QM31,
	rangeSum6 m31.QM31,
	rangeSum7 m31.QM31,
	rangeSum8 m31.QM31,
	rangeSum9 m31.QM31,
	sum10 m31.QM31,
	sum11 m31.QM31,
	enabler m31.QM31,
) m31.QM31 {
	tmp0 := partials[0]
	constraint := c.qm31.Mul(tmp0, cubeSum0)
	constraint = c.qm31.Mul(constraint, cubeSum1)
	constraint = c.qm31.Sub(constraint, cubeSum0)
	constraint = c.qm31.Sub(constraint, cubeSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp1 := partials[1]
	diff := c.qm31.Sub(tmp1, tmp0)
	constraint = c.qm31.Mul(diff, cubeSum2)
	constraint = c.qm31.Mul(constraint, roundKeysSum)
	constraint = c.qm31.Sub(constraint, cubeSum2)
	constraint = c.qm31.Sub(constraint, roundKeysSum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp2 := partials[2]
	diff = c.qm31.Sub(tmp2, tmp1)
	constraint = c.qm31.Mul(diff, rangeSum4)
	constraint = c.qm31.Mul(constraint, rangeSum5)
	constraint = c.qm31.Sub(constraint, rangeSum4)
	constraint = c.qm31.Sub(constraint, rangeSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp3 := partials[3]
	diff = c.qm31.Sub(tmp3, tmp2)
	constraint = c.qm31.Mul(diff, rangeSum6)
	constraint = c.qm31.Mul(constraint, rangeSum7)
	constraint = c.qm31.Sub(constraint, rangeSum6)
	constraint = c.qm31.Sub(constraint, rangeSum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp4 := partials[4]
	diff = c.qm31.Sub(tmp4, tmp3)
	constraint = c.qm31.Mul(diff, rangeSum8)
	constraint = c.qm31.Mul(constraint, rangeSum9)
	constraint = c.qm31.Sub(constraint, rangeSum8)
	constraint = c.qm31.Sub(constraint, rangeSum9)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp5 := partials[5]
	diff = c.qm31.Sub(tmp5, tmp4)
	diff = c.qm31.Sub(diff, prevPartial)
	columnAdjust := c.qm31.Mul(c.claimedSum, c.columnSizeInv)
	diff = c.qm31.Add(diff, columnAdjust)

	constraint = c.qm31.Mul(diff, sum10)
	constraint = c.qm31.Mul(constraint, sum11)
	constraint = c.qm31.Add(constraint, c.qm31.Mul(sum10, enabler))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(sum11, enabler))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
