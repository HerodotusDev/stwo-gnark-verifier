package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	poseidon3PartialRoundsTraceColumns       = 169
	poseidon3PartialRoundsInteractionColumns = 36
)

type Poseidon3PartialRoundsChainClaim struct {
	LogSize uints.U8
}

type Poseidon3PartialRoundsChainInteractionClaim struct {
	ClaimedSum m31.QM31
}

type Poseidon3PartialRoundsChainComponent struct {
	qm31 *m31.QM31Chip

	poseidonRoundKeysElements      m31.InteractionElements
	cube252Elements                m31.InteractionElements
	range4444Elements              m31.InteractionElements
	range44Elements                m31.InteractionElements
	rangeFelt252Width27Elements    m31.InteractionElements
	poseidon3PartialRoundsElements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewPoseidon3PartialRoundsChain(
	api frontend.API,
	qm31 *m31.QM31Chip,
	poseidonRoundKeysElements m31.InteractionElements,
	cube252Elements m31.InteractionElements,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	rangeFelt252Width27Elements m31.InteractionElements,
	poseidon3PartialRoundsElements m31.InteractionElements,
	claim Poseidon3PartialRoundsChainClaim,
	interactionClaim Poseidon3PartialRoundsChainInteractionClaim,
) *Poseidon3PartialRoundsChainComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &Poseidon3PartialRoundsChainComponent{
		qm31:                           qm31,
		poseidonRoundKeysElements:      poseidonRoundKeysElements,
		cube252Elements:                cube252Elements,
		range4444Elements:              range4444Elements,
		range44Elements:                range44Elements,
		rangeFelt252Width27Elements:    rangeFelt252Width27Elements,
		poseidon3PartialRoundsElements: poseidon3PartialRoundsElements,
		claimedSum:                     interactionClaim.ClaimedSum,
		columnSizeInv:                  qm31.Inverse(columnSize),
		vanishEvalInv:                  qm31.One(),
	}
}

func (c *Poseidon3PartialRoundsChainComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 { // FORMAT
	traceSampledValues, interactionSampledValues := traces.Take(poseidon3PartialRoundsTraceColumns, poseidon3PartialRoundsInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputLimbs := traceSampledValues.Slice(0, 42)
	poseidonRoundKeysOutputs := traceSampledValues.Slice(42, 30)
	cubeOutputs0 := traceSampledValues.Slice(72, 10)
	combination0 := traceSampledValues.Slice(82, 10)
	pCoef0 := traceSampledValues.Get(92)
	combination1 := traceSampledValues.Slice(93, 10)
	pCoef1 := traceSampledValues.Get(103)
	cubeOutputs1 := traceSampledValues.Slice(104, 10)
	combination2 := traceSampledValues.Slice(114, 10)
	pCoef2 := traceSampledValues.Get(124)
	combination3 := traceSampledValues.Slice(125, 10)
	pCoef3 := traceSampledValues.Get(135)
	cubeOutputs2 := traceSampledValues.Slice(136, 10)
	combination4 := traceSampledValues.Slice(146, 10)
	pCoef4 := traceSampledValues.Get(156)
	combination5 := traceSampledValues.Slice(157, 10)
	pCoef5 := traceSampledValues.Get(167)
	enabler := traceSampledValues.Get(168)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 9)
	for i := 0; i < 8; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	partials[8] = interactionSampledValues.Partial(c.qm31, 32, 1)
	prevPartial := interactionSampledValues.Partial(c.qm31, 32, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	enablerConstraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	values := make([]m31.QM31, 0, 31)
	values = append(values, inputLimbs[1])
	values = append(values, poseidonRoundKeysOutputs[:30]...)
	poseidonRoundKeysSum, err := c.qm31.Combine(c.poseidonRoundKeysElements, values)
	if err != nil {
		panic(err)
	}

	var inputRound0 [50]m31.QM31
	for i := 0; i < 40; i++ {
		inputRound0[i] = inputLimbs[i+2]
	}
	for i := 0; i < 10; i++ {
		inputRound0[40+i] = poseidonRoundKeysOutputs[i]
	}
	var cubeRound0 [10]m31.QM31
	var combFirst0 [10]m31.QM31
	var combSecond0 [10]m31.QM31
	for i := 0; i < 10; i++ {
		cubeRound0[i] = cubeOutputs0[i]
		combFirst0[i] = combination0[i]
		combSecond0[i] = combination1[i]
	}

	round0 := sub.PoseidonPartialRoundEvaluate(
		c.qm31,
		inputRound0,
		cubeRound0,
		combFirst0,
		combSecond0,
		pCoef0,
		pCoef1,
		c.cube252Elements,
		c.range4444Elements,
		c.range44Elements,
		c.rangeFelt252Width27Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = round0.Sum

	var inputRound1 [50]m31.QM31
	for i := 0; i < 20; i++ {
		inputRound1[i] = inputLimbs[i+22]
	}
	for i := 0; i < 10; i++ {
		inputRound1[20+i] = cubeOutputs0[i]
	}
	for i := 0; i < 10; i++ {
		inputRound1[30+i] = combination1[i]
	}
	for i := 0; i < 10; i++ {
		inputRound1[40+i] = poseidonRoundKeysOutputs[i+10]
	}

	var cubeRound1 [10]m31.QM31
	var combFirst1 [10]m31.QM31
	var combSecond1 [10]m31.QM31
	for i := 0; i < 10; i++ {
		cubeRound1[i] = cubeOutputs1[i]
		combFirst1[i] = combination2[i]
		combSecond1[i] = combination3[i]
	}

	round1 := sub.PoseidonPartialRoundEvaluate(
		c.qm31,
		inputRound1,
		cubeRound1,
		combFirst1,
		combSecond1,
		pCoef2,
		pCoef3,
		c.cube252Elements,
		c.range4444Elements,
		c.range44Elements,
		c.rangeFelt252Width27Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = round1.Sum

	var inputRound2 [50]m31.QM31
	for i := 0; i < 10; i++ {
		inputRound2[i] = cubeOutputs0[i]
	}
	for i := 0; i < 10; i++ {
		inputRound2[10+i] = combination1[i]
	}
	for i := 0; i < 10; i++ {
		inputRound2[20+i] = cubeOutputs1[i]
	}
	for i := 0; i < 10; i++ {
		inputRound2[30+i] = combination3[i]
	}
	for i := 0; i < 10; i++ {
		inputRound2[40+i] = poseidonRoundKeysOutputs[i+20]
	}

	var cubeRound2 [10]m31.QM31
	var combFirst2 [10]m31.QM31
	var combSecond2 [10]m31.QM31
	for i := 0; i < 10; i++ {
		cubeRound2[i] = cubeOutputs2[i]
		combFirst2[i] = combination4[i]
		combSecond2[i] = combination5[i]
	}

	round2 := sub.PoseidonPartialRoundEvaluate(
		c.qm31,
		inputRound2,
		cubeRound2,
		combFirst2,
		combSecond2,
		pCoef4,
		pCoef5,
		c.cube252Elements,
		c.range4444Elements,
		c.range44Elements,
		c.rangeFelt252Width27Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = round2.Sum

	sum16, err := c.qm31.Combine(c.poseidon3PartialRoundsElements, inputLimbs)
	if err != nil {
		panic(err)
	}

	values = values[:0]
	values = append(values, inputLimbs[0])
	values = append(values, c.qm31.Add(inputLimbs[1], c.qm31.One()))
	values = append(values, cubeOutputs1...)
	values = append(values, combination3...)
	values = append(values, cubeOutputs2...)
	values = append(values, combination5...)
	sum17, err := c.qm31.Combine(c.poseidon3PartialRoundsElements, values)
	if err != nil {
		panic(err)
	}

	sum = c.lookupConstraints(
		sum,
		randomCoeff,
		partials,
		prevPartial,
		poseidonRoundKeysSum,
		round0.CubeLookupSum,
		round0.Range4444Sums[0],
		round0.Range4444Sums[1],
		round0.Range44Sum,
		round0.RangeFeltSum,
		round1.CubeLookupSum,
		round1.Range4444Sums[0],
		round1.Range4444Sums[1],
		round1.Range44Sum,
		round1.RangeFeltSum,
		round2.CubeLookupSum,
		round2.Range4444Sums[0],
		round2.Range4444Sums[1],
		round2.Range44Sum,
		round2.RangeFeltSum,
		sum16,
		sum17,
		enabler,
	)

	return sum
}

func (c *Poseidon3PartialRoundsChainComponent) lookupConstraints(
	sum m31.QM31,
	randomCoeff m31.QM31,
	partials []m31.QM31,
	prevPartial m31.QM31,
	poseidonRoundKeysSum m31.QM31,
	cube252Sum1 m31.QM31,
	range4444Sum2 m31.QM31,
	range4444Sum3 m31.QM31,
	range44Sum4 m31.QM31,
	rangeFeltSum5 m31.QM31,
	cube252Sum6 m31.QM31,
	range4444Sum7 m31.QM31,
	range4444Sum8 m31.QM31,
	range44Sum9 m31.QM31,
	rangeFeltSum10 m31.QM31,
	cube252Sum11 m31.QM31,
	range4444Sum12 m31.QM31,
	range4444Sum13 m31.QM31,
	range44Sum14 m31.QM31,
	rangeFeltSum15 m31.QM31,
	sum16 m31.QM31,
	sum17 m31.QM31,
	enabler m31.QM31,
) m31.QM31 {
	if len(partials) != 9 {
		panic("poseidon 3 partial rounds expects 9 partials")
	}

	tmp0 := partials[0]
	constraint := c.qm31.Mul(tmp0, poseidonRoundKeysSum)
	constraint = c.qm31.Mul(constraint, cube252Sum1)
	constraint = c.qm31.Sub(constraint, poseidonRoundKeysSum)
	constraint = c.qm31.Sub(constraint, cube252Sum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp1 := partials[1]
	diff := c.qm31.Sub(tmp1, tmp0)
	constraint = c.qm31.Mul(diff, range4444Sum2)
	constraint = c.qm31.Mul(constraint, range4444Sum3)
	constraint = c.qm31.Sub(constraint, range4444Sum2)
	constraint = c.qm31.Sub(constraint, range4444Sum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp2 := partials[2]
	diff = c.qm31.Sub(tmp2, tmp1)
	constraint = c.qm31.Mul(diff, range44Sum4)
	constraint = c.qm31.Mul(constraint, rangeFeltSum5)
	constraint = c.qm31.Sub(constraint, range44Sum4)
	constraint = c.qm31.Sub(constraint, rangeFeltSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp3 := partials[3]
	diff = c.qm31.Sub(tmp3, tmp2)
	constraint = c.qm31.Mul(diff, cube252Sum6)
	constraint = c.qm31.Mul(constraint, range4444Sum7)
	constraint = c.qm31.Sub(constraint, cube252Sum6)
	constraint = c.qm31.Sub(constraint, range4444Sum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp4 := partials[4]
	diff = c.qm31.Sub(tmp4, tmp3)
	constraint = c.qm31.Mul(diff, range4444Sum8)
	constraint = c.qm31.Mul(constraint, range44Sum9)
	constraint = c.qm31.Sub(constraint, range4444Sum8)
	constraint = c.qm31.Sub(constraint, range44Sum9)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp5 := partials[5]
	diff = c.qm31.Sub(tmp5, tmp4)
	constraint = c.qm31.Mul(diff, rangeFeltSum10)
	constraint = c.qm31.Mul(constraint, cube252Sum11)
	constraint = c.qm31.Sub(constraint, rangeFeltSum10)
	constraint = c.qm31.Sub(constraint, cube252Sum11)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp6 := partials[6]
	diff = c.qm31.Sub(tmp6, tmp5)
	constraint = c.qm31.Mul(diff, range4444Sum12)
	constraint = c.qm31.Mul(constraint, range4444Sum13)
	constraint = c.qm31.Sub(constraint, range4444Sum12)
	constraint = c.qm31.Sub(constraint, range4444Sum13)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp7 := partials[7]
	diff = c.qm31.Sub(tmp7, tmp6)
	constraint = c.qm31.Mul(diff, range44Sum14)
	constraint = c.qm31.Mul(constraint, rangeFeltSum15)
	constraint = c.qm31.Sub(constraint, range44Sum14)
	constraint = c.qm31.Sub(constraint, rangeFeltSum15)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp8 := partials[8]
	diff = c.qm31.Sub(tmp8, tmp7)
	diff = c.qm31.Sub(diff, prevPartial)
	columnAdjust := c.qm31.Mul(c.claimedSum, c.columnSizeInv)
	diff = c.qm31.Add(diff, columnAdjust)
	constraint = c.qm31.Mul(diff, sum16)
	constraint = c.qm31.Mul(constraint, sum17)
	constraint = c.qm31.Add(constraint, c.qm31.Mul(sum16, enabler))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(sum17, enabler))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
