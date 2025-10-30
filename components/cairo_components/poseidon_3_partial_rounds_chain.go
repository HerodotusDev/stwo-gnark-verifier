package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	poseidon3PartialRoundsTraceColumns       = 169
	poseidon3PartialRoundsInteractionColumns = 36
)

type Poseidon3PartialRoundsChainClaim struct {
	LogSize uint32
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
	columnSize := uint64(1) << claim.LogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &Poseidon3PartialRoundsChainComponent{
		qm31:                           qm31,
		poseidonRoundKeysElements:      poseidonRoundKeysElements,
		cube252Elements:                cube252Elements,
		range4444Elements:              range4444Elements,
		range44Elements:                range44Elements,
		rangeFelt252Width27Elements:    rangeFelt252Width27Elements,
		poseidon3PartialRoundsElements: poseidon3PartialRoundsElements,
		claimedSum:                     interactionClaim.ClaimedSum,
		columnSizeInv:                  qm31.Inverse(columnSizeQM),
		vanishEvalInv:                  qm31.One(),
	}
}

func (c *Poseidon3PartialRoundsChainComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	if len(traceSampledValues) != poseidon3PartialRoundsTraceColumns {
		panic("poseidon_3_partial_rounds_chain expects 169 trace columns")
	}
	if len(interactionSampledValues) != poseidon3PartialRoundsInteractionColumns {
		panic("poseidon_3_partial_rounds_chain expects 36 interaction columns")
	}

	getTrace := func(index int) m31.QM31 {
		column := traceSampledValues[index]
		if len(column) == 0 {
			panic("missing trace sample")
		}
		return column[0]
	}
	gatherTrace := func(start, count int) []m31.QM31 {
		values := make([]m31.QM31, count)
		for i := 0; i < count; i++ {
			values[i] = getTrace(start + i)
		}
		return values
	}

	inputLimbs := gatherTrace(0, 42)
	poseidonRoundKeysOutputs := gatherTrace(42, 30)
	cubeOutputs0 := gatherTrace(72, 10)
	combination0 := gatherTrace(82, 10)
	pCoef0 := getTrace(92)
	combination1 := gatherTrace(93, 10)
	pCoef1 := getTrace(103)
	cubeOutputs1 := gatherTrace(104, 10)
	combination2 := gatherTrace(114, 10)
	pCoef2 := getTrace(124)
	combination3 := gatherTrace(125, 10)
	pCoef3 := getTrace(135)
	cubeOutputs2 := gatherTrace(136, 10)
	combination4 := gatherTrace(146, 10)
	pCoef4 := getTrace(156)
	combination5 := gatherTrace(157, 10)
	pCoef5 := getTrace(167)
	enabler := getTrace(168)

	// Constraint: enabler is boolean.
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
		interactionSampledValues,
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
	interactionSampledValues [][]m31.QM31,
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
	getInteraction := func(index int) []m31.QM31 {
		column := interactionSampledValues[index]
		if len(column) == 0 {
			panic("missing interaction value")
		}
		return column
	}

	traceVals := make([]m31.QM31, 36)
	traceNegVals := make([]m31.QM31, 4)
	for i := 0; i < 32; i++ {
		traceVals[i] = getInteraction(i)[0]
	}
	for i := 0; i < 4; i++ {
		values := getInteraction(32 + i)
		if len(values) != 2 {
			panic("expected two interaction partial evaluations")
		}
		traceNegVals[i] = values[0]
		traceVals[32+i] = values[1]
	}

	fp := func(a, b, cVal, d m31.QM31) m31.QM31 {
		return c.qm31.FromPartialEvals(a, b, cVal, d)
	}

	tmp0 := fp(traceVals[0], traceVals[1], traceVals[2], traceVals[3])
	constraint := c.qm31.Mul(tmp0, poseidonRoundKeysSum)
	constraint = c.qm31.Mul(constraint, cube252Sum1)
	constraint = c.qm31.Sub(constraint, poseidonRoundKeysSum)
	constraint = c.qm31.Sub(constraint, cube252Sum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp1 := fp(traceVals[4], traceVals[5], traceVals[6], traceVals[7])
	diff := c.qm31.Sub(tmp1, tmp0)
	constraint = c.qm31.Mul(diff, range4444Sum2)
	constraint = c.qm31.Mul(constraint, range4444Sum3)
	constraint = c.qm31.Sub(constraint, range4444Sum2)
	constraint = c.qm31.Sub(constraint, range4444Sum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp2 := fp(traceVals[8], traceVals[9], traceVals[10], traceVals[11])
	diff = c.qm31.Sub(tmp2, tmp1)
	constraint = c.qm31.Mul(diff, range44Sum4)
	constraint = c.qm31.Mul(constraint, rangeFeltSum5)
	constraint = c.qm31.Sub(constraint, range44Sum4)
	constraint = c.qm31.Sub(constraint, rangeFeltSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp3 := fp(traceVals[12], traceVals[13], traceVals[14], traceVals[15])
	diff = c.qm31.Sub(tmp3, tmp2)
	constraint = c.qm31.Mul(diff, cube252Sum6)
	constraint = c.qm31.Mul(constraint, range4444Sum7)
	constraint = c.qm31.Sub(constraint, cube252Sum6)
	constraint = c.qm31.Sub(constraint, range4444Sum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp4 := fp(traceVals[16], traceVals[17], traceVals[18], traceVals[19])
	diff = c.qm31.Sub(tmp4, tmp3)
	constraint = c.qm31.Mul(diff, range4444Sum8)
	constraint = c.qm31.Mul(constraint, range44Sum9)
	constraint = c.qm31.Sub(constraint, range4444Sum8)
	constraint = c.qm31.Sub(constraint, range44Sum9)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp5 := fp(traceVals[20], traceVals[21], traceVals[22], traceVals[23])
	diff = c.qm31.Sub(tmp5, tmp4)
	constraint = c.qm31.Mul(diff, rangeFeltSum10)
	constraint = c.qm31.Mul(constraint, cube252Sum11)
	constraint = c.qm31.Sub(constraint, rangeFeltSum10)
	constraint = c.qm31.Sub(constraint, cube252Sum11)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp6 := fp(traceVals[24], traceVals[25], traceVals[26], traceVals[27])
	diff = c.qm31.Sub(tmp6, tmp5)
	constraint = c.qm31.Mul(diff, range4444Sum12)
	constraint = c.qm31.Mul(constraint, range4444Sum13)
	constraint = c.qm31.Sub(constraint, range4444Sum12)
	constraint = c.qm31.Sub(constraint, range4444Sum13)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp7 := fp(traceVals[28], traceVals[29], traceVals[30], traceVals[31])
	diff = c.qm31.Sub(tmp7, tmp6)
	constraint = c.qm31.Mul(diff, range44Sum14)
	constraint = c.qm31.Mul(constraint, rangeFeltSum15)
	constraint = c.qm31.Sub(constraint, range44Sum14)
	constraint = c.qm31.Sub(constraint, rangeFeltSum15)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp8 := fp(traceVals[32], traceVals[33], traceVals[34], traceVals[35])
	diff = c.qm31.Sub(tmp8, tmp7)
	prevShift := fp(traceNegVals[0], traceNegVals[1], traceNegVals[2], traceNegVals[3])
	diff = c.qm31.Sub(diff, prevShift)
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
