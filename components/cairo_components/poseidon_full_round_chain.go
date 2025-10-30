package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

const (
	poseidonFullRoundTraceColumns       = 126
	poseidonFullRoundInteractionColumns = 24
)

type PoseidonFullRoundChainClaim struct {
	LogSize uint32
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
	qm31 *m31.QM31Chip,
	cube252Elements m31.InteractionElements,
	poseidonRoundKeysElements m31.InteractionElements,
	range33333Elements m31.InteractionElements,
	fullRoundChainElements m31.InteractionElements,
	claim PoseidonFullRoundChainClaim,
	interactionClaim PoseidonFullRoundChainInteractionClaim,
) *PoseidonFullRoundChainComponent {
	columnSize := uint64(1) << claim.LogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &PoseidonFullRoundChainComponent{
		qm31:                      qm31,
		cube252Elements:           cube252Elements,
		poseidonRoundKeysElements: poseidonRoundKeysElements,
		range33333Elements:        range33333Elements,
		fullRoundChainElements:    fullRoundChainElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSizeQM),
		vanishEvalInv:             qm31.One(),
	}
}

func (c *PoseidonFullRoundChainComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	if len(traceSampledValues) != poseidonFullRoundTraceColumns {
		panic("poseidon_full_round_chain expects 126 trace columns")
	}
	if len(interactionSampledValues) != poseidonFullRoundInteractionColumns {
		panic("poseidon_full_round_chain expects 24 interaction columns")
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

	inputLimbs := gatherTrace(0, 32)
	cubeOutputs0 := gatherTrace(32, 10)
	cubeOutputs1 := gatherTrace(42, 10)
	cubeOutputs2 := gatherTrace(52, 10)
	poseidonRoundKeys := gatherTrace(62, 30)
	combination0 := gatherTrace(92, 10)
	pCoef0 := getTrace(102)
	combination1 := gatherTrace(103, 10)
	pCoef1 := getTrace(113)
	combination2 := gatherTrace(114, 10)
	pCoef2 := getTrace(124)
	enabler := getTrace(125)

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
		interactionSampledValues,
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
	interactionSampledValues [][]m31.QM31,
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
	if len(interactionSampledValues) != poseidonFullRoundInteractionColumns {
		panic("poseidon_full_round_chain expects 24 interaction values")
	}

	traceVals := make([]m31.QM31, 24)
	prevVals := make([]m31.QM31, 4)
	for i := 0; i < 24; i++ {
		column := interactionSampledValues[i]
		if i < 20 {
			if len(column) != 1 {
				panic("unexpected interaction sample size")
			}
			traceVals[i] = column[0]
		} else {
			if len(column) != 2 {
				panic("unexpected interaction sample size")
			}
			prevVals[i-20] = column[0]
			traceVals[i] = column[1]
		}
	}

	fp := func(a, b, cVal, d m31.QM31) m31.QM31 {
		return c.qm31.FromPartialEvals(a, b, cVal, d)
	}

	tmp0 := fp(traceVals[0], traceVals[1], traceVals[2], traceVals[3])
	constraint := c.qm31.Mul(tmp0, cubeSum0)
	constraint = c.qm31.Mul(constraint, cubeSum1)
	constraint = c.qm31.Sub(constraint, cubeSum0)
	constraint = c.qm31.Sub(constraint, cubeSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp1 := fp(traceVals[4], traceVals[5], traceVals[6], traceVals[7])
	diff := c.qm31.Sub(tmp1, tmp0)
	constraint = c.qm31.Mul(diff, cubeSum2)
	constraint = c.qm31.Mul(constraint, roundKeysSum)
	constraint = c.qm31.Sub(constraint, cubeSum2)
	constraint = c.qm31.Sub(constraint, roundKeysSum)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp2 := fp(traceVals[8], traceVals[9], traceVals[10], traceVals[11])
	diff = c.qm31.Sub(tmp2, tmp1)
	constraint = c.qm31.Mul(diff, rangeSum4)
	constraint = c.qm31.Mul(constraint, rangeSum5)
	constraint = c.qm31.Sub(constraint, rangeSum4)
	constraint = c.qm31.Sub(constraint, rangeSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp3 := fp(traceVals[12], traceVals[13], traceVals[14], traceVals[15])
	diff = c.qm31.Sub(tmp3, tmp2)
	constraint = c.qm31.Mul(diff, rangeSum6)
	constraint = c.qm31.Mul(constraint, rangeSum7)
	constraint = c.qm31.Sub(constraint, rangeSum6)
	constraint = c.qm31.Sub(constraint, rangeSum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp4 := fp(traceVals[16], traceVals[17], traceVals[18], traceVals[19])
	diff = c.qm31.Sub(tmp4, tmp3)
	constraint = c.qm31.Mul(diff, rangeSum8)
	constraint = c.qm31.Mul(constraint, rangeSum9)
	constraint = c.qm31.Sub(constraint, rangeSum8)
	constraint = c.qm31.Sub(constraint, rangeSum9)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	tmp5 := fp(traceVals[20], traceVals[21], traceVals[22], traceVals[23])
	diff = c.qm31.Sub(tmp5, tmp4)
	prev := fp(prevVals[0], prevVals[1], prevVals[2], prevVals[3])
	diff = c.qm31.Sub(diff, prev)
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
