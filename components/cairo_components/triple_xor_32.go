package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type TripleXor32Claim struct {
	LogSize uint32
}

type TripleXor32InteractionClaim struct {
	ClaimedSum m31.QM31
}

type TripleXor32Component struct {
	qm31 *m31.QM31Chip

	verifyBitwiseXor8Elements m31.InteractionElements
	tripleXor32Elements       m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewTripleXor32(
	qm31 *m31.QM31Chip,
	verifyBitwiseXor8Elements m31.InteractionElements,
	tripleXor32Elements m31.InteractionElements,
	claim TripleXor32Claim,
	interactionClaim TripleXor32InteractionClaim,
) *TripleXor32Component {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &TripleXor32Component{
		qm31:                      qm31,
		verifyBitwiseXor8Elements: verifyBitwiseXor8Elements,
		tripleXor32Elements:       tripleXor32Elements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSizeQM),
		vanishEvalInv:             qm31.One(),
	}
}

func (c *TripleXor32Component) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	_ = preprocessedSampledValues

	trace := traceSampledValues

	input0 := trace[0][0]
	input1 := trace[1][0]
	input2 := trace[2][0]
	input3 := trace[3][0]
	input4 := trace[4][0]
	input5 := trace[5][0]

	ms0 := trace[6][0]
	ms1 := trace[7][0]
	ms2 := trace[8][0]
	ms3 := trace[9][0]
	ms4 := trace[10][0]
	ms5 := trace[11][0]

	xor12 := trace[12][0]
	xor13 := trace[13][0]
	xor14 := trace[14][0]
	xor15 := trace[15][0]
	xor16 := trace[16][0]
	xor17 := trace[17][0]
	xor18 := trace[18][0]
	xor19 := trace[19][0]

	enabler := trace[20][0]

	// Enabler must be boolean.
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	low0 := sub.Split16LowPartSize8Evaluate(c.qm31, input0, ms0)
	low1 := sub.Split16LowPartSize8Evaluate(c.qm31, input1, ms1)
	low2 := sub.Split16LowPartSize8Evaluate(c.qm31, input2, ms2)
	low3 := sub.Split16LowPartSize8Evaluate(c.qm31, input3, ms3)
	low4 := sub.Split16LowPartSize8Evaluate(c.qm31, input4, ms4)
	low5 := sub.Split16LowPartSize8Evaluate(c.qm31, input5, ms5)

	combineXor := func(a, b, result m31.QM31) m31.QM31 {
		val, err := c.qm31.Combine(
			c.verifyBitwiseXor8Elements,
			[]m31.QM31{a, b, result},
		)
		if err != nil {
			panic(err)
		}
		return val
	}

	sum0 := combineXor(low0, low2, xor12)
	sum1 := combineXor(xor12, low4, xor13)
	sum2 := combineXor(ms0, ms2, xor14)
	sum3 := combineXor(xor14, ms4, xor15)
	sum4 := combineXor(low1, low3, xor16)
	sum5 := combineXor(xor16, low5, xor17)
	sum6 := combineXor(ms1, ms3, xor18)
	sum7 := combineXor(xor18, ms5, xor19)

	xorLimb0 := c.qm31.Add(xor13, c.qm31.Mul(xor15, qm31Const(256)))
	xorLimb1 := c.qm31.Add(xor17, c.qm31.Mul(xor19, qm31Const(256)))

	tripleXorSum, err := c.qm31.Combine(
		c.tripleXor32Elements,
		[]m31.QM31{
			input0,
			input1,
			input2,
			input3,
			input4,
			input5,
			xorLimb0,
			xorLimb1,
		},
	)
	if err != nil {
		panic(err)
	}

	part := func(start int, offset int) m31.QM31 {
		return c.qm31.FromPartialEvals(
			interactionSampledValues[start][offset],
			interactionSampledValues[start+1][offset],
			interactionSampledValues[start+2][offset],
			interactionSampledValues[start+3][offset],
		)
	}

	part0 := part(0, 0)
	part1 := part(4, 0)
	part2 := part(8, 0)
	part3 := part(12, 0)
	part4 := c.qm31.FromPartialEvals(
		interactionSampledValues[16][1],
		interactionSampledValues[17][1],
		interactionSampledValues[18][1],
		interactionSampledValues[19][1],
	)
	part4Prev := c.qm31.FromPartialEvals(
		interactionSampledValues[16][0],
		interactionSampledValues[17][0],
		interactionSampledValues[18][0],
		interactionSampledValues[19][0],
	)

	// (part0 * sum0 * sum1) - sum0 - sum1
	constraint = c.qm31.Mul(part0, c.qm31.Mul(sum0, sum1))
	constraint = c.qm31.Sub(constraint, sum0)
	constraint = c.qm31.Sub(constraint, sum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// (part1 - part0) * sum2 * sum3 - sum2 - sum3
	diff := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(sum2, sum3))
	constraint = c.qm31.Sub(constraint, sum2)
	constraint = c.qm31.Sub(constraint, sum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// (part2 - part1) * sum4 * sum5 - sum4 - sum5
	diff = c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(sum4, sum5))
	constraint = c.qm31.Sub(constraint, sum4)
	constraint = c.qm31.Sub(constraint, sum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// (part3 - part2) * sum6 * sum7 - sum6 - sum7
	diff = c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff, c.qm31.Mul(sum6, sum7))
	constraint = c.qm31.Sub(constraint, sum6)
	constraint = c.qm31.Sub(constraint, sum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	// (part4 - part3 - part4Prev + claimedSum * columnSizeInv) * tripleXorSum + enabler
	diff = c.qm31.Sub(part4, part3)
	diff = c.qm31.Sub(diff, part4Prev)
	diff = c.qm31.Add(diff, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Mul(diff, tripleXorSum)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
