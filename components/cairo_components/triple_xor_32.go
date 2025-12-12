package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

type TripleXor32Claim struct {
	LogSize frontend.Variable
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

const (
	TripleXor32TraceColumns       = 21
	TripleXor32InteractionColumns = 20
)

func NewTripleXor32(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyBitwiseXor8Elements m31.InteractionElements,
	tripleXor32Elements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim TripleXor32Claim,
	interactionClaim TripleXor32InteractionClaim,
) TripleXor32Component {
	columnSize := computeColumnSize(api, claim.LogSize)

	return TripleXor32Component{
		qm31:                      qm31,
		verifyBitwiseXor8Elements: verifyBitwiseXor8Elements,
		tripleXor32Elements:       tripleXor32Elements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             qm31.Inverse(columnSize),
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c TripleXor32Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(TripleXor32TraceColumns, TripleXor32InteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	input0 := traceSampledValues.Get(0)
	input1 := traceSampledValues.Get(1)
	input2 := traceSampledValues.Get(2)
	input3 := traceSampledValues.Get(3)
	input4 := traceSampledValues.Get(4)
	input5 := traceSampledValues.Get(5)

	ms0 := traceSampledValues.Get(6)
	ms1 := traceSampledValues.Get(7)
	ms2 := traceSampledValues.Get(8)
	ms3 := traceSampledValues.Get(9)
	ms4 := traceSampledValues.Get(10)
	ms5 := traceSampledValues.Get(11)

	xor12 := traceSampledValues.Get(12)
	xor13 := traceSampledValues.Get(13)
	xor14 := traceSampledValues.Get(14)
	xor15 := traceSampledValues.Get(15)
	xor16 := traceSampledValues.Get(16)
	xor17 := traceSampledValues.Get(17)
	xor18 := traceSampledValues.Get(18)
	xor19 := traceSampledValues.Get(19)

	enabler := traceSampledValues.Get(20)

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
