package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	rangeCheckFelt252Width27TraceColumns       = 20
	rangeCheckFelt252Width27InteractionColumns = 32
)

type RangeCheckFelt252Width27Claim struct {
	LogSize uints.U8
}

type RangeCheckFelt252Width27InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheckFelt252Width27Component struct {
	qm31 *m31.QM31Chip

	logSize uints.U8

	rangeCheck9_9Elements            m31.InteractionElements
	rangeCheck18Elements             m31.InteractionElements
	rangeCheckFelt252Width27Elements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheckFelt252Width27(
	api frontend.API,
	qm31 *m31.QM31Chip,
	rangeCheck9_9Elements m31.InteractionElements,
	rangeCheck18Elements m31.InteractionElements,
	rangeCheckFelt252Width27Elements m31.InteractionElements,
	claim RangeCheckFelt252Width27Claim,
	interactionClaim RangeCheckFelt252Width27InteractionClaim,
) *RangeCheckFelt252Width27Component {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return &RangeCheckFelt252Width27Component{
		qm31:                             qm31,
		logSize:                          claim.LogSize,
		rangeCheck9_9Elements:            rangeCheck9_9Elements,
		rangeCheck18Elements:             rangeCheck18Elements,
		rangeCheckFelt252Width27Elements: rangeCheckFelt252Width27Elements,
		claimedSum:                       interactionClaim.ClaimedSum,
		columnSizeInv:                    columnSizeInv,
		vanishEvalInv:                    qm31.One(), // Assume vanishing polynomial evaluates to 1.
	}
}

func (c *RangeCheckFelt252Width27Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(rangeCheckFelt252Width27TraceColumns, rangeCheckFelt252Width27InteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputLimb0 := traceSampledValues.Get(0)
	inputLimb1 := traceSampledValues.Get(1)
	inputLimb2 := traceSampledValues.Get(2)
	inputLimb3 := traceSampledValues.Get(3)
	inputLimb4 := traceSampledValues.Get(4)
	inputLimb5 := traceSampledValues.Get(5)
	inputLimb6 := traceSampledValues.Get(6)
	inputLimb7 := traceSampledValues.Get(7)
	inputLimb8 := traceSampledValues.Get(8)
	inputLimb9 := traceSampledValues.Get(9)
	limb0High := traceSampledValues.Get(10)
	limb1Low := traceSampledValues.Get(11)
	limb2High := traceSampledValues.Get(12)
	limb3Low := traceSampledValues.Get(13)
	limb4High := traceSampledValues.Get(14)
	limb5Low := traceSampledValues.Get(15)
	limb6High := traceSampledValues.Get(16)
	limb7Low := traceSampledValues.Get(17)
	limb8High := traceSampledValues.Get(18)
	enabler := traceSampledValues.Get(19)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	block0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	block1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	block2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	block3 := interactionSampledValues.Partial(c.qm31, 12, 0)
	block4 := interactionSampledValues.Partial(c.qm31, 16, 0)
	block5 := interactionSampledValues.Partial(c.qm31, 20, 0)
	block6 := interactionSampledValues.Partial(c.qm31, 24, 0)
	block7Curr := interactionSampledValues.Partial(c.qm31, 28, 1)
	block7Prev := interactionSampledValues.Partial(c.qm31, 28, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	constraint := c.qm31.Mul(enabler, c.qm31.Sub(enabler, c.qm31.One()))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	rc9_9sum0, err := c.qm31.Combine(c.rangeCheck9_9Elements, []m31.QM31{limb0High, limb1Low})
	if err != nil {
		panic(err)
	}

	scale262144 := qm31Const(262144)
	scale4194304 := qm31Const(4194304)

	rc18sum1Input := c.qm31.Sub(inputLimb0, c.qm31.Mul(limb0High, scale262144))
	rc18sum1, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum1Input})
	if err != nil {
		panic(err)
	}

	rc18sum2Input := c.qm31.Mul(c.qm31.Sub(inputLimb1, limb1Low), scale4194304)
	rc18sum2, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum2Input})
	if err != nil {
		panic(err)
	}

	rc9_9sum3, err := c.qm31.Combine(c.rangeCheck9_9Elements, []m31.QM31{limb2High, limb3Low})
	if err != nil {
		panic(err)
	}

	rc18sum4Input := c.qm31.Sub(inputLimb2, c.qm31.Mul(limb2High, scale262144))
	rc18sum4, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum4Input})
	if err != nil {
		panic(err)
	}

	rc18sum5Input := c.qm31.Mul(c.qm31.Sub(inputLimb3, limb3Low), scale4194304)
	rc18sum5, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum5Input})
	if err != nil {
		panic(err)
	}

	rc9_9sum6, err := c.qm31.Combine(c.rangeCheck9_9Elements, []m31.QM31{limb4High, limb5Low})
	if err != nil {
		panic(err)
	}

	rc18sum7Input := c.qm31.Sub(inputLimb4, c.qm31.Mul(limb4High, scale262144))
	rc18sum7, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum7Input})
	if err != nil {
		panic(err)
	}

	rc18sum8Input := c.qm31.Mul(c.qm31.Sub(inputLimb5, limb5Low), scale4194304)
	rc18sum8, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum8Input})
	if err != nil {
		panic(err)
	}

	rc9_9sum9, err := c.qm31.Combine(c.rangeCheck9_9Elements, []m31.QM31{limb6High, limb7Low})
	if err != nil {
		panic(err)
	}

	rc18sum10Input := c.qm31.Sub(inputLimb6, c.qm31.Mul(limb6High, scale262144))
	rc18sum10, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum10Input})
	if err != nil {
		panic(err)
	}

	rc18sum11Input := c.qm31.Mul(c.qm31.Sub(inputLimb7, limb7Low), scale4194304)
	rc18sum11, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum11Input})
	if err != nil {
		panic(err)
	}

	rc9_9sum12, err := c.qm31.Combine(c.rangeCheck9_9Elements, []m31.QM31{limb8High, inputLimb9})
	if err != nil {
		panic(err)
	}

	rc18sum13Input := c.qm31.Sub(inputLimb8, c.qm31.Mul(limb8High, scale262144))
	rc18sum13, err := c.qm31.Combine(c.rangeCheck18Elements, []m31.QM31{rc18sum13Input})
	if err != nil {
		panic(err)
	}

	feltInputs := []m31.QM31{
		inputLimb0,
		inputLimb1,
		inputLimb2,
		inputLimb3,
		inputLimb4,
		inputLimb5,
		inputLimb6,
		inputLimb7,
		inputLimb8,
		inputLimb9,
	}
	rcFeltSum14, err := c.qm31.Combine(c.rangeCheckFelt252Width27Elements, feltInputs)
	if err != nil {
		panic(err)
	}

	constraint = c.qm31.Mul(block0, c.qm31.Mul(rc9_9sum0, rc18sum1))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc9_9sum0, rc18sum1))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(block1, block0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(rc18sum2, rc9_9sum3))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc18sum2, rc9_9sum3))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(block2, block1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(rc18sum4, rc18sum5))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc18sum4, rc18sum5))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(block3, block2)
	constraint = c.qm31.Mul(diff3, c.qm31.Mul(rc9_9sum6, rc18sum7))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc9_9sum6, rc18sum7))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff4 := c.qm31.Sub(block4, block3)
	constraint = c.qm31.Mul(diff4, c.qm31.Mul(rc18sum8, rc9_9sum9))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc18sum8, rc9_9sum9))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff5 := c.qm31.Sub(block5, block4)
	constraint = c.qm31.Mul(diff5, c.qm31.Mul(rc18sum10, rc18sum11))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc18sum10, rc18sum11))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff6 := c.qm31.Sub(block6, block5)
	constraint = c.qm31.Mul(diff6, c.qm31.Mul(rc9_9sum12, rc18sum13))
	constraint = c.qm31.Sub(constraint, c.qm31.Add(rc9_9sum12, rc18sum13))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff7 := c.qm31.Sub(block7Curr, block6)
	diff7 = c.qm31.Sub(diff7, block7Prev)
	diff7 = c.qm31.Add(diff7, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Mul(diff7, rcFeltSum14)
	constraint = c.qm31.Add(constraint, enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
