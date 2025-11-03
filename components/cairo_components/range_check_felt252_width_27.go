package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheckFelt252Width27Claim struct {
	LogSize uint32
}

type RangeCheckFelt252Width27InteractionClaim struct {
	ClaimedSum m31.QM31
}

type RangeCheckFelt252Width27Component struct {
	qm31 *m31.QM31Chip

	logSize uint8

	rangeCheck9_9Elements            m31.InteractionElements
	rangeCheck18Elements             m31.InteractionElements
	rangeCheckFelt252Width27Elements m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewRangeCheckFelt252Width27(
	qm31 *m31.QM31Chip,
	rangeCheck9_9Elements m31.InteractionElements,
	rangeCheck18Elements m31.InteractionElements,
	rangeCheckFelt252Width27Elements m31.InteractionElements,
	claim RangeCheckFelt252Width27Claim,
	interactionClaim RangeCheckFelt252Width27InteractionClaim,
) *RangeCheckFelt252Width27Component {
	if claim.LogSize > 255 {
		panic("range check felt252 width 27 log size must fit in uint8")
	}

	columnSize := uint64(1) << claim.LogSize
	columnSizeQM31 := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
	columnSizeInv := qm31.Inverse(columnSizeQM31)

	return &RangeCheckFelt252Width27Component{
		qm31:                             qm31,
		logSize:                          uint8(claim.LogSize),
		rangeCheck9_9Elements:            rangeCheck9_9Elements,
		rangeCheck18Elements:             rangeCheck18Elements,
		rangeCheckFelt252Width27Elements: rangeCheckFelt252Width27Elements,
		claimedSum:                       interactionClaim.ClaimedSum,
		columnSizeInv:                    columnSizeInv,
		vanishEvalInv:                    qm31.One(), // Assume vanishing polynomial evaluates to 1.
	}
}

func (c *RangeCheckFelt252Width27Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(20, 32)

	trace := traceSampledValues
	inputLimb0 := trace[0][0]
	inputLimb1 := trace[1][0]
	inputLimb2 := trace[2][0]
	inputLimb3 := trace[3][0]
	inputLimb4 := trace[4][0]
	inputLimb5 := trace[5][0]
	inputLimb6 := trace[6][0]
	inputLimb7 := trace[7][0]
	inputLimb8 := trace[8][0]
	inputLimb9 := trace[9][0]
	limb0High := trace[10][0]
	limb1Low := trace[11][0]
	limb2High := trace[12][0]
	limb3Low := trace[13][0]
	limb4High := trace[14][0]
	limb5Low := trace[15][0]
	limb6High := trace[16][0]
	limb7Low := trace[17][0]
	limb8High := trace[18][0]
	enabler := trace[19][0]

	// Enabler must be a bit.
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

	interaction := interactionSampledValues
	i0 := interaction[0][0]
	i1 := interaction[1][0]
	i2 := interaction[2][0]
	i3 := interaction[3][0]
	i4 := interaction[4][0]
	i5 := interaction[5][0]
	i6 := interaction[6][0]
	i7 := interaction[7][0]
	i8 := interaction[8][0]
	i9 := interaction[9][0]
	i10 := interaction[10][0]
	i11 := interaction[11][0]
	i12 := interaction[12][0]
	i13 := interaction[13][0]
	i14 := interaction[14][0]
	i15 := interaction[15][0]
	i16 := interaction[16][0]
	i17 := interaction[17][0]
	i18 := interaction[18][0]
	i19 := interaction[19][0]
	i20 := interaction[20][0]
	i21 := interaction[21][0]
	i22 := interaction[22][0]
	i23 := interaction[23][0]
	i24 := interaction[24][0]
	i25 := interaction[25][0]
	i26 := interaction[26][0]
	i27 := interaction[27][0]
	i28Prev := interaction[28][0]
	i28Curr := interaction[28][1]
	i29Prev := interaction[29][0]
	i29Curr := interaction[29][1]
	i30Prev := interaction[30][0]
	i30Curr := interaction[30][1]
	i31Prev := interaction[31][0]
	i31Curr := interaction[31][1]

	block0 := c.qm31.FromPartialEvals(i0, i1, i2, i3)
	block1 := c.qm31.FromPartialEvals(i4, i5, i6, i7)
	block2 := c.qm31.FromPartialEvals(i8, i9, i10, i11)
	block3 := c.qm31.FromPartialEvals(i12, i13, i14, i15)
	block4 := c.qm31.FromPartialEvals(i16, i17, i18, i19)
	block5 := c.qm31.FromPartialEvals(i20, i21, i22, i23)
	block6 := c.qm31.FromPartialEvals(i24, i25, i26, i27)
	block7Curr := c.qm31.FromPartialEvals(i28Curr, i29Curr, i30Curr, i31Curr)
	block7Prev := c.qm31.FromPartialEvals(i28Prev, i29Prev, i30Prev, i31Prev)

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
