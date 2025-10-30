package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

type BlakeGClaim struct {
	LogSize uint32
}

type BlakeGInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BlakeGComponent struct {
	qm31 *m31.QM31Chip

	verifyXor8  m31.InteractionElements
	verifyXor12 m31.InteractionElements
	verifyXor4  m31.InteractionElements
	verifyXor7  m31.InteractionElements
	verifyXor9  m31.InteractionElements
	blakeG      m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewBlakeG(
	qm31 *m31.QM31Chip,
	verifyXor8 m31.InteractionElements,
	verifyXor12 m31.InteractionElements,
	verifyXor4 m31.InteractionElements,
	verifyXor7 m31.InteractionElements,
	verifyXor9 m31.InteractionElements,
	blakeG m31.InteractionElements,
	claim BlakeGClaim,
	interactionClaim BlakeGInteractionClaim,
) *BlakeGComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &BlakeGComponent{
		qm31:          qm31,
		verifyXor8:    verifyXor8,
		verifyXor12:   verifyXor12,
		verifyXor4:    verifyXor4,
		verifyXor7:    verifyXor7,
		verifyXor9:    verifyXor9,
		blakeG:        blakeG,
		claimedSum:    interactionClaim.ClaimedSum,
		columnSizeInv: columnSizeInv,
		vanishEvalInv: qm31.One(),
	}
}

func (c *BlakeGComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	trace := traceSampledValues
	if len(trace) != 53 {
		panic("blake_g expects 53 trace columns")
	}

	input := func(idx int) m31.QM31 { return trace[idx][0] }

	inputLimb := make([]m31.QM31, 12)
	for i := 0; i < 12; i++ {
		inputLimb[i] = input(i)
	}

	tripleRes0 := make([]m31.QM31, 4)
	tripleRes1 := make([]m31.QM31, 4)
	for i := 0; i < 4; i++ {
		tripleRes0[i] = input(12 + i*10)
		tripleRes1[i] = input(13 + i*10)
	}

	ms8A := input(14)
	ms8B := input(15)
	ms8C := input(16)
	ms8D := input(17)

	xor18 := input(18)
	xor19 := input(19)
	xor20 := input(20)
	xor21 := input(21)

	ms4A := input(24)
	ms4B := input(25)
	ms4C := input(26)
	ms4D := input(27)

	xor28 := input(28)
	xor29 := input(29)
	xor30 := input(30)
	xor31 := input(31)

	ms8E := input(34)
	ms8F := input(35)
	ms8G := input(36)
	ms8H := input(37)

	xor38 := input(38)
	xor39 := input(39)
	xor40 := input(40)
	xor41 := input(41)

	ms9A := input(44)
	ms9B := input(45)
	ms9C := input(46)
	ms9D := input(47)

	xor48 := input(48)
	xor49 := input(49)
	xor50 := input(50)
	xor51 := input(51)

	enabler := input(52)

	sum = accumulateConstraint(
		c.qm31,
		sum,
		randomCoeff,
		c.qm31.Mul(
			c.qm31.Sub(
				c.qm31.Mul(enabler, enabler),
				enabler,
			),
			c.vanishEvalInv,
		),
	)

	sum = sub.TripleSum32Evaluate(
		c.qm31,
		sub.TripleSum32Inputs{
			A0: inputLimb[0],
			A1: inputLimb[1],
			B0: inputLimb[2],
			B1: inputLimb[3],
			C0: inputLimb[8],
			C1: inputLimb[9],
		},
		tripleRes0[0],
		tripleRes1[0],
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	xor16 := sub.XorRot32R16Evaluate(
		c.qm31,
		tripleRes0[0],
		tripleRes1[0],
		inputLimb[6],
		inputLimb[7],
		ms8A,
		ms8B,
		ms8C,
		ms8D,
		xor18,
		xor19,
		xor20,
		xor21,
		c.verifyXor8,
	)

	sum = sub.TripleSum32Evaluate(
		c.qm31,
		sub.TripleSum32Inputs{
			A0: inputLimb[4],
			A1: inputLimb[5],
			B0: xor16.Res0,
			B1: xor16.Res1,
			C0: c.qm31.Zero(),
			C1: c.qm31.Zero(),
		},
		tripleRes0[1],
		tripleRes1[1],
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	xor12 := sub.XorRot32R12Evaluate(
		c.qm31,
		inputLimb[2],
		inputLimb[3],
		tripleRes0[1],
		tripleRes1[1],
		ms4A,
		ms4B,
		ms4C,
		ms4D,
		xor28,
		xor29,
		xor30,
		xor31,
		c.verifyXor12,
		c.verifyXor4,
	)

	sum = sub.TripleSum32Evaluate(
		c.qm31,
		sub.TripleSum32Inputs{
			A0: tripleRes0[0],
			A1: tripleRes1[0],
			B0: xor12.Res0,
			B1: xor12.Res1,
			C0: inputLimb[10],
			C1: inputLimb[11],
		},
		tripleRes0[2],
		tripleRes1[2],
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	xor8 := sub.XorRot32R8Evaluate(
		c.qm31,
		tripleRes0[2],
		tripleRes1[2],
		xor16.Res0,
		xor16.Res1,
		ms8E,
		ms8F,
		ms8G,
		ms8H,
		xor38,
		xor39,
		xor40,
		xor41,
		c.verifyXor8,
	)

	sum = sub.TripleSum32Evaluate(
		c.qm31,
		sub.TripleSum32Inputs{
			A0: tripleRes0[1],
			A1: tripleRes1[1],
			B0: xor8.Res0,
			B1: xor8.Res1,
			C0: c.qm31.Zero(),
			C1: c.qm31.Zero(),
		},
		tripleRes0[3],
		tripleRes1[3],
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	xor7 := sub.XorRot32R7Evaluate(
		c.qm31,
		xor12.Res0,
		xor12.Res1,
		tripleRes0[3],
		tripleRes1[3],
		ms9A,
		ms9B,
		ms9C,
		ms9D,
		xor48,
		xor49,
		xor50,
		xor51,
		c.verifyXor7,
		c.verifyXor9,
	)

	blakeGSum, err := c.qm31.Combine(
		c.blakeG,
		[]m31.QM31{
			inputLimb[0], inputLimb[1], inputLimb[2], inputLimb[3],
			inputLimb[4], inputLimb[5], inputLimb[6], inputLimb[7],
			inputLimb[8], inputLimb[9], inputLimb[10], inputLimb[11],
			tripleRes0[2], tripleRes1[2],
			xor7.Res0, xor7.Res1,
			tripleRes0[3], tripleRes1[3],
			xor8.Res0, xor8.Res1,
		},
	)
	if err != nil {
		panic(err)
	}

	sum = blakeGLookupConstraints(
		c.qm31,
		sum,
		interactionSampledValues,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		enabler,
		c.columnSizeInv,
		xor16,
		xor12,
		xor8,
		xor7,
		blakeGSum,
	)

	return sum
}

func blakeGLookupConstraints(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	interaction [][]m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	enabler m31.QM31,
	columnSizeInv m31.QM31,
	xor16 sub.XorRot32R16Result,
	xor12 sub.XorRot32R12Result,
	xor8 sub.XorRot32R8Result,
	xor7 sub.XorRot32R7Result,
	blakeGSum m31.QM31,
) m31.QM31 {
	if len(interaction) != 36 {
		panic("blake_g expects 36 interaction columns")
	}

	// Convert to simple QM31 values.
	baseVals := make([]m31.QM31, 32)
	for i := 0; i < 32; i++ {
		col := interaction[i]
		if len(col) == 0 {
			panic("interaction column empty")
		}
		baseVals[i] = col[0]
	}

	getPartial := func(a, b, c, d int) m31.QM31 {
		return qm31.FromPartialEvals(baseVals[a], baseVals[b], baseVals[c], baseVals[d])
	}

	partials := []m31.QM31{
		getPartial(0, 1, 2, 3),
		getPartial(4, 5, 6, 7),
		getPartial(8, 9, 10, 11),
		getPartial(12, 13, 14, 15),
		getPartial(16, 17, 18, 19),
		getPartial(20, 21, 22, 23),
		getPartial(24, 25, 26, 27),
		getPartial(28, 29, 30, 31),
	}

	colNeg := func(idx int) (m31.QM31, m31.QM31) {
		col := interaction[idx]
		if len(col) < 2 {
			panic("interaction history column requires two samples")
		}
		return col[0], col[1]
	}

	prev32, curr32 := colNeg(32)
	prev33, curr33 := colNeg(33)
	prev34, curr34 := colNeg(34)
	prev35, curr35 := colNeg(35)

	finalPartial := qm31.FromPartialEvals(curr32, curr33, curr34, curr35)
	prevPartial := qm31.FromPartialEvals(prev32, prev33, prev34, prev35)

	type xorPair struct {
		first  m31.QM31
		second m31.QM31
	}

	pairs := []xorPair{
		{xor16.Xor8Sum0, xor16.Xor8Sum1},
		{xor16.Xor8Sum2, xor16.Xor8Sum3},
		{xor12.Xor12Sum0, xor12.Xor4Sum1},
		{xor12.Xor12Sum2, xor12.Xor4Sum3},
		{xor8.Xor8Sum0, xor8.Xor8Sum1},
		{xor8.Xor8Sum2, xor8.Xor8Sum3},
		{xor7.Xor7Sum0, xor7.Xor9Sum1},
		{xor7.Xor7Sum2, xor7.Xor9Sum3},
	}

	for idx, pair := range pairs {
		target := partials[idx]
		if idx > 0 {
			target = qm31.Sub(target, partials[idx-1])
		}

		term := qm31.Mul(target, qm31.Mul(pair.first, pair.second))
		constraint := qm31.Sub(term, pair.first)
		constraint = qm31.Sub(constraint, pair.second)
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	diff := qm31.Sub(finalPartial, partials[len(partials)-1])
	diff = qm31.Sub(diff, prevPartial)
	diff = qm31.Add(diff, qm31.Mul(claimedSum, columnSizeInv))
	constraint := qm31.Add(qm31.Mul(diff, blakeGSum), enabler)
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
