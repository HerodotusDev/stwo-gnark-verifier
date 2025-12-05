package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	BlakeGTraceColumns       = 53
	BlakeGInteractionColumns = 36
)

type BlakeGClaim struct {
	LogSize frontend.Variable
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
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyXor8 m31.InteractionElements,
	verifyXor12 m31.InteractionElements,
	verifyXor4 m31.InteractionElements,
	verifyXor7 m31.InteractionElements,
	verifyXor9 m31.InteractionElements,
	blakeG m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim BlakeGClaim,
	interactionClaim BlakeGInteractionClaim,
) BlakeGComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return BlakeGComponent{
		qm31:          qm31,
		verifyXor8:    verifyXor8,
		verifyXor12:   verifyXor12,
		verifyXor4:    verifyXor4,
		verifyXor7:    verifyXor7,
		verifyXor9:    verifyXor9,
		blakeG:        blakeG,
		claimedSum:    interactionClaim.ClaimedSum,
		columnSizeInv: columnSizeInv,
		vanishEvalInv: vanishEvalInv,
	}
}

func (c BlakeGComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(BlakeGTraceColumns, BlakeGInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	tripleRes0 := make([]m31.QM31, 4)
	tripleRes1 := make([]m31.QM31, 4)
	for i := 0; i < 4; i++ {
		tripleRes0[i] = traceSampledValues.Get(12 + i*10)
		tripleRes1[i] = traceSampledValues.Get(13 + i*10)
	}

	ms8A := traceSampledValues.Get(14)
	ms8B := traceSampledValues.Get(15)
	ms8C := traceSampledValues.Get(16)
	ms8D := traceSampledValues.Get(17)

	xor18 := traceSampledValues.Get(18)
	xor19 := traceSampledValues.Get(19)
	xor20 := traceSampledValues.Get(20)
	xor21 := traceSampledValues.Get(21)

	ms4A := traceSampledValues.Get(24)
	ms4B := traceSampledValues.Get(25)
	ms4C := traceSampledValues.Get(26)
	ms4D := traceSampledValues.Get(27)

	xor28 := traceSampledValues.Get(28)
	xor29 := traceSampledValues.Get(29)
	xor30 := traceSampledValues.Get(30)
	xor31 := traceSampledValues.Get(31)

	ms8E := traceSampledValues.Get(34)
	ms8F := traceSampledValues.Get(35)
	ms8G := traceSampledValues.Get(36)
	ms8H := traceSampledValues.Get(37)

	xor38 := traceSampledValues.Get(38)
	xor39 := traceSampledValues.Get(39)
	xor40 := traceSampledValues.Get(40)
	xor41 := traceSampledValues.Get(41)

	ms9A := traceSampledValues.Get(44)
	ms9B := traceSampledValues.Get(45)
	ms9C := traceSampledValues.Get(46)
	ms9D := traceSampledValues.Get(47)

	xor48 := traceSampledValues.Get(48)
	xor49 := traceSampledValues.Get(49)
	xor50 := traceSampledValues.Get(50)
	xor51 := traceSampledValues.Get(51)

	enabler := traceSampledValues.Get(52)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 8)
	for i := 0; i < 8; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	finalCurr := interactionSampledValues.Partial(c.qm31, 32, 1)
	finalPrev := interactionSampledValues.Partial(c.qm31, 32, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

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
			A0: traceSampledValues.Get(0),
			A1: traceSampledValues.Get(1),
			B0: traceSampledValues.Get(2),
			B1: traceSampledValues.Get(3),
			C0: traceSampledValues.Get(8),
			C1: traceSampledValues.Get(9),
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
		traceSampledValues.Get(6),
		traceSampledValues.Get(7),
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
			A0: traceSampledValues.Get(4),
			A1: traceSampledValues.Get(5),
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
		traceSampledValues.Get(2),
		traceSampledValues.Get(3),
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
			C0: traceSampledValues.Get(10),
			C1: traceSampledValues.Get(11),
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
			traceSampledValues.Get(0), traceSampledValues.Get(1), traceSampledValues.Get(2), traceSampledValues.Get(3),
			traceSampledValues.Get(4), traceSampledValues.Get(5), traceSampledValues.Get(6), traceSampledValues.Get(7),
			traceSampledValues.Get(8), traceSampledValues.Get(9), traceSampledValues.Get(10), traceSampledValues.Get(11),
			tripleRes0[2], tripleRes1[2],
			xor7.Res0, xor7.Res1,
			tripleRes0[3], tripleRes1[3],
			xor8.Res0, xor8.Res1,
		},
	)
	if err != nil {
		panic(err)
	}

	sum = c.blakeGLookupConstraints(
		sum,
		randomCoeff,
		partials,
		finalCurr,
		finalPrev,
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

func (c *BlakeGComponent) blakeGLookupConstraints(
	sum m31.QM31,
	randomCoeff m31.QM31,
	partials []m31.QM31,
	finalPartial m31.QM31,
	prevPartial m31.QM31,
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
	if len(partials) != 8 {
		panic("blake_g expects 8 partials for first 32 columns")
	}

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
			target = c.qm31.Sub(target, partials[idx-1])
		}

		term := c.qm31.Mul(target, c.qm31.Mul(pair.first, pair.second))
		constraint := c.qm31.Sub(term, pair.first)
		constraint = c.qm31.Sub(constraint, pair.second)
		constraint = c.qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	diff := c.qm31.Sub(finalPartial, partials[len(partials)-1])
	diff = c.qm31.Sub(diff, prevPartial)
	diff = c.qm31.Add(diff, c.qm31.Mul(claimedSum, columnSizeInv))
	constraint := c.qm31.Add(c.qm31.Mul(diff, blakeGSum), enabler)
	constraint = c.qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
