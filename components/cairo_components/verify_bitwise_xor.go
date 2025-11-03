package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║      Verify Bitwise XOR (4)      ║
// ╚══════════════════════════════════╝

const verifyBitwiseXor4LogSize = 8

type VerifyBitwiseXor4InteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyBitwiseXor4Component struct {
	inner *lookupConstraintComponent
}

func NewVerifyBitwiseXor4(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim VerifyBitwiseXor4InteractionClaim,
) *VerifyBitwiseXor4Component {
	return &VerifyBitwiseXor4Component{
		inner: newVerifyBitwiseXorLookupComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			verifyBitwiseXor4LogSize,
			4,
		),
	}
}

func (c *VerifyBitwiseXor4Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}

// ╔══════════════════════════════════╗
// ║      Verify Bitwise XOR (7)      ║
// ╚══════════════════════════════════╝

const verifyBitwiseXor7LogSize = 14

type VerifyBitwiseXor7InteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyBitwiseXor7Component struct {
	inner *lookupConstraintComponent
}

func NewVerifyBitwiseXor7(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim VerifyBitwiseXor7InteractionClaim,
) *VerifyBitwiseXor7Component {
	return &VerifyBitwiseXor7Component{
		inner: newVerifyBitwiseXorLookupComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			verifyBitwiseXor7LogSize,
			7,
		),
	}
}

func (c *VerifyBitwiseXor7Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}

// ╔══════════════════════════════════╗
// ║      Verify Bitwise XOR (8)      ║
// ╚══════════════════════════════════╝

const verifyBitwiseXor8LogSize = 16

type VerifyBitwiseXor8InteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyBitwiseXor8Component struct {
	inner *lookupConstraintComponent
}

func NewVerifyBitwiseXor8(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim VerifyBitwiseXor8InteractionClaim,
) *VerifyBitwiseXor8Component {
	return &VerifyBitwiseXor8Component{
		inner: newVerifyBitwiseXorLookupComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			verifyBitwiseXor8LogSize,
			8,
		),
	}
}

func (c *VerifyBitwiseXor8Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}

// ╔══════════════════════════════════╗
// ║      Verify Bitwise XOR (9)      ║
// ╚══════════════════════════════════╝

const verifyBitwiseXor9LogSize = 18

type VerifyBitwiseXor9InteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyBitwiseXor9Component struct {
	inner *lookupConstraintComponent
}

func NewVerifyBitwiseXor9(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim VerifyBitwiseXor9InteractionClaim,
) *VerifyBitwiseXor9Component {
	return &VerifyBitwiseXor9Component{
		inner: newVerifyBitwiseXorLookupComponent(
			api,
			qm31,
			interactionElements,
			interactionClaim.ClaimedSum,
			verifyBitwiseXor9LogSize,
			9,
		),
	}
}

func (c *VerifyBitwiseXor9Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	return c.inner.Evaluate(sum, traces, randomCoeff)
}

// ╔══════════════════════════════════╗
// ║     Verify Bitwise XOR (12)      ║
// ╚══════════════════════════════════╝

const verifyBitwiseXor12LogSize = 20

type VerifyBitwiseXor12InteractionClaim struct {
	ClaimedSum m31.QM31
}

type VerifyBitwiseXor12Component struct {
	qm31                *m31.QM31Chip
	interactionElements m31.InteractionElements
	claimedSum          m31.QM31
	columnSizeInv       m31.QM31
	vanishEvalInv       m31.QM31
}

const (
	verifyBitwiseXor12TraceColumns       = 16
	verifyBitwiseXor12InteractionColumns = 32
)

func NewVerifyBitwiseXor12(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	interactionClaim VerifyBitwiseXor12InteractionClaim,
) *VerifyBitwiseXor12Component {
	return &VerifyBitwiseXor12Component{
		qm31:                qm31,
		interactionElements: interactionElements,
		claimedSum:          interactionClaim.ClaimedSum,
		columnSizeInv:       qm31.Inverse(computeColumnSize(api, uints.NewU8(verifyBitwiseXor12LogSize))),
		vanishEvalInv:       qm31.One(),
	}
}

func (c *VerifyBitwiseXor12Component) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(verifyBitwiseXor12TraceColumns, verifyBitwiseXor12InteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	bitwiseXor := []m31.QM31{
		traces.Get(NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(0))),
		traces.Get(NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(1))),
		traces.Get(NewPreprocessedColumnBitwiseXor(uints.NewU8(10), uints.NewU8(2))),
	}

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	partials := make([]m31.QM31, 7)
	for i := 0; i < 7; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	currPartial := interactionSampledValues.Partial(c.qm31, 28, 1)
	prevPartial := interactionSampledValues.Partial(c.qm31, 28, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝

	inters := computeVerifyBitwiseXor12Intermediates(c.qm31, c.interactionElements, bitwiseXor)

	applyConstraint := func(base m31.QM31, intA, intB, traceA, traceB m31.QM31) {
		constraint := c.qm31.Mul(base, c.qm31.Mul(intA, intB))
		constraint = c.qm31.Add(constraint, c.qm31.Mul(intB, traceA))
		constraint = c.qm31.Add(constraint, c.qm31.Mul(intA, traceB))
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	applyConstraint(partials[0], inters[0], inters[1], traceSampledValues.Get(0), traceSampledValues.Get(1))
	for i := 1; i < 7; i++ {
		diff := c.qm31.Sub(partials[i], partials[i-1])
		applyConstraint(diff, inters[2*i], inters[2*i+1], traceSampledValues.Get(2*i), traceSampledValues.Get(2*i+1))
	}

	finalBase := c.qm31.Sub(currPartial, prevPartial)
	finalBase = c.qm31.Sub(finalBase, partials[len(partials)-1])
	finalBase = c.qm31.Add(finalBase, c.qm31.Mul(c.claimedSum, c.columnSizeInv))

	finalConstraint := c.qm31.Mul(finalBase, c.qm31.Mul(inters[14], inters[15]))
	finalConstraint = c.qm31.Add(finalConstraint, c.qm31.Mul(inters[15], traceSampledValues.Get(14)))
	finalConstraint = c.qm31.Add(finalConstraint, c.qm31.Mul(inters[14], traceSampledValues.Get(15)))
	finalConstraint = c.qm31.Mul(finalConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, finalConstraint)

	return sum
}

func computeVerifyBitwiseXor12Intermediates(
	qm31 *m31.QM31Chip,
	elements m31.InteractionElements,
	bitwise []m31.QM31,
) []m31.QM31 {
	addConst := func(value m31.QM31, constant uint64) m31.QM31 {
		if constant == 0 {
			return value
		}
		return qm31.Add(value, qm31Const(constant))
	}

	combine := func(v0, v1, v2 m31.QM31) m31.QM31 {
		res, err := qm31.Combine(elements, []m31.QM31{v0, v1, v2})
		if err != nil {
			panic(err)
		}
		return res
	}

	offsets := [16][3]uint64{
		{0, 0, 0},
		{0, 1024, 1024},
		{0, 2048, 2048},
		{0, 3072, 3072},
		{1024, 0, 1024},
		{1024, 1024, 0},
		{1024, 2048, 3072},
		{1024, 3072, 2048},
		{2048, 0, 2048},
		{2048, 1024, 3072},
		{2048, 2048, 0},
		{2048, 3072, 1024},
		{3072, 0, 3072},
		{3072, 1024, 2048},
		{3072, 2048, 1024},
		{3072, 3072, 0},
	}

	result := make([]m31.QM31, 16)
	for i, offs := range offsets {
		v0 := addConst(bitwise[0], offs[0])
		v1 := addConst(bitwise[1], offs[1])
		v2 := addConst(bitwise[2], offs[2])
		result[i] = combine(v0, v1, v2)
	}

	return result
}
