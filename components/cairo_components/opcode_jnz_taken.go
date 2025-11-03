package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	jnzTakenOpcodeTraceColumns       = 45
	jnzTakenOpcodeInteractionColumns = 16
)

type JnzTakenOpcodeClaim struct {
	LogSize uints.U8
}

type JnzTakenOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type JnzTakenOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewJnzTakenOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim JnzTakenOpcodeClaim,
	interactionClaim JnzTakenOpcodeInteractionClaim,
) *JnzTakenOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return &JnzTakenOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(),
	}
}

func (c *JnzTakenOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(jnzTakenOpcodeTraceColumns, jnzTakenOpcodeInteractionColumns)

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	// (none)

	// ╔══════════════════════════════════╗
	// ║            Main Trace            ║
	// ╚══════════════════════════════════╝
	inputPc := traceSampledValues.Get(0)
	inputAp := traceSampledValues.Get(1)
	inputFp := traceSampledValues.Get(2)
	offset0 := traceSampledValues.Get(3)
	dstBaseFP := traceSampledValues.Get(4)
	apUpdateAdd1 := traceSampledValues.Get(5)
	memDstBase := traceSampledValues.Get(6)
	dstID := traceSampledValues.Get(7)
	dstLimbs := traceSampledValues.Slice(8, 28)
	res := traceSampledValues.Get(36)
	resSquares := traceSampledValues.Get(37)
	nextPcID := traceSampledValues.Get(38)
	nextPcMSB := traceSampledValues.Get(39)
	nextPcMidSet := traceSampledValues.Get(40)
	nextPcLimb0 := traceSampledValues.Get(41)
	nextPcLimb1 := traceSampledValues.Get(42)
	nextPcLimb2 := traceSampledValues.Get(43)
	enabler := traceSampledValues.Get(44)

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	part0 := interactionSampledValues.Partial(c.qm31, 0, 0)
	part1 := interactionSampledValues.Partial(c.qm31, 4, 0)
	part2 := interactionSampledValues.Partial(c.qm31, 8, 0)
	part3 := interactionSampledValues.Partial(c.qm31, 12, 1)
	part3Prev := interactionSampledValues.Partial(c.qm31, 12, 0)

	// ╔══════════════════════════════════╗
	// ║       Constraint Evaluations     ║
	// ╚══════════════════════════════════╝
	constraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	decoded := sub.DecodeInstructionDE75AEvaluate(
		c.qm31,
		inputPc,
		offset0,
		dstBaseFP,
		apUpdateAdd1,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum
	offset0MinusBase := decoded.Offset0MinusBase

	one := c.qm31.One()

	// mem_dst_base relation.
	memDstExpected := c.qm31.Add(
		c.qm31.Mul(dstBaseFP, inputFp),
		c.qm31.Mul(c.qm31.Sub(one, dstBaseFP), inputAp),
	)
	constraint = c.qm31.Sub(memDstBase, memDstExpected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	dstLookup := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(memDstBase, offset0MinusBase),
		dstID,
		dstLimbs,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	memoryAddressSum1 := dstLookup.AddressLookupSum
	memoryIdToBigSum2 := dstLookup.IdToBigLookupSum

	// dst != 0 by enforcing inverse.
	sumLimbs := dstLimbs[0]
	for i := 1; i < len(dstLimbs); i++ {
		sumLimbs = c.qm31.Add(sumLimbs, dstLimbs[i])
	}
	constraint = c.qm31.Sub(c.qm31.Mul(sumLimbs, res), one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff0 := c.qm31.Sub(dstLimbs[0], one)
	diff21 := c.qm31.Sub(dstLimbs[21], qm31Const(136))
	diff27 := c.qm31.Sub(dstLimbs[27], qm31Const(256))

	sumSquares := c.qm31.Mul(diff0, diff0)
	for i := 1; i <= 20; i++ {
		sumSquares = c.qm31.Add(sumSquares, dstLimbs[i])
	}
	sumSquares = c.qm31.Add(sumSquares, c.qm31.Mul(diff21, diff21))
	for i := 22; i <= 26; i++ {
		sumSquares = c.qm31.Add(sumSquares, dstLimbs[i])
	}
	sumSquares = c.qm31.Add(sumSquares, c.qm31.Mul(diff27, diff27))

	constraint = c.qm31.Sub(c.qm31.Mul(sumSquares, resSquares), one)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readSmall := sub.ReadSmallEvaluate(
		c.qm31,
		c.qm31.Add(inputPc, one),
		nextPcID,
		nextPcMSB,
		nextPcMidSet,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memoryAddressSum3 := readSmall.AddressLookupSum
	memoryIdToBigSum4 := readSmall.IdToBigLookupSum
	sum = readSmall.Sum
	nextPcValue := readSmall.Value

	opcodesSum5, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPc := c.qm31.Add(inputPc, nextPcValue)
	nextAp := c.qm31.Add(inputAp, apUpdateAdd1)

	opcodesSum6, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{nextPc, nextAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	constraint = c.qm31.Mul(part0, c.qm31.Mul(verifyInstructionSum, memoryAddressSum1))
	constraint = c.qm31.Sub(constraint, verifyInstructionSum)
	constraint = c.qm31.Sub(constraint, memoryAddressSum1)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff1 := c.qm31.Sub(part1, part0)
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIdToBigSum2, memoryAddressSum3))
	constraint = c.qm31.Sub(constraint, memoryIdToBigSum2)
	constraint = c.qm31.Sub(constraint, memoryAddressSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memoryIdToBigSum4, opcodesSum5))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIdToBigSum4, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(part3, part2)
	diff3 = c.qm31.Sub(diff3, part3Prev)
	diff3 = c.qm31.Add(diff3, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff3, opcodesSum6), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
