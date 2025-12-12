package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	CallOpcodeTraceColumns       = 19
	CallOpcodeInteractionColumns = 20
)

type CallOpcodeClaim struct {
	LogSize frontend.Variable
}

type CallOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type CallOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIDElements m31.InteractionElements
	memoryIDToBigElements     m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func NewCallOpcode(
	api frontend.API,
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIDElements m31.InteractionElements,
	memoryIDToBigElements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim CallOpcodeClaim,
	interactionClaim CallOpcodeInteractionClaim,
) CallOpcodeComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	return CallOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIDElements: memoryAddressToIDElements,
		memoryIDToBigElements:     memoryIDToBigElements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             vanishEvalInv,
	}
}

func (c CallOpcodeComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(CallOpcodeTraceColumns, CallOpcodeInteractionColumns)

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
	offset2 := traceSampledValues.Get(3)
	op1BaseFP := traceSampledValues.Get(4)
	storedFpID := traceSampledValues.Get(5)
	storedFpLimb0 := traceSampledValues.Get(6)
	storedFpLimb1 := traceSampledValues.Get(7)
	storedFpLimb2 := traceSampledValues.Get(8)
	storedRetPcID := traceSampledValues.Get(9)
	storedRetPcLimb0 := traceSampledValues.Get(10)
	storedRetPcLimb1 := traceSampledValues.Get(11)
	storedRetPcLimb2 := traceSampledValues.Get(12)
	mem1Base := traceSampledValues.Get(13)
	nextPcID := traceSampledValues.Get(14)
	nextPcLimb0 := traceSampledValues.Get(15)
	nextPcLimb1 := traceSampledValues.Get(16)
	nextPcLimb2 := traceSampledValues.Get(17)
	enabler := traceSampledValues.Get(18)

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

	decoded := sub.DecodeInstructionF1EDDEvaluate(
		c.qm31,
		inputPc,
		offset2,
		op1BaseFP,
		c.verifyInstructionElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	verifyInstructionSum := decoded.VerifySum
	sum = decoded.Sum

	readStoredFp := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		inputAp,
		storedFpID,
		storedFpLimb0,
		storedFpLimb1,
		storedFpLimb2,
		c.memoryAddressToIDElements,
		c.memoryIDToBigElements,
	)
	memoryAddressSum1 := readStoredFp.AddressLookupSum
	memoryIDToBigSum2 := readStoredFp.IdToBigLookupSum

	storedFpValue := c.qm31.Add(
		c.qm31.Add(
			storedFpLimb0,
			c.qm31.Mul(storedFpLimb1, qm31Const(512)),
		),
		c.qm31.Mul(storedFpLimb2, qm31Const(262144)),
	)
	constraint = c.qm31.Sub(storedFpValue, inputFp)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readStoredRet := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(inputAp, c.qm31.One()),
		storedRetPcID,
		storedRetPcLimb0,
		storedRetPcLimb1,
		storedRetPcLimb2,
		c.memoryAddressToIDElements,
		c.memoryIDToBigElements,
	)
	memoryAddressSum3 := readStoredRet.AddressLookupSum
	memoryIDToBigSum4 := readStoredRet.IdToBigLookupSum

	storedRetPcValue := c.qm31.Add(
		c.qm31.Add(
			storedRetPcLimb0,
			c.qm31.Mul(storedRetPcLimb1, qm31Const(512)),
		),
		c.qm31.Mul(storedRetPcLimb2, qm31Const(262144)),
	)
	constraint = c.qm31.Sub(storedRetPcValue, c.qm31.Add(inputPc, c.qm31.One()))
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	mem1Expected := c.qm31.Add(
		c.qm31.Mul(op1BaseFP, inputFp),
		c.qm31.Mul(decoded.Op1BaseAP, inputAp),
	)
	constraint = c.qm31.Sub(mem1Base, mem1Expected)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	readNextPc := sub.ReadPositiveNumBits27Evaluate(
		c.qm31,
		c.qm31.Add(mem1Base, decoded.Offset2MinusBase),
		nextPcID,
		nextPcLimb0,
		nextPcLimb1,
		nextPcLimb2,
		c.memoryAddressToIDElements,
		c.memoryIDToBigElements,
	)
	memoryAddressSum5 := readNextPc.AddressLookupSum
	memoryIDToBigSum6 := readNextPc.IdToBigLookupSum

	var err error
	opcodesSum7, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{inputPc, inputAp, inputFp},
	)
	if err != nil {
		panic(err)
	}

	nextPcValue := c.qm31.Add(
		c.qm31.Add(
			nextPcLimb0,
			c.qm31.Mul(nextPcLimb1, qm31Const(512)),
		),
		c.qm31.Mul(nextPcLimb2, qm31Const(262144)),
	)
	nextApPlusTwo := c.qm31.Add(inputAp, qm31Const(2))

	opcodesSum8, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{nextPcValue, nextApPlusTwo, nextApPlusTwo},
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
	constraint = c.qm31.Mul(diff1, c.qm31.Mul(memoryIDToBigSum2, memoryAddressSum3))
	constraint = c.qm31.Sub(constraint, memoryIDToBigSum2)
	constraint = c.qm31.Sub(constraint, memoryAddressSum3)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff2 := c.qm31.Sub(part2, part1)
	constraint = c.qm31.Mul(diff2, c.qm31.Mul(memoryIDToBigSum4, memoryAddressSum5))
	constraint = c.qm31.Sub(constraint, memoryIDToBigSum4)
	constraint = c.qm31.Sub(constraint, memoryAddressSum5)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff3 := c.qm31.Sub(part3, part2)
	constraint = c.qm31.Mul(diff3, c.qm31.Mul(memoryIDToBigSum6, opcodesSum7))
	constraint = c.qm31.Sub(constraint, c.qm31.Mul(memoryIDToBigSum6, enabler))
	constraint = c.qm31.Sub(constraint, opcodesSum7)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	diff4 := c.qm31.Sub(part4, part3)
	diff4 = c.qm31.Sub(diff4, part4Prev)
	diff4 = c.qm31.Add(diff4, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	constraint = c.qm31.Add(c.qm31.Mul(diff4, opcodesSum8), enabler)
	constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

	return sum
}
