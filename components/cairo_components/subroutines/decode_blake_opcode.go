package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type BlakeOpcodeFlags struct {
	DstBaseFP   m31.QM31
	Op0BaseFP   m31.QM31
	Op1BaseFP   m31.QM31
	Op1BaseAP   m31.QM31
	ApUpdateAdd m31.QM31
}

type BlakeMemBases struct {
	Mem0   m31.QM31
	Mem1   m31.QM31
	MemDst m31.QM31
}

type BlakeOperand struct {
	ID    m31.QM31
	Limbs [3]m31.QM31
}

type BlakeDstInput struct {
	Base m31.QM31
	Word BlakeWordInputs
}

type DecodeBlakeOpcodeResult struct {
	Sum         m31.QM31
	Instruction DecodeInstruction64420Result
	Op0Lookup   ReadPositiveNumBits27Result
	Op1Lookup   ReadPositiveNumBits27Result
	ApLookup    ReadPositiveNumBits27Result
	DstLookup   ReadBlakeWordResult
	Outputs     [4]m31.QM31
}

func DecodeBlakeOpcodeEvaluate(
	qm31 *m31.QM31Chip,
	pc m31.QM31,
	ap m31.QM31,
	fp m31.QM31,
	offsets [3]m31.QM31,
	flags BlakeOpcodeFlags,
	opcodeExtension m31.QM31,
	memBases BlakeMemBases,
	op0 BlakeOperand,
	op1 BlakeOperand,
	apOperand BlakeOperand,
	dst BlakeDstInput,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeBlakeOpcodeResult {
	inst := DecodeInstruction64420Evaluate(
		qm31,
		pc,
		offsets[0],
		offsets[1],
		offsets[2],
		flags.DstBaseFP,
		flags.Op0BaseFP,
		flags.Op1BaseFP,
		flags.Op1BaseAP,
		flags.ApUpdateAdd,
		opcodeExtension,
		verifyInstructionElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = inst.Sum

	one := qm31.One()

	// op1_base_fp + op1_base_ap == 1
	constraint := qm31.Sub(qm31.Add(flags.Op1BaseFP, flags.Op1BaseAP), one)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// opcode_extension in {1, 2}
	constraint = qm31.Mul(
		qm31.Sub(opcodeExtension, qm31Const(1)),
		qm31.Sub(opcodeExtension, qm31Const(2)),
	)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// mem0_base relation
	expectedMem0 := qm31.Add(
		qm31.Mul(flags.Op0BaseFP, fp),
		qm31.Mul(qm31.Sub(one, flags.Op0BaseFP), ap),
	)
	constraint = qm31.Sub(memBases.Mem0, expectedMem0)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op0Ptr := qm31.Add(memBases.Mem0, inst.Offset1MinusBase)
	op0Lookup := ReadPositiveNumBits27Evaluate(
		qm31,
		op0Ptr,
		op0.ID,
		op0.Limbs[0],
		op0.Limbs[1],
		op0.Limbs[2],
		memoryAddressElements,
		memoryIdElements,
	)

	// mem1_base relation
	expectedMem1 := qm31.Add(
		qm31.Mul(flags.Op1BaseFP, fp),
		qm31.Mul(flags.Op1BaseAP, ap),
	)
	constraint = qm31.Sub(memBases.Mem1, expectedMem1)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op1Ptr := qm31.Add(memBases.Mem1, inst.Offset2MinusBase)
	op1Lookup := ReadPositiveNumBits27Evaluate(
		qm31,
		op1Ptr,
		op1.ID,
		op1.Limbs[0],
		op1.Limbs[1],
		op1.Limbs[2],
		memoryAddressElements,
		memoryIdElements,
	)

	apLookup := ReadPositiveNumBits27Evaluate(
		qm31,
		ap,
		apOperand.ID,
		apOperand.Limbs[0],
		apOperand.Limbs[1],
		apOperand.Limbs[2],
		memoryAddressElements,
		memoryIdElements,
	)

	// mem_dst_base relation
	expectedDst := qm31.Add(
		qm31.Mul(flags.DstBaseFP, fp),
		qm31.Mul(qm31.Sub(one, flags.DstBaseFP), ap),
	)
	constraint = qm31.Sub(memBases.MemDst, expectedDst)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	dstPtr := qm31.Add(memBases.MemDst, inst.Offset0MinusBase)
	dstLookup := ReadBlakeWordEvaluate(
		qm31,
		dstPtr,
		dst.Word.Low16Bits,
		dst.Word.High16Bits,
		dst.Word.Low7MsBits,
		dst.Word.High14MsBits,
		dst.Word.High5MsBits,
		dst.Word.StateID,
		rangeCheckElements,
		memoryAddressElements,
		memoryIdElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = dstLookup.Sum

	buildWord := func(limbs [3]m31.QM31) m31.QM31 {
		return qm31.Add(
			qm31.Add(limbs[0], qm31.Mul(limbs[1], qm31Const(512))),
			qm31.Mul(limbs[2], qm31Const(262144)),
		)
	}

	outputs := [4]m31.QM31{
		buildWord(op0.Limbs),
		buildWord(op1.Limbs),
		buildWord(apOperand.Limbs),
		qm31.Sub(opcodeExtension, qm31Const(1)),
	}

	return DecodeBlakeOpcodeResult{
		Sum:         sum,
		Instruction: inst,
		Op0Lookup:   op0Lookup,
		Op1Lookup:   op1Lookup,
		ApLookup:    apLookup,
		DstLookup:   dstLookup,
		Outputs:     outputs,
	}
}
