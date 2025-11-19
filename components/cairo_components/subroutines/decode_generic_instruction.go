package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeGenericInstructionResult struct {
	Sum         m31.QM31
	Instruction DecodeInstructionDf7A6Result
	Outputs     [8]m31.QM31
}

func DecodeGenericInstructionEvaluate(
	qm31 *m31.QM31Chip,
	pc m31.QM31,
	offsets [3]m31.QM31,
	dstBaseFP m31.QM31,
	op0BaseFP m31.QM31,
	op1Imm m31.QM31,
	op1BaseFP m31.QM31,
	op1BaseAP m31.QM31,
	resAdd m31.QM31,
	resMul m31.QM31,
	pcUpdateJump m31.QM31,
	pcUpdateJumpRel m31.QM31,
	pcUpdateJnz m31.QM31,
	apUpdateAdd m31.QM31,
	apUpdateAdd1 m31.QM31,
	opcodeCall m31.QM31,
	opcodeRet m31.QM31,
	opcodeAssertEq m31.QM31,
	verifyInstructionElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) DecodeGenericInstructionResult {
	inst := DecodeInstructionDf7A6Evaluate(
		qm31,
		pc,
		offsets[0],
		offsets[1],
		offsets[2],
		dstBaseFP,
		op0BaseFP,
		op1Imm,
		op1BaseFP,
		op1BaseAP,
		resAdd,
		resMul,
		pcUpdateJump,
		pcUpdateJumpRel,
		pcUpdateJnz,
		apUpdateAdd,
		apUpdateAdd1,
		opcodeCall,
		opcodeRet,
		opcodeAssertEq,
		verifyInstructionElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = inst.Sum

	one := qm31.One()

	op1Src := qm31.Sub(qm31.Sub(qm31.Sub(one, op1Imm), op1BaseFP), op1BaseAP)
	constraint := qm31.Mul(op1Src, qm31.Sub(one, op1Src))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	resLogic := qm31.Sub(qm31.Sub(qm31.Sub(one, resAdd), resMul), pcUpdateJnz)
	constraint = qm31.Mul(resLogic, qm31.Sub(one, resLogic))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	pcUpdate := qm31.Sub(qm31.Sub(qm31.Sub(one, pcUpdateJump), pcUpdateJumpRel), pcUpdateJnz)
	constraint = qm31.Mul(pcUpdate, qm31.Sub(one, pcUpdate))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	apUpdate := qm31.Sub(qm31.Sub(qm31.Sub(one, apUpdateAdd), apUpdateAdd1), opcodeCall)
	constraint = qm31.Mul(apUpdate, qm31.Sub(one, apUpdate))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	fpUpdate := qm31.Sub(qm31.Sub(one, opcodeCall), opcodeRet)
	constraint = qm31.Mul(fpUpdate, qm31.Sub(one, fpUpdate))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	outputs := [8]m31.QM31{
		op1Src,
		resLogic,
		pcUpdate,
		fpUpdate,
		qm31.Add(one, op1Imm),
		inst.Offset0MinusBase,
		inst.Offset1MinusBase,
		inst.Offset2MinusBase,
	}

	return DecodeGenericInstructionResult{
		Sum:         sum,
		Instruction: inst,
		Outputs:     outputs,
	}
}
