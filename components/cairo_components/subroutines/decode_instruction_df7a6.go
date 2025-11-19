package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type DecodeInstructionDf7A6Result struct {
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
	VerifySum        m31.QM31
	Sum              m31.QM31
}

func DecodeInstructionDf7A6Evaluate(
	qm31 *m31.QM31Chip,
	inputPC m31.QM31,
	offset0 m31.QM31,
	offset1 m31.QM31,
	offset2 m31.QM31,
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
) DecodeInstructionDf7A6Result {
	one := qm31.One()

	flags := []m31.QM31{
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
	}
	for _, flag := range flags {
		constraint := qm31.Mul(flag, qm31.Sub(one, flag))
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	alpha := qm31.Mul(dstBaseFP, qm31Const(8))
	alpha = qm31.Add(alpha, qm31.Mul(op0BaseFP, qm31Const(16)))
	alpha = qm31.Add(alpha, qm31.Mul(op1Imm, qm31Const(32)))
	alpha = qm31.Add(alpha, qm31.Mul(op1BaseFP, qm31Const(64)))
	alpha = qm31.Add(alpha, qm31.Mul(op1BaseAP, qm31Const(128)))
	alpha = qm31.Add(alpha, qm31.Mul(resAdd, qm31Const(256)))

	beta := resMul
	beta = qm31.Add(beta, qm31.Mul(pcUpdateJump, qm31Const(2)))
	beta = qm31.Add(beta, qm31.Mul(pcUpdateJumpRel, qm31Const(4)))
	beta = qm31.Add(beta, qm31.Mul(pcUpdateJnz, qm31Const(8)))
	beta = qm31.Add(beta, qm31.Mul(apUpdateAdd, qm31Const(16)))
	beta = qm31.Add(beta, qm31.Mul(apUpdateAdd1, qm31Const(32)))
	beta = qm31.Add(beta, qm31.Mul(opcodeCall, qm31Const(64)))
	beta = qm31.Add(beta, qm31.Mul(opcodeRet, qm31Const(128)))
	beta = qm31.Add(beta, qm31.Mul(opcodeAssertEq, qm31Const(256)))

	values := []m31.QM31{
		inputPC,
		offset0,
		offset1,
		offset2,
		alpha,
		beta,
		qm31.Zero(),
	}

	verifySum, err := qm31.Combine(verifyInstructionElements, values)
	if err != nil {
		panic(err)
	}

	base := qm31Const(32768)

	return DecodeInstructionDf7A6Result{
		Offset0MinusBase: qm31.Sub(offset0, base),
		Offset1MinusBase: qm31.Sub(offset1, base),
		Offset2MinusBase: qm31.Sub(offset2, base),
		VerifySum:        verifySum,
		Sum:              sum,
	}
}
