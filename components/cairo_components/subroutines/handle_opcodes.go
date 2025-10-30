package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type HandleOpcodesInputs struct {
	InputPC          m31.QM31
	InputFP          m31.QM31
	DstBaseFP        m31.QM31
	Op0BaseFP        m31.QM31
	Op1BaseFP        m31.QM31
	PcUpdateJump     m31.QM31
	OpcodeCall       m31.QM31
	OpcodeRet        m31.QM31
	OpcodeAssertEq   m31.QM31
	ResLogicFlag     m31.QM31
	Op1ImmPlusOne    m31.QM31
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
}

func HandleOpcodesEvaluate(
	qm31 *m31.QM31Chip,
	inputs HandleOpcodesInputs,
	dstLimbs []m31.QM31,
	op0Limbs []m31.QM31,
	resLimbs []m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(dstLimbs) != 28 || len(op0Limbs) != 28 || len(resLimbs) != 28 {
		panic("HandleOpcodesEvaluate expects 28 limbs for each operand slice")
	}

	for i := 0; i < 28; i++ {
		diff := qm31.Sub(resLimbs[i], dstLimbs[i])
		constraint := qm31.Mul(inputs.OpcodeAssertEq, diff)
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	retOffset0 := qm31.Mul(
		inputs.OpcodeRet,
		qm31.Add(inputs.Offset0MinusBase, qm31Const(2)),
	)
	retOffset0 = qm31.Mul(retOffset0, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, retOffset0)

	retOffset2 := qm31.Mul(
		inputs.OpcodeRet,
		qm31.Add(inputs.Offset2MinusBase, qm31Const(1)),
	)
	retOffset2 = qm31.Mul(retOffset2, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, retOffset2)

	retFlags := qm31.Sub(qm31Const(4), inputs.PcUpdateJump)
	retFlags = qm31.Sub(retFlags, inputs.DstBaseFP)
	retFlags = qm31.Sub(retFlags, inputs.Op1BaseFP)
	retFlags = qm31.Sub(retFlags, inputs.ResLogicFlag)
	retConstraint := qm31.Mul(inputs.OpcodeRet, retFlags)
	retConstraint = qm31.Mul(retConstraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, retConstraint)

	callOffset0 := qm31.Mul(inputs.OpcodeCall, inputs.Offset0MinusBase)
	callOffset0 = qm31.Mul(callOffset0, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, callOffset0)

	callOffset1 := qm31.Mul(
		inputs.OpcodeCall,
		qm31.Sub(qm31.One(), inputs.Offset1MinusBase),
	)
	callOffset1 = qm31.Mul(callOffset1, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, callOffset1)

	callFlags := qm31.Add(inputs.Op0BaseFP, inputs.DstBaseFP)
	callFlags = qm31.Mul(inputs.OpcodeCall, callFlags)
	callFlags = qm31.Mul(callFlags, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, callFlags)

	dstAddrInput := make([]m31.QM31, 29)
	copy(dstAddrInput, dstLimbs)
	dstAddrInput[28] = inputs.OpcodeCall
	dstAddr := CondFelt252AsAddrEvaluate(
		qm31,
		dstAddrInput,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = dstAddr.Sum

	dstAddrConstraint := qm31.Mul(
		inputs.OpcodeCall,
		qm31.Sub(dstAddr.Addr, inputs.InputFP),
	)
	dstAddrConstraint = qm31.Mul(dstAddrConstraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, dstAddrConstraint)

	op0AddrInput := make([]m31.QM31, 29)
	copy(op0AddrInput, op0Limbs)
	op0AddrInput[28] = inputs.OpcodeCall
	op0Addr := CondFelt252AsAddrEvaluate(
		qm31,
		op0AddrInput,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = op0Addr.Sum

	pcPlusImm := qm31.Add(inputs.InputPC, inputs.Op1ImmPlusOne)
	op0AddrConstraint := qm31.Mul(
		inputs.OpcodeCall,
		qm31.Sub(op0Addr.Addr, pcPlusImm),
	)
	op0AddrConstraint = qm31.Mul(op0AddrConstraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, op0AddrConstraint)

	return sum
}
