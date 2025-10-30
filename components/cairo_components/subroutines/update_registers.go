package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type UpdateRegistersInputs struct {
	InputPC         m31.QM31
	InputAP         m31.QM31
	InputFP         m31.QM31
	PcUpdateJump    m31.QM31
	PcUpdateJumpRel m31.QM31
	PcUpdateJnz     m31.QM31
	ApUpdateAdd     m31.QM31
	ApUpdateAdd1    m31.QM31
	OpcodeCall      m31.QM31
	OpcodeRet       m31.QM31
	PcUpdateFlag    m31.QM31
	FpUpdateFlag    m31.QM31
	Op1ImmPlusOne   m31.QM31
}

func UpdateRegistersEvaluate(
	qm31 *m31.QM31Chip,
	inputs UpdateRegistersInputs,
	dstLimbs []m31.QM31,
	op1Limbs []m31.QM31,
	resLimbs []m31.QM31,
	msbDst m31.QM31,
	midLimbsDst m31.QM31,
	dstSumSquaresInv m31.QM31,
	dstSumInv m31.QM31,
	op1AsRelImmCond m31.QM31,
	msbOp1 m31.QM31,
	midLimbsOp1 m31.QM31,
	nextPcJnz m31.QM31,
	nextPc m31.QM31,
	nextAp m31.QM31,
	nextFp m31.QM31,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(dstLimbs) != 28 || len(op1Limbs) != 28 || len(resLimbs) != 28 {
		panic("UpdateRegistersEvaluate expects 28 limbs for each operand slice")
	}

	resAddrInput := make([]m31.QM31, 29)
	copy(resAddrInput, resLimbs)
	resAddrInput[28] = inputs.PcUpdateJump
	resAddr := CondFelt252AsAddrEvaluate(
		qm31,
		resAddrInput,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = resAddr.Sum

	dstAddrInput := make([]m31.QM31, 29)
	copy(dstAddrInput, dstLimbs)
	dstAddrInput[28] = inputs.OpcodeRet
	dstAddr := CondFelt252AsAddrEvaluate(
		qm31,
		dstAddrInput,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = dstAddr.Sum

	relEnabler := qm31.Add(inputs.PcUpdateJumpRel, inputs.ApUpdateAdd)
	resRelInput := make([]m31.QM31, 29)
	copy(resRelInput, resLimbs)
	resRelInput[28] = relEnabler
	resRel := CondFelt252AsRelImmEvaluate(
		qm31,
		resRelInput,
		msbDst,
		midLimbsDst,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = resRel.Sum

	diff0 := qm31.Sub(dstLimbs[0], qm31Const(1))
	diff1 := qm31.Sub(dstLimbs[21], qm31Const(136))
	diff2 := qm31.Sub(dstLimbs[27], qm31Const(256))

	dstNorm := qm31.Mul(diff0, diff0)
	for i := 1; i <= 20; i++ {
		dstNorm = qm31.Add(dstNorm, dstLimbs[i])
	}
	dstNorm = qm31.Add(dstNorm, qm31.Mul(diff1, diff1))
	for i := 22; i <= 26; i++ {
		dstNorm = qm31.Add(dstNorm, dstLimbs[i])
	}
	dstNorm = qm31.Add(dstNorm, qm31.Mul(diff2, diff2))

	constraint := qm31.Sub(qm31.Mul(dstNorm, dstSumSquaresInv), qm31.One())
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	dstSum := qm31.Zero()
	for _, limb := range dstLimbs {
		dstSum = qm31.Add(dstSum, limb)
	}

	op1CondConstraint := qm31.Sub(
		op1AsRelImmCond,
		qm31.Mul(inputs.PcUpdateJnz, dstSum),
	)
	op1CondConstraint = qm31.Mul(op1CondConstraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, op1CondConstraint)

	op1RelInput := make([]m31.QM31, 29)
	copy(op1RelInput, op1Limbs)
	op1RelInput[28] = op1AsRelImmCond
	op1Rel := CondFelt252AsRelImmEvaluate(
		qm31,
		op1RelInput,
		msbOp1,
		midLimbsOp1,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = op1Rel.Sum

	conditionalJump := qm31.Mul(
		qm31.Sub(nextPcJnz, qm31.Add(inputs.InputPC, op1Rel.RelImm)),
		dstSum,
	)
	conditionalJump = qm31.Mul(conditionalJump, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, conditionalJump)

	dstSumScaled := qm31.Sub(
		qm31.Mul(dstSum, dstSumInv),
		qm31.One(),
	)
	jumpFallback := qm31.Mul(
		qm31.Sub(nextPcJnz, qm31.Add(inputs.InputPC, inputs.Op1ImmPlusOne)),
		dstSumScaled,
	)
	jumpFallback = qm31.Mul(jumpFallback, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, jumpFallback)

	nextPcExpected := qm31.Mul(
		inputs.PcUpdateFlag,
		qm31.Add(inputs.InputPC, inputs.Op1ImmPlusOne),
	)
	nextPcExpected = qm31.Add(
		nextPcExpected,
		qm31.Mul(inputs.PcUpdateJump, resAddr.Addr),
	)
	nextPcExpected = qm31.Add(
		nextPcExpected,
		qm31.Mul(
			inputs.PcUpdateJumpRel,
			qm31.Add(inputs.InputPC, resRel.RelImm),
		),
	)
	nextPcExpected = qm31.Add(
		nextPcExpected,
		qm31.Mul(inputs.PcUpdateJnz, nextPcJnz),
	)
	constraint = qm31.Sub(nextPc, nextPcExpected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	nextApExpected := qm31.Add(
		inputs.InputAP,
		qm31.Mul(inputs.ApUpdateAdd, resRel.RelImm),
	)
	nextApExpected = qm31.Add(nextApExpected, inputs.ApUpdateAdd1)
	nextApExpected = qm31.Add(
		nextApExpected,
		qm31.Mul(inputs.OpcodeCall, qm31Const(2)),
	)
	constraint = qm31.Sub(nextAp, nextApExpected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	nextFpExpected := qm31.Mul(inputs.FpUpdateFlag, inputs.InputFP)
	nextFpExpected = qm31.Add(
		nextFpExpected,
		qm31.Mul(inputs.OpcodeRet, dstAddr.Addr),
	)
	nextFpExpected = qm31.Add(
		nextFpExpected,
		qm31.Mul(
			inputs.OpcodeCall,
			qm31.Add(inputs.InputAP, qm31Const(2)),
		),
	)
	constraint = qm31.Sub(nextFp, nextFpExpected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
