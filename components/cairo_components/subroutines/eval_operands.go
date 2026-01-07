package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type EvalOperandsParams struct {
	InputPC          m31.QM31
	InputAP          m31.QM31
	InputFP          m31.QM31
	DstBaseFP        m31.QM31
	Op0BaseFP        m31.QM31
	Op1Imm           m31.QM31
	Op1BaseFP        m31.QM31
	Op1BaseAP        m31.QM31
	ResAddFlag       m31.QM31
	ResMulFlag       m31.QM31
	PcUpdateJnz      m31.QM31
	Op1SrcIndicator  m31.QM31
	ResLogicFlag     m31.QM31
	Offset0MinusBase m31.QM31
	Offset1MinusBase m31.QM31
	Offset2MinusBase m31.QM31
}

type EvalOperandsResult struct {
	Sum               m31.QM31
	MemoryAddressSums [3]m31.QM31
	MemoryIDSums      [3]m31.QM31
	RangeCheck99      [28]m31.QM31
	RangeCheck19      [28]m31.QM31
}

func EvalOperandsEvaluate(
	qm31 *m31.QM31Chip,
	params EvalOperandsParams,
	dstSrc m31.QM31,
	dstID m31.QM31,
	dstLimbs []m31.QM31,
	op0Src m31.QM31,
	op0ID m31.QM31,
	op0Limbs []m31.QM31,
	op1Src m31.QM31,
	op1ID m31.QM31,
	op1Limbs []m31.QM31,
	addResLimbs []m31.QM31,
	subPBit m31.QM31,
	mulResLimbs []m31.QM31,
	k m31.QM31,
	carries []m31.QM31,
	resLimbs []m31.QM31,
	memoryAddressElements m31.InteractionElements,
	memoryIDElements m31.InteractionElements,
	rangeCheck99Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) EvalOperandsResult {
	if len(dstLimbs) != 28 || len(op0Limbs) != 28 || len(op1Limbs) != 28 || len(addResLimbs) != 28 || len(mulResLimbs) != 28 || len(resLimbs) != 28 {
		panic("EvalOperandsEvaluate expects 28 limbs for each operand")
	}
	if len(carries) != 27 {
		panic("EvalOperandsEvaluate expects 27 carry values")
	}

	result := EvalOperandsResult{}
	one := qm31.One()

	dstExpected := qm31.Add(
		qm31.Mul(params.DstBaseFP, params.InputFP),
		qm31.Mul(qm31.Sub(one, params.DstBaseFP), params.InputAP),
	)
	constraint := qm31.Sub(dstSrc, dstExpected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	dstAddress := qm31.Add(dstSrc, params.Offset0MinusBase)
	dstRead := ReadPositiveNumBits252Evaluate(
		qm31,
		dstAddress,
		dstID,
		dstLimbs,
		memoryAddressElements,
		memoryIDElements,
	)
	result.MemoryAddressSums[0] = dstRead.AddressLookupSum
	result.MemoryIDSums[0] = dstRead.IdToBigLookupSum

	op0Expected := qm31.Add(
		qm31.Mul(params.Op0BaseFP, params.InputFP),
		qm31.Mul(qm31.Sub(one, params.Op0BaseFP), params.InputAP),
	)
	constraint = qm31.Sub(op0Src, op0Expected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op0Address := qm31.Add(op0Src, params.Offset1MinusBase)
	op0Read := ReadPositiveNumBits252Evaluate(
		qm31,
		op0Address,
		op0ID,
		op0Limbs,
		memoryAddressElements,
		memoryIDElements,
	)
	result.MemoryAddressSums[1] = op0Read.AddressLookupSum
	result.MemoryIDSums[1] = op0Read.IdToBigLookupSum

	op0AddrLimbs := make([]m31.QM31, 29)
	copy(op0AddrLimbs, op0Limbs)
	op0AddrLimbs[28] = params.Op1SrcIndicator
	op0Addr := CondFelt252AsAddrEvaluate(
		qm31,
		op0AddrLimbs,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = op0Addr.Sum

	op1Expected := qm31.Add(
		qm31.Add(
			qm31.Mul(params.Op1BaseFP, params.InputFP),
			qm31.Mul(params.Op1BaseAP, params.InputAP),
		),
		qm31.Mul(params.Op1Imm, params.InputPC),
	)
	op1Expected = qm31.Add(op1Expected, qm31.Mul(params.Op1SrcIndicator, op0Addr.Addr))
	constraint = qm31.Sub(op1Src, op1Expected)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	op1Address := qm31.Add(op1Src, params.Offset2MinusBase)
	op1Read := ReadPositiveNumBits252Evaluate(
		qm31,
		op1Address,
		op1ID,
		op1Limbs,
		memoryAddressElements,
		memoryIDElements,
	)
	result.MemoryAddressSums[2] = op1Read.AddressLookupSum
	result.MemoryIDSums[2] = op1Read.IdToBigLookupSum

	addRes := Add252Evaluate(
		qm31,
		op0Limbs,
		op1Limbs,
		addResLimbs,
		subPBit,
		rangeCheck99Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = addRes.Sum
	copy(result.RangeCheck99[:14], addRes.RangeCheckSums[:])

	mulRes := Mul252Evaluate(
		qm31,
		op0Limbs,
		op1Limbs,
		mulResLimbs,
		k,
		carries,
		rangeCheck99Elements,
		rangeCheck19Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = mulRes.Sum
	copy(result.RangeCheck99[14:], mulRes.ResultRangeSums[:])
	copy(result.RangeCheck19[:], mulRes.CarryRangeSums[:])

	resGate := qm31.Sub(one, params.PcUpdateJnz)
	for i := 0; i < 28; i++ {
		resTerm := qm31.Mul(
			params.ResLogicFlag,
			qm31.Sub(resLimbs[i], op1Limbs[i]),
		)
		resTerm = qm31.Add(
			resTerm,
			qm31.Mul(
				params.ResAddFlag,
				qm31.Sub(resLimbs[i], addResLimbs[i]),
			),
		)
		resTerm = qm31.Add(
			resTerm,
			qm31.Mul(
				params.ResMulFlag,
				qm31.Sub(resLimbs[i], mulResLimbs[i]),
			),
		)
		constraint = qm31.Mul(resGate, resTerm)
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	result.Sum = sum
	return result
}
