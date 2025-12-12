package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ModPoint struct {
	ID    m31.QM31
	Limbs [11]m31.QM31
}

type Pointer3 struct {
	ID    m31.QM31
	Limbs [3]m31.QM31
}

type OffsetEntry struct {
	ID          m31.QM31
	MSB         m31.QM31
	MidLimbsSet m31.QM31
	Limbs       [3]m31.QM31
}

type ModUtilsInputs struct {
	BaseAddress        m31.QM31
	InstanceNum        m31.QM31
	IsInstanceZero     m31.QM31
	Points             [4]ModPoint
	PrevPointIDs       [4]m31.QM31
	ValuesPointer      Pointer3
	OffsetsPointer     Pointer3
	OffsetsPointerPrev Pointer3
	ValuesPointerPrev  m31.QM31
	NPointer           Pointer3
	NPointerPrev       Pointer3
	Offsets            [3]OffsetEntry
	A                  [4]ModPoint
	B                  [4]ModPoint
	C                  [4]ModPoint
}

type ModUtilsResult struct {
	Sum                 m31.QM31
	AddressLookupSums   []m31.QM31
	IdToBigLookupSums   []m31.QM31
	ReadSmallValues     [3]m31.QM31
	InstanceAddress     m31.QM31
	PrevInstanceAddress m31.QM31
	BlockResetCondition m31.QM31
}

func ModUtilsEvaluate(
	qm31 *m31.QM31Chip,
	inputs ModUtilsInputs,
	memoryAddressElements m31.InteractionElements,
	memoryIDElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ModUtilsResult {
	result := ModUtilsResult{
		AddressLookupSums: make([]m31.QM31, 0, 60),
		IdToBigLookupSums: make([]m31.QM31, 0, 60),
	}

	appendAddress := func(val m31.QM31) {
		result.AddressLookupSums = append(result.AddressLookupSums, val)
	}
	appendId := func(val m31.QM31) {
		result.IdToBigLookupSums = append(result.IdToBigLookupSums, val)
	}

	one := qm31.One()
	seven := qm31Const(7)

	// Constraint: is_instance_zero is a bit.
	constraint := qm31.Mul(inputs.IsInstanceZero, qm31.Sub(inputs.IsInstanceZero, one))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	// Constraint: is_instance_zero implies instance_num == 0.
	constraint = qm31.Mul(inputs.IsInstanceZero, inputs.InstanceNum)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	addConst := func(val m31.QM31, offset uint64) m31.QM31 {
		return qm31.Add(val, qm31Const(offset))
	}

	instanceAddr := qm31.Add(inputs.BaseAddress, qm31.Mul(seven, inputs.InstanceNum))
	prevInstanceAddr := qm31.Add(
		inputs.BaseAddress,
		qm31.Mul(
			seven,
			qm31.Add(
				qm31.Sub(inputs.InstanceNum, one),
				inputs.IsInstanceZero,
			),
		),
	)

	result.InstanceAddress = instanceAddr
	result.PrevInstanceAddress = prevInstanceAddr

	readPoints := func(base m31.QM31, points [4]ModPoint) {
		for i := 0; i < 4; i++ {
			addr := base
			if i > 0 {
				addr = addConst(base, uint64(i))
			}
			resPoint := ReadPositiveNumBits99Evaluate(
				qm31,
				addr,
				points[i].ID,
				points[i].Limbs,
				memoryAddressElements,
				memoryIDElements,
				sum,
				domainVanishInv,
				randomCoeff,
			)
			appendAddress(resPoint.AddressLookupSum)
			appendId(resPoint.IdToBigLookupSum)
		}
	}

	readPoints(instanceAddr, inputs.Points)

	readPointer27 := func(addr m31.QM31, ptr Pointer3) {
		resPtr := ReadPositiveNumBits27Evaluate(
			qm31,
			addr,
			ptr.ID,
			ptr.Limbs[0],
			ptr.Limbs[1],
			ptr.Limbs[2],
			memoryAddressElements,
			memoryIDElements,
		)
		appendAddress(resPtr.AddressLookupSum)
		appendId(resPtr.IdToBigLookupSum)
	}

	readPointer27(addConst(instanceAddr, 4), inputs.ValuesPointer)
	readPointer27(addConst(instanceAddr, 5), inputs.OffsetsPointer)
	readPointer27(addConst(prevInstanceAddr, 5), inputs.OffsetsPointerPrev)
	readPointer27(addConst(instanceAddr, 6), inputs.NPointer)
	readPointer27(addConst(prevInstanceAddr, 6), inputs.NPointerPrev)

	combine27 := func(ptr Pointer3) m31.QM31 {
		val := ptr.Limbs[0]
		val = qm31.Add(val, qm31.Mul(ptr.Limbs[1], qm31Const(512)))
		val = qm31.Add(val, qm31.Mul(ptr.Limbs[2], qm31Const(262144)))
		return val
	}

	valuesPtrValue := combine27(inputs.ValuesPointer)
	offsetsPtrValue := combine27(inputs.OffsetsPointer)
	offsetsPtrPrevValue := combine27(inputs.OffsetsPointerPrev)
	nValue := combine27(inputs.NPointer)
	nPrevValue := combine27(inputs.NPointerPrev)

	blockResetCondition := qm31.Mul(
		qm31.Sub(nPrevValue, one),
		qm31.Sub(inputs.IsInstanceZero, one),
	)
	result.BlockResetCondition = blockResetCondition

	constraint = qm31.Mul(
		blockResetCondition,
		qm31.Sub(qm31.Sub(nPrevValue, one), nValue),
	)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(
		blockResetCondition,
		qm31.Sub(qm31.Sub(offsetsPtrValue, qm31Const(3)), offsetsPtrPrevValue),
	)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	memCond := func(addr m31.QM31, id m31.QM31, knownID m31.QM31) {
		resCond := MemCondVerifyEqualKnownIDEvaluate(
			qm31,
			addr,
			id,
			blockResetCondition,
			knownID,
			memoryAddressElements,
			sum,
			domainVanishInv,
			randomCoeff,
		)
		sum = resCond.Sum
		appendAddress(resCond.AddressLookupSum)
	}

	memCond(addConst(prevInstanceAddr, 4), inputs.ValuesPointer.ID, inputs.ValuesPointerPrev)
	for i := 0; i < 4; i++ {
		addr := prevInstanceAddr
		if i > 0 {
			addr = addConst(prevInstanceAddr, uint64(i))
		}
		memCond(addr, inputs.Points[i].ID, inputs.PrevPointIDs[i])
	}

	readSmall := func(base m31.QM31, entry OffsetEntry) m31.QM31 {
		resSmall := ReadSmallEvaluate(
			qm31,
			base,
			entry.ID,
			entry.MSB,
			entry.MidLimbsSet,
			entry.Limbs[0],
			entry.Limbs[1],
			entry.Limbs[2],
			memoryAddressElements,
			memoryIDElements,
			sum,
			domainVanishInv,
			randomCoeff,
		)
		sum = resSmall.Sum
		appendAddress(resSmall.AddressLookupSum)
		appendId(resSmall.IdToBigLookupSum)
		return resSmall.Value
	}

	aOffset := readSmall(offsetsPtrValue, inputs.Offsets[0])
	bOffset := readSmall(addConst(offsetsPtrValue, 1), inputs.Offsets[1])
	cOffset := readSmall(addConst(offsetsPtrValue, 2), inputs.Offsets[2])
	result.ReadSmallValues = [3]m31.QM31{aOffset, bOffset, cOffset}

	readPoints(qm31.Add(valuesPtrValue, aOffset), inputs.A)
	readPoints(qm31.Add(valuesPtrValue, bOffset), inputs.B)
	readPoints(qm31.Add(valuesPtrValue, cOffset), inputs.C)

	result.Sum = sum
	return result
}
