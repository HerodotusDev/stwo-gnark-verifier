package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type CreateBlakeRoundInputResult struct {
	Sum               m31.QM31
	RangeCheckSums    [8]m31.QM31
	AddressLookupSums [8]m31.QM31
	IdToBigLookupSums [8]m31.QM31
	VerifyXorSums     [4]m31.QM31
	Outputs           [4]m31.QM31
}

func CreateBlakeRoundInputEvaluate(
	qm31 *m31.QM31Chip,
	input [4]m31.QM31,
	stateWords [8]BlakeWordInputs,
	ms8Bits [2]m31.QM31,
	xorValues [4]m31.QM31,
	rangeCheckElements m31.InteractionElements,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	verifyXorElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) CreateBlakeRoundInputResult {
	base := input[0]

	var rangeSums [8]m31.QM31
	var addressSums [8]m31.QM31
	var idSums [8]m31.QM31

	for i := 0; i < 8; i++ {
		word := stateWords[i]
		offset := qm31.Add(base, qm31Const(uint64(i)))
		readRes := ReadBlakeWordEvaluate(
			qm31,
			offset,
			word.Low16Bits,
			word.High16Bits,
			word.Low7MsBits,
			word.High14MsBits,
			word.High5MsBits,
			word.StateID,
			rangeCheckElements,
			memoryAddressElements,
			memoryIdElements,
			sum,
			domainVanishInv,
			randomCoeff,
		)
		sum = readRes.Sum
		rangeSums[i] = readRes.RangeCheckSum
		addressSums[i] = readRes.AddressLookupSum
		idSums[i] = readRes.IdToBigLookupSum
	}

	low0 := Split16LowPartSize8Evaluate(qm31, input[1], ms8Bits[0])
	low1 := Split16LowPartSize8Evaluate(qm31, input[2], ms8Bits[1])

	xorConsts := [4]uint64{127, 82, 14, 81}

	xorSum0 := BitwiseXorNumBits8Evaluate(
		qm31,
		low0,
		qm31Const(xorConsts[0]),
		xorValues[0],
		verifyXorElements,
	)
	xorSum1 := BitwiseXorNumBits8Evaluate(
		qm31,
		ms8Bits[0],
		qm31Const(xorConsts[1]),
		xorValues[1],
		verifyXorElements,
	)
	xorSum2 := BitwiseXorNumBits8Evaluate(
		qm31,
		low1,
		qm31Const(xorConsts[2]),
		xorValues[2],
		verifyXorElements,
	)
	xorSum3 := BitwiseXorNumBits8Evaluate(
		qm31,
		ms8Bits[1],
		qm31Const(xorConsts[3]),
		xorValues[3],
		verifyXorElements,
	)

	outputs := [4]m31.QM31{
		qm31.Add(xorValues[0], qm31.Mul(xorValues[1], qm31Const(256))),
		qm31.Add(xorValues[2], qm31.Mul(xorValues[3], qm31Const(256))),
		qm31.Add(
			qm31.Mul(input[3], qm31Const(9812)),
			qm31.Mul(qm31.Sub(qm31.One(), input[3]), qm31Const(55723)),
		),
		qm31.Add(
			qm31.Mul(input[3], qm31Const(57468)),
			qm31.Mul(qm31.Sub(qm31.One(), input[3]), qm31Const(8067)),
		),
	}

	return CreateBlakeRoundInputResult{
		Sum:               sum,
		RangeCheckSums:    rangeSums,
		AddressLookupSums: addressSums,
		IdToBigLookupSums: idSums,
		VerifyXorSums: [4]m31.QM31{
			xorSum0,
			xorSum1,
			xorSum2,
			xorSum3,
		},
		Outputs: outputs,
	}
}

type BlakeWordInputs struct {
	Low16Bits    m31.QM31
	High16Bits   m31.QM31
	Low7MsBits   m31.QM31
	High14MsBits m31.QM31
	High5MsBits  m31.QM31
	StateID      m31.QM31
}
