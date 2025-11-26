package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type XorRot32R16Result struct {
	Res0     m31.QM31
	Res1     m31.QM31
	Xor8Sum0 m31.QM31
	Xor8Sum1 m31.QM31
	Xor8Sum2 m31.QM31
	Xor8Sum3 m31.QM31
}

func XorRot32R16Evaluate(
	qm31 *m31.QM31Chip,
	input0 m31.QM31,
	input1 m31.QM31,
	input2 m31.QM31,
	input3 m31.QM31,
	msb0 m31.QM31,
	msb1 m31.QM31,
	msb2 m31.QM31,
	msb3 m31.QM31,
	xor4 m31.QM31,
	xor5 m31.QM31,
	xor6 m31.QM31,
	xor7 m31.QM31,
	lookup m31.InteractionElements,
) XorRot32R16Result {
	low0 := Split16LowPartSize8Evaluate(qm31, input0, msb0)
	low1 := Split16LowPartSize8Evaluate(qm31, input1, msb1)
	low2 := Split16LowPartSize8Evaluate(qm31, input2, msb2)
	low3 := Split16LowPartSize8Evaluate(qm31, input3, msb3)

	xorSum0 := BitwiseXorNumBits8Evaluate(qm31, low0, low2, xor4, lookup)
	xorSum1 := BitwiseXorNumBits8Evaluate(qm31, msb0, msb2, xor5, lookup)
	xorSum2 := BitwiseXorNumBits8Evaluate(qm31, low1, low3, xor6, lookup)
	xorSum3 := BitwiseXorNumBits8Evaluate(qm31, msb1, msb3, xor7, lookup)

	res0 := qm31.Add(xor6, qm31.Mul(xor7, qm31Const(256)))
	res1 := qm31.Add(xor4, qm31.Mul(xor5, qm31Const(256)))

	return XorRot32R16Result{
		Res0:     res0,
		Res1:     res1,
		Xor8Sum0: xorSum0,
		Xor8Sum1: xorSum1,
		Xor8Sum2: xorSum2,
		Xor8Sum3: xorSum3,
	}
}

type XorRot32R12Result struct {
	Res0      m31.QM31
	Res1      m31.QM31
	Xor12Sum0 m31.QM31
	Xor4Sum1  m31.QM31
	Xor12Sum2 m31.QM31
	Xor4Sum3  m31.QM31
}

func XorRot32R12Evaluate(
	qm31 *m31.QM31Chip,
	input0 m31.QM31,
	input1 m31.QM31,
	input2 m31.QM31,
	input3 m31.QM31,
	msb0 m31.QM31,
	msb1 m31.QM31,
	msb2 m31.QM31,
	msb3 m31.QM31,
	xor4 m31.QM31,
	xor5 m31.QM31,
	xor6 m31.QM31,
	xor7 m31.QM31,
	lookup12 m31.InteractionElements,
	lookup4 m31.InteractionElements,
) XorRot32R12Result {
	low0 := Split16LowPartSize12Evaluate(qm31, input0, msb0)
	low1 := Split16LowPartSize12Evaluate(qm31, input1, msb1)
	low2 := Split16LowPartSize12Evaluate(qm31, input2, msb2)
	low3 := Split16LowPartSize12Evaluate(qm31, input3, msb3)

	xor12Sum0 := BitwiseXorNumBits12Evaluate(qm31, low0, low2, xor4, lookup12)
	xor4Sum1 := BitwiseXorNumBits4Evaluate(qm31, msb0, msb2, xor5, lookup4)
	xor12Sum2 := BitwiseXorNumBits12Evaluate(qm31, low1, low3, xor6, lookup12)
	xor4Sum3 := BitwiseXorNumBits4Evaluate(qm31, msb1, msb3, xor7, lookup4)

	res0 := qm31.Add(xor5, qm31.Mul(xor6, qm31Const(16)))
	res1 := qm31.Add(xor7, qm31.Mul(xor4, qm31Const(16)))

	return XorRot32R12Result{
		Res0:      res0,
		Res1:      res1,
		Xor12Sum0: xor12Sum0,
		Xor4Sum1:  xor4Sum1,
		Xor12Sum2: xor12Sum2,
		Xor4Sum3:  xor4Sum3,
	}
}

type XorRot32R8Result struct {
	Res0     m31.QM31
	Res1     m31.QM31
	Xor8Sum0 m31.QM31
	Xor8Sum1 m31.QM31
	Xor8Sum2 m31.QM31
	Xor8Sum3 m31.QM31
}

func XorRot32R8Evaluate(
	qm31 *m31.QM31Chip,
	input0 m31.QM31,
	input1 m31.QM31,
	input2 m31.QM31,
	input3 m31.QM31,
	msb0 m31.QM31,
	msb1 m31.QM31,
	msb2 m31.QM31,
	msb3 m31.QM31,
	xor4 m31.QM31,
	xor5 m31.QM31,
	xor6 m31.QM31,
	xor7 m31.QM31,
	lookup m31.InteractionElements,
) XorRot32R8Result {
	low0 := Split16LowPartSize8Evaluate(qm31, input0, msb0)
	low1 := Split16LowPartSize8Evaluate(qm31, input1, msb1)
	low2 := Split16LowPartSize8Evaluate(qm31, input2, msb2)
	low3 := Split16LowPartSize8Evaluate(qm31, input3, msb3)

	xorSum0 := BitwiseXorNumBits8Evaluate(qm31, low0, low2, xor4, lookup)
	xorSum1 := BitwiseXorNumBits8Evaluate(qm31, msb0, msb2, xor5, lookup)
	xorSum2 := BitwiseXorNumBits8Evaluate(qm31, low1, low3, xor6, lookup)
	xorSum3 := BitwiseXorNumBits8Evaluate(qm31, msb1, msb3, xor7, lookup)

	res0 := qm31.Add(xor5, qm31.Mul(xor6, qm31Const(256)))
	res1 := qm31.Add(xor7, qm31.Mul(xor4, qm31Const(256)))

	return XorRot32R8Result{
		Res0:     res0,
		Res1:     res1,
		Xor8Sum0: xorSum0,
		Xor8Sum1: xorSum1,
		Xor8Sum2: xorSum2,
		Xor8Sum3: xorSum3,
	}
}

type XorRot32R7Result struct {
	Res0     m31.QM31
	Res1     m31.QM31
	Xor7Sum0 m31.QM31
	Xor9Sum1 m31.QM31
	Xor7Sum2 m31.QM31
	Xor9Sum3 m31.QM31
}

func XorRot32R7Evaluate(
	qm31 *m31.QM31Chip,
	input0 m31.QM31,
	input1 m31.QM31,
	input2 m31.QM31,
	input3 m31.QM31,
	msb0 m31.QM31,
	msb1 m31.QM31,
	msb2 m31.QM31,
	msb3 m31.QM31,
	xor4 m31.QM31,
	xor5 m31.QM31,
	xor6 m31.QM31,
	xor7 m31.QM31,
	lookup7 m31.InteractionElements,
	lookup9 m31.InteractionElements,
) XorRot32R7Result {
	low0 := Split16LowPartSize7Evaluate(qm31, input0, msb0)
	low1 := Split16LowPartSize7Evaluate(qm31, input1, msb1)
	low2 := Split16LowPartSize7Evaluate(qm31, input2, msb2)
	low3 := Split16LowPartSize7Evaluate(qm31, input3, msb3)

	xor7Sum0 := BitwiseXorNumBits7Evaluate(qm31, low0, low2, xor4, lookup7)
	xor9Sum1 := BitwiseXorNumBits9Evaluate(qm31, msb0, msb2, xor5, lookup9)
	xor7Sum2 := BitwiseXorNumBits7Evaluate(qm31, low1, low3, xor6, lookup7)
	xor9Sum3 := BitwiseXorNumBits9Evaluate(qm31, msb1, msb3, xor7, lookup9)

	res0 := qm31.Add(xor5, qm31.Mul(xor6, qm31Const(512)))
	res1 := qm31.Add(xor7, qm31.Mul(xor4, qm31Const(512)))

	return XorRot32R7Result{
		Res0:     res0,
		Res1:     res1,
		Xor7Sum0: xor7Sum0,
		Xor9Sum1: xor9Sum1,
		Xor7Sum2: xor7Sum2,
		Xor9Sum3: xor9Sum3,
	}
}
