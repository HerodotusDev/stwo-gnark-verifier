package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ECAddInputs struct {
	X1 [28]m31.QM31
	Y1 [28]m31.QM31
	X2 [28]m31.QM31
	Y2 [28]m31.QM31
}

type ECAddTrace struct {
	// x2 - x1
	SubDiff1     [28]m31.QM31
	SubDiff1PBit m31.QM31

	// x2 + x1
	AddRes     [28]m31.QM31
	AddResPBit m31.QM31

	// y2 - y1
	SubDiff2     [28]m31.QM31
	SubDiff2PBit m31.QM31

	// (y2 - y1) / (x2 - x1)
	DivRes     [28]m31.QM31
	DivK       m31.QM31
	DivCarries [27]m31.QM31

	// slope^2
	Mul1Res     [28]m31.QM31
	Mul1K       m31.QM31
	Mul1Carries [27]m31.QM31

	// slope^2 - (x2 + x1)
	SubDiff3     [28]m31.QM31
	SubDiff3PBit m31.QM31

	// x1 - (slope^2 - (x2 + x1))
	SubDiff4     [28]m31.QM31
	SubDiff4PBit m31.QM31

	// slope * (x1 - x3)
	Mul2Res     [28]m31.QM31
	Mul2K       m31.QM31
	Mul2Carries [27]m31.QM31

	// (slope * (x1 - x3)) - y1
	SubDiff5     [28]m31.QM31
	SubDiff5PBit m31.QM31
}

type ECAddResult struct {
	Sum              m31.QM31
	RangeCheck9Sums  [211]m31.QM31
	RangeCheck19Sums [197]m31.QM31
}

func ECAddEvaluate(
	qm31 *m31.QM31Chip,
	inputs ECAddInputs,
	trace ECAddTrace,
	rangeCheck9Elements m31.InteractionElements,
	rangeCheck19Elements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ECAddResult {
	var range9 [211]m31.QM31
	var range19 [197]m31.QM31

	for i := range range9 {
		range9[i] = qm31.Zero()
	}
	for i := range range19 {
		range19[i] = qm31.Zero()
	}

	sub1 := Sub252Evaluate(
		qm31,
		inputs.X2[:],
		inputs.X1[:],
		trace.SubDiff1[:],
		trace.SubDiff1PBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = sub1.Sum
	copy(range9[0:14], sub1.RangeCheckSums[:])

	add := Add252Evaluate(
		qm31,
		inputs.X2[:],
		inputs.X1[:],
		trace.AddRes[:],
		trace.AddResPBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = add.Sum
	copy(range9[14:28], add.RangeCheckSums[:])

	sub2 := Sub252Evaluate(
		qm31,
		inputs.Y2[:],
		inputs.Y1[:],
		trace.SubDiff2[:],
		trace.SubDiff2PBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = sub2.Sum
	copy(range9[28:42], sub2.RangeCheckSums[:])

	div := Div252Evaluate(
		qm31,
		trace.SubDiff2[:],
		trace.SubDiff1[:],
		trace.DivRes[:],
		trace.DivK,
		trace.DivCarries[:],
		rangeCheck9Elements,
		rangeCheck19Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = div.Sum
	copy(range9[42:56], div.ResultRangeSums[:])
	copy(range19[56:84], div.CarryRangeSums[:])

	mul1 := Mul252Evaluate(
		qm31,
		trace.DivRes[:],
		trace.DivRes[:],
		trace.Mul1Res[:],
		trace.Mul1K,
		trace.Mul1Carries[:],
		rangeCheck9Elements,
		rangeCheck19Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = mul1.Sum
	copy(range9[84:98], mul1.ResultRangeSums[:])
	copy(range19[98:126], mul1.CarryRangeSums[:])

	sub3 := Sub252Evaluate(
		qm31,
		trace.Mul1Res[:],
		trace.AddRes[:],
		trace.SubDiff3[:],
		trace.SubDiff3PBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = sub3.Sum
	copy(range9[126:140], sub3.RangeCheckSums[:])

	sub4 := Sub252Evaluate(
		qm31,
		inputs.X1[:],
		trace.SubDiff3[:],
		trace.SubDiff4[:],
		trace.SubDiff4PBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = sub4.Sum
	copy(range9[140:154], sub4.RangeCheckSums[:])

	mul2 := Mul252Evaluate(
		qm31,
		trace.DivRes[:],
		trace.SubDiff4[:],
		trace.Mul2Res[:],
		trace.Mul2K,
		trace.Mul2Carries[:],
		rangeCheck9Elements,
		rangeCheck19Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = mul2.Sum
	copy(range9[154:168], mul2.ResultRangeSums[:])
	copy(range19[168:196], mul2.CarryRangeSums[:])

	sub5 := Sub252Evaluate(
		qm31,
		trace.Mul2Res[:],
		inputs.Y1[:],
		trace.SubDiff5[:],
		trace.SubDiff5PBit,
		rangeCheck9Elements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = sub5.Sum
	copy(range9[196:210], sub5.RangeCheckSums[:])

	return ECAddResult{
		Sum:              sum,
		RangeCheck9Sums:  range9,
		RangeCheck19Sums: range19,
	}
}
