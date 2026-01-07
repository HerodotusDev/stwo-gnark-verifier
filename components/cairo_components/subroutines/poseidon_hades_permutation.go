package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type PoseidonHadesPermutationInputs struct {
	Input                         [30]m31.QM31
	CombinationSets               [7][10]m31.QM31
	PCoefs                        [7]m31.QM31
	PoseidonFullRoundChainOutputs [2][30]m31.QM31
	CubeOutputs                   [2][10]m31.QM31
	Poseidon3PartialOutputs       [40]m31.QM31
	Seq                           m31.QM31
}

type PoseidonHadesPermutationLookups struct {
	PoseidonFullRoundChain      m31.InteractionElements
	RangeCheckFelt252Width27    m31.InteractionElements
	Cube252                     m31.InteractionElements
	RangeCheck33333             m31.InteractionElements
	RangeCheck4444              m31.InteractionElements
	RangeCheck44                m31.InteractionElements
	Poseidon3PartialRoundsChain m31.InteractionElements
}

type PoseidonHadesPermutationResult struct {
	Sum                              m31.QM31
	PoseidonFullRoundChainSum0       m31.QM31
	PoseidonFullRoundChainSum1       m31.QM31
	RangeCheckFelt252Width27Sum2     m31.QM31
	RangeCheckFelt252Width27Sum3     m31.QM31
	Cube252Sum4                      m31.QM31
	RangeCheck33333Sum5              m31.QM31
	RangeCheck33333Sum6              m31.QM31
	Cube252Sum7                      m31.QM31
	RangeCheck4444Sum8               m31.QM31
	RangeCheck4444Sum9               m31.QM31
	RangeCheck44Sum10                m31.QM31
	Poseidon3PartialRoundsChainSum11 m31.QM31
	Poseidon3PartialRoundsChainSum12 m31.QM31
	RangeCheck4444Sum13              m31.QM31
	RangeCheck4444Sum14              m31.QM31
	RangeCheck44Sum15                m31.QM31
	RangeCheck4444Sum16              m31.QM31
	RangeCheck4444Sum17              m31.QM31
	RangeCheck44Sum18                m31.QM31
	PoseidonFullRoundChainSum19      m31.QM31
	PoseidonFullRoundChainSum20      m31.QM31
}

func PoseidonHadesPermutationEvaluate(
	qm31 *m31.QM31Chip,
	in PoseidonHadesPermutationInputs,
	lookups PoseidonHadesPermutationLookups,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) PoseidonHadesPermutationResult {
	var lcInput0 [20]m31.QM31
	copy(lcInput0[:10], in.Input[:10])
	lcInput0[10] = qm31Const(74972783)
	lcInput0[11] = qm31Const(117420501)
	lcInput0[12] = qm31Const(112795138)
	lcInput0[13] = qm31Const(91013252)
	lcInput0[14] = qm31Const(60709090)
	lcInput0[15] = qm31Const(44848225)
	lcInput0[16] = qm31Const(108487870)
	lcInput0[17] = qm31Const(44781849)
	lcInput0[18] = qm31Const(102193642)
	lcInput0[19] = qm31Const(208)
	sum = LinearCombinationN2Coefs11Evaluate(
		qm31,
		lcInput0,
		in.CombinationSets[0],
		in.PCoefs[0],
		sum,
		domainVanishInv,
		randomCoeff,
	)

	var lcInput1 [20]m31.QM31
	copy(lcInput1[:10], in.Input[10:20])
	lcInput1[10] = qm31Const(41224388)
	lcInput1[11] = qm31Const(90391646)
	lcInput1[12] = qm31Const(36279186)
	lcInput1[13] = qm31Const(129717753)
	lcInput1[14] = qm31Const(94624323)
	lcInput1[15] = qm31Const(75104388)
	lcInput1[16] = qm31Const(133303902)
	lcInput1[17] = qm31Const(48945103)
	lcInput1[18] = qm31Const(41320857)
	lcInput1[19] = qm31Const(112)
	sum = LinearCombinationN2Coefs11Evaluate(
		qm31,
		lcInput1,
		in.CombinationSets[1],
		in.PCoefs[1],
		sum,
		domainVanishInv,
		randomCoeff,
	)

	var lcInput2 [20]m31.QM31
	copy(lcInput2[:10], in.Input[20:30])
	lcInput2[10] = qm31Const(4883209)
	lcInput2[11] = qm31Const(28820206)
	lcInput2[12] = qm31Const(79012328)
	lcInput2[13] = qm31Const(49157069)
	lcInput2[14] = qm31Const(78826183)
	lcInput2[15] = qm31Const(72285071)
	lcInput2[16] = qm31Const(33413160)
	lcInput2[17] = qm31Const(90842759)
	lcInput2[18] = qm31Const(60124463)
	lcInput2[19] = qm31Const(116)
	sum = LinearCombinationN2Coefs11Evaluate(
		qm31,
		lcInput2,
		in.CombinationSets[2],
		in.PCoefs[2],
		sum,
		domainVanishInv,
		randomCoeff,
	)

	chainTmp := qm31.Mul(in.Seq, qm31Const(2))

	var result PoseidonHadesPermutationResult

	values := make([]m31.QM31, 0, 32)
	values = append(values, chainTmp, qm31Const(0))
	values = append(values, in.CombinationSets[0][:]...)
	values = append(values, in.CombinationSets[1][:]...)
	values = append(values, in.CombinationSets[2][:]...)
	sum0, err := qm31.Combine(lookups.PoseidonFullRoundChain, values)
	if err != nil {
		panic(err)
	}
	result.PoseidonFullRoundChainSum0 = sum0

	values = values[:0]
	values = append(values, chainTmp, qm31Const(4))
	values = append(values, in.PoseidonFullRoundChainOutputs[0][:]...)
	sum1, err := qm31.Combine(lookups.PoseidonFullRoundChain, values)
	if err != nil {
		panic(err)
	}
	result.PoseidonFullRoundChainSum1 = sum1

	values = values[:0]
	values = append(values, in.PoseidonFullRoundChainOutputs[0][:10]...)
	rcFeltSum2, err := qm31.Combine(lookups.RangeCheckFelt252Width27, values)
	if err != nil {
		panic(err)
	}
	result.RangeCheckFelt252Width27Sum2 = rcFeltSum2

	values = values[:0]
	values = append(values, in.PoseidonFullRoundChainOutputs[0][10:20]...)
	rcFeltSum3, err := qm31.Combine(lookups.RangeCheckFelt252Width27, values)
	if err != nil {
		panic(err)
	}
	result.RangeCheckFelt252Width27Sum3 = rcFeltSum3

	values = values[:0]
	values = append(values, in.PoseidonFullRoundChainOutputs[0][20:30]...)
	values = append(values, in.CubeOutputs[0][:]...)
	cubeSum4, err := qm31.Combine(lookups.Cube252, values)
	if err != nil {
		panic(err)
	}
	result.Cube252Sum4 = cubeSum4

	var lcInput3 [40]m31.QM31
	copy(lcInput3[:20], in.PoseidonFullRoundChainOutputs[0][:20])
	copy(lcInput3[20:30], in.CubeOutputs[0][:])
	lcInput3[30] = qm31Const(103094260)
	lcInput3[31] = qm31Const(121146754)
	lcInput3[32] = qm31Const(95050340)
	lcInput3[33] = qm31Const(16173996)
	lcInput3[34] = qm31Const(50758155)
	lcInput3[35] = qm31Const(54415179)
	lcInput3[36] = qm31Const(19292069)
	lcInput3[37] = qm31Const(45351266)
	lcInput3[38] = qm31Const(122233508)
	lcInput3[39] = qm31Const(248)
	lcRes3 := LinearCombinationN4Coefs11M2_1Evaluate(
		qm31,
		lcInput3,
		in.CombinationSets[3],
		in.PCoefs[3],
		lookups.RangeCheck33333,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = lcRes3.Sum
	result.RangeCheck33333Sum5 = lcRes3.RangeSum0
	result.RangeCheck33333Sum6 = lcRes3.RangeSum1

	values = values[:0]
	values = append(values, in.CombinationSets[3][:]...)
	values = append(values, in.CubeOutputs[1][:]...)
	cubeSum7, err := qm31.Combine(lookups.Cube252, values)
	if err != nil {
		panic(err)
	}
	result.Cube252Sum7 = cubeSum7

	var lcInput4 [40]m31.QM31
	copy(lcInput4[:10], in.PoseidonFullRoundChainOutputs[0][:10])
	copy(lcInput4[10:20], in.CubeOutputs[0][:])
	copy(lcInput4[20:30], in.CubeOutputs[1][:])
	lcInput4[30] = qm31Const(121657377)
	lcInput4[31] = qm31Const(112479959)
	lcInput4[32] = qm31Const(130418270)
	lcInput4[33] = qm31Const(4974792)
	lcInput4[34] = qm31Const(59852719)
	lcInput4[35] = qm31Const(120369218)
	lcInput4[36] = qm31Const(62439890)
	lcInput4[37] = qm31Const(50468641)
	lcInput4[38] = qm31Const(86573645)
	lcInput4[39] = qm31Const(154)
	lcRes4 := LinearCombinationN4Coefs42M2_1Evaluate(
		qm31,
		lcInput4,
		in.CombinationSets[4],
		in.PCoefs[4],
		lookups.RangeCheck4444,
		lookups.RangeCheck44,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = lcRes4.Sum
	result.RangeCheck4444Sum8 = lcRes4.RangeSum0
	result.RangeCheck4444Sum9 = lcRes4.RangeSum1
	result.RangeCheck44Sum10 = lcRes4.RangeSum2

	values = values[:0]
	values = append(values, in.Seq, qm31Const(4))
	values = append(values, in.CubeOutputs[0][:]...)
	values = append(values, in.CombinationSets[3][:]...)
	values = append(values, in.CubeOutputs[1][:]...)
	values = append(values, in.CombinationSets[4][:]...)
	prcSum11, err := qm31.Combine(lookups.Poseidon3PartialRoundsChain, values)
	if err != nil {
		panic(err)
	}
	result.Poseidon3PartialRoundsChainSum11 = prcSum11

	values = values[:0]
	values = append(values, in.Seq, qm31Const(31))
	values = append(values, in.Poseidon3PartialOutputs[:]...)
	prcSum12, err := qm31.Combine(lookups.Poseidon3PartialRoundsChain, values)
	if err != nil {
		panic(err)
	}
	result.Poseidon3PartialRoundsChainSum12 = prcSum12

	var lcInput5 [40]m31.QM31
	copy(lcInput5[:30], in.Poseidon3PartialOutputs[:30])
	lcInput5[30] = qm31Const(40454143)
	lcInput5[31] = qm31Const(49554771)
	lcInput5[32] = qm31Const(55508188)
	lcInput5[33] = qm31Const(116986206)
	lcInput5[34] = qm31Const(88680813)
	lcInput5[35] = qm31Const(45553283)
	lcInput5[36] = qm31Const(62360091)
	lcInput5[37] = qm31Const(77099918)
	lcInput5[38] = qm31Const(22899501)
	lcInput5[39] = qm31Const(99)
	lcRes5 := LinearCombinationN4Coefs42_11Evaluate(
		qm31,
		lcInput5,
		in.CombinationSets[5],
		in.PCoefs[5],
		lookups.RangeCheck4444,
		lookups.RangeCheck44,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = lcRes5.Sum
	result.RangeCheck4444Sum13 = lcRes5.RangeSum0
	result.RangeCheck4444Sum14 = lcRes5.RangeSum1
	result.RangeCheck44Sum15 = lcRes5.RangeSum2

	var lcInput6 [40]m31.QM31
	copy(lcInput6[:20], in.Poseidon3PartialOutputs[20:40])
	copy(lcInput6[20:30], in.CombinationSets[5][:])
	lcInput6[30] = qm31Const(48383197)
	lcInput6[31] = qm31Const(48193339)
	lcInput6[32] = qm31Const(55955004)
	lcInput6[33] = qm31Const(65659846)
	lcInput6[34] = qm31Const(68491350)
	lcInput6[35] = qm31Const(119023582)
	lcInput6[36] = qm31Const(33439011)
	lcInput6[37] = qm31Const(58475513)
	lcInput6[38] = qm31Const(18765944)
	lcInput6[39] = qm31Const(20)
	lcRes6 := LinearCombinationN4Coefs42_11Evaluate(
		qm31,
		lcInput6,
		in.CombinationSets[6],
		in.PCoefs[6],
		lookups.RangeCheck4444,
		lookups.RangeCheck44,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = lcRes6.Sum
	result.RangeCheck4444Sum16 = lcRes6.RangeSum0
	result.RangeCheck4444Sum17 = lcRes6.RangeSum1
	result.RangeCheck44Sum18 = lcRes6.RangeSum2

	chainID := qm31.Add(chainTmp, qm31Const(1))

	values = values[:0]
	values = append(values, chainID, qm31Const(31))
	values = append(values, in.CombinationSets[6][:]...)
	values = append(values, in.CombinationSets[5][:]...)
	values = append(values, in.Poseidon3PartialOutputs[30:40]...)
	sum19, err := qm31.Combine(lookups.PoseidonFullRoundChain, values)
	if err != nil {
		panic(err)
	}
	result.PoseidonFullRoundChainSum19 = sum19

	values = values[:0]
	values = append(values, chainID, qm31Const(35))
	values = append(values, in.PoseidonFullRoundChainOutputs[1][:]...)
	sum20, err := qm31.Combine(lookups.PoseidonFullRoundChain, values)
	if err != nil {
		panic(err)
	}
	result.PoseidonFullRoundChainSum20 = sum20

	result.Sum = sum

	return result
}
