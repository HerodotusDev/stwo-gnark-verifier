package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	poseidonBuiltinTraceColumns       = 341
	poseidonBuiltinInteractionColumns = 68
)

type PoseidonBuiltinClaim struct {
	LogSize                     uint32
	PoseidonBuiltinSegmentStart uint32
}

type PoseidonBuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PoseidonBuiltinComponent struct {
	qm31 *m31.QM31Chip

	memoryAddressToIdElements         m31.InteractionElements
	memoryIdToBigElements             m31.InteractionElements
	poseidonFullRoundChainElements    m31.InteractionElements
	rangeCheckFelt252Width27Elements  m31.InteractionElements
	cube252Elements                   m31.InteractionElements
	range33333Elements                m31.InteractionElements
	range4444Elements                 m31.InteractionElements
	range44Elements                   m31.InteractionElements
	poseidon3PartialRoundsChainLookup m31.InteractionElements

	claimedSum    m31.QM31
	segmentStart  m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
	logSize       uint32
}

func NewPoseidonBuiltin(
	qm31Chip *m31.QM31Chip,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	poseidonFullRoundChainElements m31.InteractionElements,
	rangeCheckFelt252Width27Elements m31.InteractionElements,
	cube252Elements m31.InteractionElements,
	range33333Elements m31.InteractionElements,
	range4444Elements m31.InteractionElements,
	range44Elements m31.InteractionElements,
	poseidon3PartialRoundsChainElements m31.InteractionElements,
	claim PoseidonBuiltinClaim,
	interactionClaim PoseidonBuiltinInteractionClaim,
) *PoseidonBuiltinComponent {
	columnSize := uint64(1) << claim.LogSize
	columnSizeQM := m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))

	return &PoseidonBuiltinComponent{
		qm31:                              qm31Chip,
		memoryAddressToIdElements:         memoryAddressToIdElements,
		memoryIdToBigElements:             memoryIdToBigElements,
		poseidonFullRoundChainElements:    poseidonFullRoundChainElements,
		rangeCheckFelt252Width27Elements:  rangeCheckFelt252Width27Elements,
		cube252Elements:                   cube252Elements,
		range33333Elements:                range33333Elements,
		range4444Elements:                 range4444Elements,
		range44Elements:                   range44Elements,
		poseidon3PartialRoundsChainLookup: poseidon3PartialRoundsChainElements,
		claimedSum:                        interactionClaim.ClaimedSum,
		segmentStart:                      m31.NewQM31FromM31(m31.NewM31Unchecked(uint64(claim.PoseidonBuiltinSegmentStart))),
		columnSizeInv:                     qm31Chip.Inverse(columnSizeQM),
		vanishEvalInv:                     qm31Chip.One(),
		logSize:                           claim.LogSize,
	}
}

func (c *PoseidonBuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(poseidonBuiltinTraceColumns, poseidonBuiltinInteractionColumns)

	trace := traceSampledValues
	interaction := interactionSampledValues

	if len(trace) != poseidonBuiltinTraceColumns {
		panic("poseidon_builtin expects 341 trace columns")
	}
	if len(interaction) != poseidonBuiltinInteractionColumns {
		panic("poseidon_builtin expects 68 interaction columns")
	}

	seqColumn := NewPreprocessedColumnSeq(uints.NewU8(uint8(c.logSize)))
	seq := traces.Get(seqColumn)

	cursor := 0
	nextTrace := func() m31.QM31 {
		if cursor >= len(trace) {
			panic("insufficient trace columns")
		}
		column := trace[cursor]
		cursor++
		if len(column) == 0 {
			panic("trace column missing sampled value")
		}
		return column[0]
	}

	var inputIDs [3]m31.QM31
	var inputLimbs [3][28]m31.QM31
	for state := 0; state < 3; state++ {
		inputIDs[state] = nextTrace()
		for i := 0; i < 28; i++ {
			inputLimbs[state][i] = nextTrace()
		}
	}

	var combinationSets [7][10]m31.QM31
	var pCoefs [7]m31.QM31
	for set := 0; set < 3; set++ {
		for i := 0; i < 10; i++ {
			combinationSets[set][i] = nextTrace()
		}
		pCoefs[set] = nextTrace()
	}

	var frOutputs0 [30]m31.QM31
	for i := 0; i < 30; i++ {
		frOutputs0[i] = nextTrace()
	}

	var cubeOutputs [2][10]m31.QM31
	for i := 0; i < 10; i++ {
		cubeOutputs[0][i] = nextTrace()
	}
	for i := 0; i < 10; i++ {
		combinationSets[3][i] = nextTrace()
	}
	pCoefs[3] = nextTrace()
	for i := 0; i < 10; i++ {
		cubeOutputs[1][i] = nextTrace()
	}
	for i := 0; i < 10; i++ {
		combinationSets[4][i] = nextTrace()
	}
	pCoefs[4] = nextTrace()

	var prcOutputs [40]m31.QM31
	for i := 0; i < 40; i++ {
		prcOutputs[i] = nextTrace()
	}

	for i := 0; i < 10; i++ {
		combinationSets[5][i] = nextTrace()
	}
	pCoefs[5] = nextTrace()
	for i := 0; i < 10; i++ {
		combinationSets[6][i] = nextTrace()
	}
	pCoefs[6] = nextTrace()

	var frOutputs1 [30]m31.QM31
	for i := 0; i < 30; i++ {
		frOutputs1[i] = nextTrace()
	}

	var unpack0, unpack1, unpack2 [18]m31.QM31
	for i := 0; i < 18; i++ {
		unpack0[i] = nextTrace()
	}
	outputStateID0 := nextTrace()
	for i := 0; i < 18; i++ {
		unpack1[i] = nextTrace()
	}
	outputStateID1 := nextTrace()
	for i := 0; i < 18; i++ {
		unpack2[i] = nextTrace()
	}
	outputStateID2 := nextTrace()

	if cursor != poseidonBuiltinTraceColumns {
		panic("unexpected trace column count")
	}

	baseAddress := c.qm31.Add(c.segmentStart, c.qm31.Mul(seq, qm31Const(6)))

	read0 := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		baseAddress,
		inputIDs[0],
		inputLimbs[0][:],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	read1 := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(baseAddress, qm31Const(1)),
		inputIDs[1],
		inputLimbs[1][:],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)
	read2 := sub.ReadPositiveNumBits252Evaluate(
		c.qm31,
		c.qm31.Add(baseAddress, qm31Const(2)),
		inputIDs[2],
		inputLimbs[2][:],
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
	)

	pack0 := packPoseidonState(c.qm31, inputLimbs[0])
	pack1 := packPoseidonState(c.qm31, inputLimbs[1])
	pack2 := packPoseidonState(c.qm31, inputLimbs[2])

	var hadesIn sub.PoseidonHadesPermutationInputs
	copy(hadesIn.Input[0:10], pack0[:])
	copy(hadesIn.Input[10:20], pack1[:])
	copy(hadesIn.Input[20:30], pack2[:])
	hadesIn.CombinationSets = combinationSets
	copy(hadesIn.PCoefs[:], pCoefs[:])
	copy(hadesIn.PoseidonFullRoundChainOutputs[0][:], frOutputs0[:])
	copy(hadesIn.PoseidonFullRoundChainOutputs[1][:], frOutputs1[:])
	hadesIn.CubeOutputs = cubeOutputs
	hadesIn.Poseidon3PartialOutputs = prcOutputs
	hadesIn.Seq = seq

	hadesLookups := sub.PoseidonHadesPermutationLookups{
		PoseidonFullRoundChain:      c.poseidonFullRoundChainElements,
		RangeCheckFelt252Width27:    c.rangeCheckFelt252Width27Elements,
		Cube252:                     c.cube252Elements,
		RangeCheck33333:             c.range33333Elements,
		RangeCheck4444:              c.range4444Elements,
		RangeCheck44:                c.range44Elements,
		Poseidon3PartialRoundsChain: c.poseidon3PartialRoundsChainLookup,
	}

	hadesRes := sub.PoseidonHadesPermutationEvaluate(
		c.qm31,
		hadesIn,
		hadesLookups,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = hadesRes.Sum

	var inputs0 [10]m31.QM31
	copy(inputs0[:], frOutputs1[0:10])
	low0, high0 := splitUnpackPairs(unpack0)
	feltOut0 := sub.Felt252UnpackFrom27Evaluate(c.qm31, inputs0, low0, high0)

	var inputs1 [10]m31.QM31
	copy(inputs1[:], frOutputs1[10:20])
	low1, high1 := splitUnpackPairs(unpack1)
	feltOut1 := sub.Felt252UnpackFrom27Evaluate(c.qm31, inputs1, low1, high1)

	var inputs2 [10]m31.QM31
	copy(inputs2[:], frOutputs1[20:30])
	low2, high2 := splitUnpackPairs(unpack2)
	feltOut2 := sub.Felt252UnpackFrom27Evaluate(c.qm31, inputs2, low2, high2)

	memInput0 := buildMemVerifyLimbs(unpack0, feltOut0, frOutputs1[9])
	memInput1 := buildMemVerifyLimbs(unpack1, feltOut1, frOutputs1[19])
	memInput2 := buildMemVerifyLimbs(unpack2, feltOut2, frOutputs1[29])

	memRes0 := sub.MemVerifyEvaluate(
		c.qm31,
		c.qm31.Add(baseAddress, qm31Const(3)),
		memInput0[:],
		outputStateID0,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memRes1 := sub.MemVerifyEvaluate(
		c.qm31,
		c.qm31.Add(baseAddress, qm31Const(4)),
		memInput1[:],
		outputStateID1,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	memRes2 := sub.MemVerifyEvaluate(
		c.qm31,
		c.qm31.Add(baseAddress, qm31Const(5)),
		memInput2[:],
		outputStateID2,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)

	var partials [17]m31.QM31
	for group := 0; group < 16; group++ {
		idx := group * 4
		partials[group] = c.qm31.FromPartialEvals(
			interaction[idx+0][0],
			interaction[idx+1][0],
			interaction[idx+2][0],
			interaction[idx+3][0],
		)
	}
	partials[16] = c.qm31.FromPartialEvals(
		interaction[64][1],
		interaction[65][1],
		interaction[66][1],
		interaction[67][1],
	)

	if len(interaction[64]) < 2 || len(interaction[65]) < 2 || len(interaction[66]) < 2 || len(interaction[67]) < 2 {
		panic("interaction columns missing neg1 values")
	}
	partialNeg1 := c.qm31.FromPartialEvals(
		interaction[64][0],
		interaction[65][0],
		interaction[66][0],
		interaction[67][0],
	)

	apply := func(constraint m31.QM31) {
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)
	}

	memoryAddressToIdSum0 := read0.AddressLookupSum
	memoryIdToBigSum1 := read0.IdToBigLookupSum
	memoryAddressToIdSum2 := read1.AddressLookupSum
	memoryIdToBigSum3 := read1.IdToBigLookupSum
	memoryAddressToIdSum4 := read2.AddressLookupSum
	memoryIdToBigSum5 := read2.IdToBigLookupSum

	poseidonFullRoundChainSum6 := hadesRes.PoseidonFullRoundChainSum0
	poseidonFullRoundChainSum7 := hadesRes.PoseidonFullRoundChainSum1
	rangeCheckFelt252Width27Sum8 := hadesRes.RangeCheckFelt252Width27Sum2
	rangeCheckFelt252Width27Sum9 := hadesRes.RangeCheckFelt252Width27Sum3
	cube252Sum10 := hadesRes.Cube252Sum4
	range33333Sum11 := hadesRes.RangeCheck33333Sum5
	range33333Sum12 := hadesRes.RangeCheck33333Sum6
	cube252Sum13 := hadesRes.Cube252Sum7
	range4444Sum14 := hadesRes.RangeCheck4444Sum8
	range4444Sum15 := hadesRes.RangeCheck4444Sum9
	range44Sum16 := hadesRes.RangeCheck44Sum10
	poseidon3PartialSum17 := hadesRes.Poseidon3PartialRoundsChainSum11
	poseidon3PartialSum18 := hadesRes.Poseidon3PartialRoundsChainSum12
	range4444Sum19 := hadesRes.RangeCheck4444Sum13
	range4444Sum20 := hadesRes.RangeCheck4444Sum14
	range44Sum21 := hadesRes.RangeCheck44Sum15
	range4444Sum22 := hadesRes.RangeCheck4444Sum16
	range4444Sum23 := hadesRes.RangeCheck4444Sum17
	range44Sum24 := hadesRes.RangeCheck44Sum18
	poseidonFullRoundChainSum25 := hadesRes.PoseidonFullRoundChainSum19
	poseidonFullRoundChainSum26 := hadesRes.PoseidonFullRoundChainSum20

	memoryAddressToIdSum27 := memRes0.AddressLookupSum
	memoryIdToBigSum28 := memRes0.IdToBigLookupSum
	memoryAddressToIdSum29 := memRes1.AddressLookupSum
	memoryIdToBigSum30 := memRes1.IdToBigLookupSum
	memoryAddressToIdSum31 := memRes2.AddressLookupSum
	memoryIdToBigSum32 := memRes2.IdToBigLookupSum

	diff := c.qm31.Mul(partials[0], memoryAddressToIdSum0)
	diff = c.qm31.Mul(diff, memoryIdToBigSum1)
	diff = c.qm31.Sub(diff, memoryAddressToIdSum0)
	diff = c.qm31.Sub(diff, memoryIdToBigSum1)
	apply(diff)

	curr := c.qm31.Sub(partials[1], partials[0])
	curr = c.qm31.Mul(curr, memoryAddressToIdSum2)
	curr = c.qm31.Mul(curr, memoryIdToBigSum3)
	curr = c.qm31.Sub(curr, memoryAddressToIdSum2)
	curr = c.qm31.Sub(curr, memoryIdToBigSum3)
	apply(curr)

	curr = c.qm31.Sub(partials[2], partials[1])
	curr = c.qm31.Mul(curr, memoryAddressToIdSum4)
	curr = c.qm31.Mul(curr, memoryIdToBigSum5)
	curr = c.qm31.Sub(curr, memoryAddressToIdSum4)
	curr = c.qm31.Sub(curr, memoryIdToBigSum5)
	apply(curr)

	curr = c.qm31.Sub(partials[3], partials[2])
	curr = c.qm31.Mul(curr, poseidonFullRoundChainSum6)
	curr = c.qm31.Mul(curr, poseidonFullRoundChainSum7)
	curr = c.qm31.Sub(curr, poseidonFullRoundChainSum6)
	curr = c.qm31.Add(curr, poseidonFullRoundChainSum7)
	apply(curr)

	curr = c.qm31.Sub(partials[4], partials[3])
	curr = c.qm31.Mul(curr, rangeCheckFelt252Width27Sum8)
	curr = c.qm31.Mul(curr, rangeCheckFelt252Width27Sum9)
	curr = c.qm31.Sub(curr, rangeCheckFelt252Width27Sum8)
	curr = c.qm31.Sub(curr, rangeCheckFelt252Width27Sum9)
	apply(curr)

	curr = c.qm31.Sub(partials[5], partials[4])
	curr = c.qm31.Mul(curr, cube252Sum10)
	curr = c.qm31.Mul(curr, range33333Sum11)
	curr = c.qm31.Sub(curr, cube252Sum10)
	curr = c.qm31.Sub(curr, range33333Sum11)
	apply(curr)

	curr = c.qm31.Sub(partials[6], partials[5])
	curr = c.qm31.Mul(curr, range33333Sum12)
	curr = c.qm31.Mul(curr, cube252Sum13)
	curr = c.qm31.Sub(curr, range33333Sum12)
	curr = c.qm31.Sub(curr, cube252Sum13)
	apply(curr)

	curr = c.qm31.Sub(partials[7], partials[6])
	curr = c.qm31.Mul(curr, range4444Sum14)
	curr = c.qm31.Mul(curr, range4444Sum15)
	curr = c.qm31.Sub(curr, range4444Sum14)
	curr = c.qm31.Sub(curr, range4444Sum15)
	apply(curr)

	curr = c.qm31.Sub(partials[8], partials[7])
	curr = c.qm31.Mul(curr, range44Sum16)
	curr = c.qm31.Mul(curr, poseidon3PartialSum17)
	curr = c.qm31.Add(curr, range44Sum16)
	curr = c.qm31.Sub(curr, poseidon3PartialSum17)
	apply(curr)

	curr = c.qm31.Sub(partials[9], partials[8])
	curr = c.qm31.Mul(curr, poseidon3PartialSum18)
	curr = c.qm31.Mul(curr, range4444Sum19)
	curr = c.qm31.Sub(curr, poseidon3PartialSum18)
	curr = c.qm31.Sub(curr, range4444Sum19)
	apply(curr)

	curr = c.qm31.Sub(partials[10], partials[9])
	curr = c.qm31.Mul(curr, range4444Sum20)
	curr = c.qm31.Mul(curr, range44Sum21)
	curr = c.qm31.Sub(curr, range4444Sum20)
	curr = c.qm31.Sub(curr, range44Sum21)
	apply(curr)

	curr = c.qm31.Sub(partials[11], partials[10])
	curr = c.qm31.Mul(curr, range4444Sum22)
	curr = c.qm31.Mul(curr, range4444Sum23)
	curr = c.qm31.Sub(curr, range4444Sum22)
	curr = c.qm31.Sub(curr, range4444Sum23)
	apply(curr)

	curr = c.qm31.Sub(partials[12], partials[11])
	curr = c.qm31.Mul(curr, range44Sum24)
	curr = c.qm31.Mul(curr, poseidonFullRoundChainSum25)
	curr = c.qm31.Add(curr, range44Sum24)
	curr = c.qm31.Sub(curr, poseidonFullRoundChainSum25)
	apply(curr)

	curr = c.qm31.Sub(partials[13], partials[12])
	curr = c.qm31.Mul(curr, poseidonFullRoundChainSum26)
	curr = c.qm31.Mul(curr, memoryAddressToIdSum27)
	curr = c.qm31.Sub(curr, poseidonFullRoundChainSum26)
	curr = c.qm31.Sub(curr, memoryAddressToIdSum27)
	apply(curr)

	curr = c.qm31.Sub(partials[14], partials[13])
	curr = c.qm31.Mul(curr, memoryIdToBigSum28)
	curr = c.qm31.Mul(curr, memoryAddressToIdSum29)
	curr = c.qm31.Sub(curr, memoryIdToBigSum28)
	curr = c.qm31.Sub(curr, memoryAddressToIdSum29)
	apply(curr)

	curr = c.qm31.Sub(partials[15], partials[14])
	curr = c.qm31.Mul(curr, memoryIdToBigSum30)
	curr = c.qm31.Mul(curr, memoryAddressToIdSum31)
	curr = c.qm31.Sub(curr, memoryIdToBigSum30)
	curr = c.qm31.Sub(curr, memoryAddressToIdSum31)
	apply(curr)

	curr = c.qm31.Sub(partials[16], partials[15])
	curr = c.qm31.Sub(curr, partialNeg1)
	curr = c.qm31.Add(curr, c.qm31.Mul(c.claimedSum, c.columnSizeInv))
	curr = c.qm31.Mul(curr, memoryIdToBigSum32)
	curr = c.qm31.Sub(curr, qm31Const(1))
	apply(curr)

	return sum
}

func packPoseidonState(qm31 *m31.QM31Chip, limbs [28]m31.QM31) [10]m31.QM31 {
	scale := qm31Const(512)
	scaleSquare := qm31Const(262144)
	var packed [10]m31.QM31
	for i := 0; i < 9; i++ {
		base := i * 3
		term := qm31.Mul(limbs[base+1], scale)
		term = qm31.Add(term, qm31.Mul(limbs[base+2], scaleSquare))
		packed[i] = qm31.Add(limbs[base], term)
	}
	packed[9] = limbs[27]
	return packed
}

func splitUnpackPairs(values [18]m31.QM31) (low [9]m31.QM31, high [9]m31.QM31) {
	for i := 0; i < 9; i++ {
		low[i] = values[2*i]
		high[i] = values[2*i+1]
	}
	return
}

func buildMemVerifyLimbs(unpacked [18]m31.QM31, felt [10]m31.QM31, tail m31.QM31) [28]m31.QM31 {
	var result [28]m31.QM31
	idx := 0
	for i := 0; i < 9; i++ {
		result[idx] = unpacked[2*i]
		result[idx+1] = unpacked[2*i+1]
		result[idx+2] = felt[i]
		idx += 3
	}
	result[27] = tail
	return result
}
