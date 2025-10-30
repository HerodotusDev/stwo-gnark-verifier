package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	blakeCompressTraceColumns       = 169
	blakeCompressInteractionColumns = 148
)

type BlakeCompressOpcodeClaim struct {
	LogSize uint32
}

type BlakeCompressOpcodeInteractionClaim struct {
	ClaimedSum m31.QM31
}

type BlakeCompressOpcodeComponent struct {
	qm31 *m31.QM31Chip

	verifyInstructionElements m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck725Elements     m31.InteractionElements
	verifyBitwiseXor8Elements m31.InteractionElements
	blakeRoundElements        m31.InteractionElements
	tripleXor32Elements       m31.InteractionElements
	opcodesElements           m31.InteractionElements

	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
	logSize       uint8
}

func NewBlakeCompressOpcode(
	qm31 *m31.QM31Chip,
	verifyInstructionElements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck725Elements m31.InteractionElements,
	verifyBitwiseXor8Elements m31.InteractionElements,
	blakeRoundElements m31.InteractionElements,
	tripleXor32Elements m31.InteractionElements,
	opcodesElements m31.InteractionElements,
	claim BlakeCompressOpcodeClaim,
	interactionClaim BlakeCompressOpcodeInteractionClaim,
) *BlakeCompressOpcodeComponent {
	columnSize := uint32(1)
	if claim.LogSize > 0 {
		columnSize <<= claim.LogSize
	}
	columnSizeInv := qm31.Inverse(m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize)))

	return &BlakeCompressOpcodeComponent{
		qm31:                      qm31,
		verifyInstructionElements: verifyInstructionElements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck725Elements:     rangeCheck725Elements,
		verifyBitwiseXor8Elements: verifyBitwiseXor8Elements,
		blakeRoundElements:        blakeRoundElements,
		tripleXor32Elements:       tripleXor32Elements,
		opcodesElements:           opcodesElements,
		claimedSum:                interactionClaim.ClaimedSum,
		columnSizeInv:             columnSizeInv,
		vanishEvalInv:             qm31.One(),
		logSize:                   uint8(claim.LogSize),
	}
}

func (c *BlakeCompressOpcodeComponent) Evaluate(
	sum m31.QM31,
	preprocessedSampledValues PreprocessedSampledValues,
	traceSampledValues [][]m31.QM31,
	interactionSampledValues [][]m31.QM31,
	randomCoeff m31.QM31,
) m31.QM31 {
	if len(traceSampledValues) != blakeCompressTraceColumns {
		panic("blake_compress_opcode expects 169 trace columns")
	}
	if len(interactionSampledValues) != blakeCompressInteractionColumns {
		panic("blake_compress_opcode expects 148 interaction columns")
	}

	getTrace := func(idx int) m31.QM31 {
		col := traceSampledValues[idx]
		if len(col) == 0 {
			panic("trace column empty")
		}
		return col[0]
	}

	seq := preprocessedSampledValues.Get(
		NewPreprocessedColumnSeq(uints.NewU8(c.logSize)),
	)

	pc := getTrace(0)
	ap := getTrace(1)
	fp := getTrace(2)

	offsets := [3]m31.QM31{
		getTrace(3),
		getTrace(4),
		getTrace(5),
	}

	flags := sub.BlakeOpcodeFlags{
		DstBaseFP:   getTrace(6),
		Op0BaseFP:   getTrace(7),
		Op1BaseFP:   getTrace(8),
		Op1BaseAP:   getTrace(9),
		ApUpdateAdd: getTrace(10),
	}

	opcodeExtension := getTrace(11)

	memBases := sub.BlakeMemBases{
		Mem0:   getTrace(12),
		Mem1:   getTrace(17),
		MemDst: getTrace(26),
	}

	op0 := sub.BlakeOperand{
		ID: getTrace(13),
		Limbs: [3]m31.QM31{
			getTrace(14),
			getTrace(15),
			getTrace(16),
		},
	}

	op1 := sub.BlakeOperand{
		ID: getTrace(18),
		Limbs: [3]m31.QM31{
			getTrace(19),
			getTrace(20),
			getTrace(21),
		},
	}

	apOperand := sub.BlakeOperand{
		ID: getTrace(22),
		Limbs: [3]m31.QM31{
			getTrace(23),
			getTrace(24),
			getTrace(25),
		},
	}

	dstWord := sub.BlakeWordInputs{
		Low16Bits:    getTrace(27),
		High16Bits:   getTrace(28),
		Low7MsBits:   getTrace(29),
		High14MsBits: getTrace(30),
		High5MsBits:  getTrace(31),
		StateID:      getTrace(32),
	}

	enabler := getTrace(168)

	// Enforce boolean enabler
	enablerConstraint := c.qm31.Sub(c.qm31.Mul(enabler, enabler), enabler)
	enablerConstraint = c.qm31.Mul(enablerConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, enablerConstraint)

	decodeRes := sub.DecodeBlakeOpcodeEvaluate(
		c.qm31,
		pc,
		ap,
		fp,
		offsets,
		flags,
		opcodeExtension,
		memBases,
		op0,
		op1,
		apOperand,
		sub.BlakeDstInput{
			Base: memBases.MemDst,
			Word: dstWord,
		},
		c.verifyInstructionElements,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.rangeCheck725Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = decodeRes.Sum

	verifyInstructionSum := decodeRes.Instruction.VerifySum
	memoryAddressToIdSum1 := decodeRes.Op0Lookup.AddressLookupSum
	memoryIdToBigSum2 := decodeRes.Op0Lookup.IdToBigLookupSum
	memoryAddressToIdSum3 := decodeRes.Op1Lookup.AddressLookupSum
	memoryIdToBigSum4 := decodeRes.Op1Lookup.IdToBigLookupSum
	memoryAddressToIdSum5 := decodeRes.ApLookup.AddressLookupSum
	memoryIdToBigSum6 := decodeRes.ApLookup.IdToBigLookupSum
	rangeCheckSum7 := decodeRes.DstLookup.RangeCheckSum
	memoryAddressToIdSum8 := decodeRes.DstLookup.AddressLookupSum
	memoryIdToBigSum9 := decodeRes.DstLookup.IdToBigLookupSum

	decodeOutputs := decodeRes.Outputs

	messageLow16 := getTrace(27)
	messageHigh16 := getTrace(28)

	var stateWords [8]sub.BlakeWordInputs
	for i := 0; i < 8; i++ {
		base := 33 + i*6
		stateWords[i] = sub.BlakeWordInputs{
			Low16Bits:    getTrace(base),
			High16Bits:   getTrace(base + 1),
			Low7MsBits:   getTrace(base + 2),
			High14MsBits: getTrace(base + 3),
			High5MsBits:  getTrace(base + 4),
			StateID:      getTrace(base + 5),
		}
	}

	ms8Bits := [2]m31.QM31{
		getTrace(81),
		getTrace(82),
	}

	xorValues := [4]m31.QM31{
		getTrace(83),
		getTrace(84),
		getTrace(85),
		getTrace(86),
	}

	createInput := sub.CreateBlakeRoundInputEvaluate(
		c.qm31,
		[4]m31.QM31{
			decodeOutputs[0],
			messageLow16,
			messageHigh16,
			decodeOutputs[3],
		},
		stateWords,
		ms8Bits,
		xorValues,
		c.rangeCheck725Elements,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		c.verifyBitwiseXor8Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = createInput.Sum

	rangeCheckInput := createInput.RangeCheckSums
	addressInput := createInput.AddressLookupSums
	idInput := createInput.IdToBigLookupSums
	verifyXorSums := createInput.VerifyXorSums

	createOutputs := createInput.Outputs

	blakeRoundSum38 := c.combineBlakeRoundSum38(
		seq,
		stateWords,
		createOutputs,
		decodeOutputs[1],
	)

	blakeRoundOutputs := make([]m31.QM31, 33)
	for i := 0; i < len(blakeRoundOutputs); i++ {
		blakeRoundOutputs[i] = getTrace(87 + i)
	}

	blakeRoundSum39 := c.combineBlakeRoundSum39(
		seq,
		blakeRoundOutputs,
	)

	var triplePairs [8]sub.TripleXorPair
	for i := 0; i < 8; i++ {
		triplePairs[i] = sub.TripleXorPair{
			Limb0: getTrace(120 + i*2),
			Limb1: getTrace(121 + i*2),
		}
	}

	createOutput := sub.CreateBlakeOutputEvaluate(
		c.qm31,
		c.buildBlakeOutputInputs(stateWords, blakeRoundOutputs),
		triplePairs,
		c.tripleXor32Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = createOutput.Sum
	tripleXorSums := createOutput.LookupSums

	type newStateWord struct {
		Low7   m31.QM31
		High14 m31.QM31
		High5  m31.QM31
		ID     m31.QM31
	}

	newState := make([]newStateWord, 8)
	for i := 0; i < 8; i++ {
		base := 136 + i*4
		newState[i] = newStateWord{
			Low7:   getTrace(base),
			High14: getTrace(base + 1),
			High5:  getTrace(base + 2),
			ID:     getTrace(base + 3),
		}
	}

	rangeCheckNew := make([]m31.QM31, 8)
	addressNew := make([]m31.QM31, 8)
	idNew := make([]m31.QM31, 8)

	for i := 0; i < 8; i++ {
		address := decodeOutputs[2]
		if i > 0 {
			address = c.qm31.Add(address, qm31Const(uint64(i)))
		}

		verifyRes := sub.VerifyBlakeWordEvaluate(
			c.qm31,
			[3]m31.QM31{
				address,
				triplePairs[i].Limb0,
				triplePairs[i].Limb1,
			},
			newState[i].Low7,
			newState[i].High14,
			newState[i].High5,
			newState[i].ID,
			c.rangeCheck725Elements,
			c.memoryAddressToIdElements,
			c.memoryIdToBigElements,
			sum,
			c.vanishEvalInv,
			randomCoeff,
		)
		sum = verifyRes.Sum
		rangeCheckNew[i] = verifyRes.RangeCheckSum
		addressNew[i] = verifyRes.AddressLookupSum
		idNew[i] = verifyRes.IdToBigLookupSum
	}

	opcodesSum72, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{pc, ap, fp},
	)
	if err != nil {
		panic(err)
	}

	opcodesSum73, err := c.qm31.Combine(
		c.opcodesElements,
		[]m31.QM31{
			c.qm31.Add(pc, qm31Const(1)),
			c.qm31.Add(ap, flags.ApUpdateAdd),
			fp,
		},
	)
	if err != nil {
		panic(err)
	}

	pairs := c.buildBlakeCompressPairs(
		verifyInstructionSum,
		memoryAddressToIdSum1,
		memoryIdToBigSum2,
		memoryAddressToIdSum3,
		memoryIdToBigSum4,
		memoryAddressToIdSum5,
		memoryIdToBigSum6,
		rangeCheckSum7,
		memoryAddressToIdSum8,
		memoryIdToBigSum9,
		rangeCheckInput,
		addressInput,
		idInput,
		verifyXorSums,
		blakeRoundSum38,
		blakeRoundSum39,
		tripleXorSums,
		rangeCheckNew,
		addressNew,
		idNew,
	)

	sum = blakeCompressLookupConstraints(
		c.qm31,
		sum,
		interactionSampledValues,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		enabler,
		c.columnSizeInv,
		pairs,
		opcodesSum72,
		opcodesSum73,
	)

	return sum
}

func (c *BlakeCompressOpcodeComponent) combineBlakeRoundSum38(
	seq m31.QM31,
	stateWords [8]sub.BlakeWordInputs,
	createOutputs [4]m31.QM31,
	decodeOutput m31.QM31,
) m31.QM31 {
	values := []m31.QM31{
		seq,
		c.qm31.Zero(),
		stateWords[0].Low16Bits,
		stateWords[0].High16Bits,
		stateWords[1].Low16Bits,
		stateWords[1].High16Bits,
		stateWords[2].Low16Bits,
		stateWords[2].High16Bits,
		stateWords[3].Low16Bits,
		stateWords[3].High16Bits,
		stateWords[4].Low16Bits,
		stateWords[4].High16Bits,
		stateWords[5].Low16Bits,
		stateWords[5].High16Bits,
		stateWords[6].Low16Bits,
		stateWords[6].High16Bits,
		stateWords[7].Low16Bits,
		stateWords[7].High16Bits,
		qm31Const(58983),
		qm31Const(27145),
		qm31Const(44677),
		qm31Const(47975),
		qm31Const(62322),
		qm31Const(15470),
		qm31Const(62778),
		qm31Const(42319),
		createOutputs[0],
		createOutputs[1],
		qm31Const(26764),
		qm31Const(39685),
		createOutputs[2],
		createOutputs[3],
		qm31Const(52505),
		qm31Const(23520),
		decodeOutput,
	}

	sum, err := c.qm31.Combine(c.blakeRoundElements, values)
	if err != nil {
		panic(err)
	}
	return sum
}

func (c *BlakeCompressOpcodeComponent) combineBlakeRoundSum39(
	seq m31.QM31,
	blakeRoundOutputs []m31.QM31,
) m31.QM31 {
	values := make([]m31.QM31, 0, 35)
	values = append(values, seq)
	values = append(values, qm31Const(10))
	values = append(values, blakeRoundOutputs...)
	sum, err := c.qm31.Combine(c.blakeRoundElements, values)
	if err != nil {
		panic(err)
	}
	return sum
}

func (c *BlakeCompressOpcodeComponent) buildBlakeOutputInputs(
	stateWords [8]sub.BlakeWordInputs,
	blakeRoundOutputs []m31.QM31,
) []m31.QM31 {
	inputs := make([]m31.QM31, 0, 48)
	for i := 0; i < 8; i++ {
		inputs = append(inputs, stateWords[i].Low16Bits, stateWords[i].High16Bits)
	}
	inputs = append(inputs, blakeRoundOutputs[:32]...)
	return inputs
}

type blakeCompressPair struct {
	First          m31.QM31
	Second         m31.QM31
	SecondPositive bool
}

func (c *BlakeCompressOpcodeComponent) buildBlakeCompressPairs(
	verifyInstructionSum m31.QM31,
	memoryAddressToIdSum1 m31.QM31,
	memoryIdToBigSum2 m31.QM31,
	memoryAddressToIdSum3 m31.QM31,
	memoryIdToBigSum4 m31.QM31,
	memoryAddressToIdSum5 m31.QM31,
	memoryIdToBigSum6 m31.QM31,
	rangeCheckSum7 m31.QM31,
	memoryAddressToIdSum8 m31.QM31,
	memoryIdToBigSum9 m31.QM31,
	rangeCheckInput [8]m31.QM31,
	addressInput [8]m31.QM31,
	idInput [8]m31.QM31,
	verifyXorSums [4]m31.QM31,
	blakeRoundSum38 m31.QM31,
	blakeRoundSum39 m31.QM31,
	tripleXorSums [8]m31.QM31,
	rangeCheckNew []m31.QM31,
	addressNew []m31.QM31,
	idNew []m31.QM31,
) []blakeCompressPair {
	pairs := []blakeCompressPair{
		{First: verifyInstructionSum, Second: memoryAddressToIdSum1},
		{First: memoryIdToBigSum2, Second: memoryAddressToIdSum3},
		{First: memoryIdToBigSum4, Second: memoryAddressToIdSum5},
		{First: memoryIdToBigSum6, Second: rangeCheckSum7},
		{First: memoryAddressToIdSum8, Second: memoryIdToBigSum9},
	}

	for idx := 0; idx < len(rangeCheckInput); idx += 2 {
		next := idx + 1
		pairs = append(pairs,
			blakeCompressPair{First: rangeCheckInput[idx], Second: addressInput[idx]},
			blakeCompressPair{First: idInput[idx], Second: rangeCheckInput[next]},
			blakeCompressPair{First: addressInput[next], Second: idInput[next]},
		)
	}

	pairs = append(pairs,
		blakeCompressPair{First: verifyXorSums[0], Second: verifyXorSums[1]},
		blakeCompressPair{First: verifyXorSums[2], Second: verifyXorSums[3]},
		blakeCompressPair{First: blakeRoundSum38, Second: blakeRoundSum39, SecondPositive: true},
	)

	for idx := 0; idx < len(tripleXorSums); idx += 2 {
		pairs = append(pairs, blakeCompressPair{First: tripleXorSums[idx], Second: tripleXorSums[idx+1]})
	}

	for idx := 0; idx < len(rangeCheckNew); idx += 2 {
		next := idx + 1
		pairs = append(pairs,
			blakeCompressPair{First: rangeCheckNew[idx], Second: addressNew[idx]},
			blakeCompressPair{First: idNew[idx], Second: rangeCheckNew[next]},
			blakeCompressPair{First: addressNew[next], Second: idNew[next]},
		)
	}

	return pairs
}

func blakeCompressLookupConstraints(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	interaction [][]m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	enabler m31.QM31,
	columnSizeInv m31.QM31,
	pairs []blakeCompressPair,
	opcodesSum72 m31.QM31,
	opcodesSum73 m31.QM31,
) m31.QM31 {
	if len(interaction) != blakeCompressInteractionColumns {
		panic("blake_compress_opcode expects 148 interaction columns")
	}
	if len(pairs) != 36 {
		panic("unexpected number of lookup pairs for blake_compress_opcode")
	}

	partials := make([]m31.QM31, len(pairs)+1)
	for i := range partials {
		base := i * 4
		values := [4]m31.QM31{}
		for j := 0; j < 4; j++ {
			col := interaction[base+j]
			if len(col) == 0 {
				panic("interaction column empty")
			}
			value := col[0]
			if base+j >= blakeCompressInteractionColumns-4 {
				if len(col) < 2 {
					panic("interaction history column requires two samples")
				}
				value = col[1]
			}
			values[j] = value
		}
		partials[i] = qm31.FromPartialEvals(values[0], values[1], values[2], values[3])
	}

	prevPartial := qm31.FromPartialEvals(
		interaction[blakeCompressInteractionColumns-4][0],
		interaction[blakeCompressInteractionColumns-3][0],
		interaction[blakeCompressInteractionColumns-2][0],
		interaction[blakeCompressInteractionColumns-1][0],
	)

	for idx, pair := range pairs {
		partial := partials[idx]
		if idx > 0 {
			partial = qm31.Sub(partial, partials[idx-1])
		}
		constraint := qm31.Mul(qm31.Mul(partial, pair.First), pair.Second)
		constraint = qm31.Sub(constraint, pair.First)
		if pair.SecondPositive {
			constraint = qm31.Add(constraint, pair.Second)
		} else {
			constraint = qm31.Sub(constraint, pair.Second)
		}
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	last := qm31.Sub(partials[len(partials)-1], partials[len(partials)-2])
	last = qm31.Sub(last, prevPartial)
	last = qm31.Add(last, qm31.Mul(claimedSum, columnSizeInv))
	constraint := qm31.Mul(qm31.Mul(last, opcodesSum72), opcodesSum73)
	constraint = qm31.Add(constraint, qm31.Mul(opcodesSum72, enabler))
	constraint = qm31.Sub(constraint, qm31.Mul(opcodesSum73, enabler))
	constraint = qm31.Mul(constraint, vanishEvalInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	return sum
}
