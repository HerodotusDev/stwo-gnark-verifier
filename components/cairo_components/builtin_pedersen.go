package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	pedersenBuiltinTraceColumns       = 351
	pedersenBuiltinInteractionColumns = 40
)

var pedersenPartialEcMulSum10Constants = []uint64{
	435, 50, 508, 83, 221, 281, 377, 383, 212, 264, 301, 458, 130, 102,
	385, 269, 145, 276, 483, 226, 422, 253, 308, 125, 472, 301, 227, 27,
	92, 321, 252, 259, 252, 413, 228, 31, 24, 118, 301, 202, 15, 464,
	334, 212, 471, 461, 419, 354, 96, 213, 319, 191, 251, 330, 15, 222,
}

type PedersenBuiltinClaim struct {
	LogSize                     uints.U8
	PedersenBuiltinSegmentStart uint32
}

type PedersenBuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type PedersenBuiltinComponent struct {
	qm31 *m31.QM31Chip

	rangeCheck54Elements      m31.InteractionElements
	memoryAddressToIdElements m31.InteractionElements
	memoryIdToBigElements     m31.InteractionElements
	rangeCheck8Elements       m31.InteractionElements
	partialEcMulElements      m31.InteractionElements

	claimedSum    m31.QM31
	segmentStart  m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
	logSize       uints.U8
}

func NewPedersenBuiltin(
	api frontend.API,
	qm31Chip *m31.QM31Chip,
	rangeCheck54Elements m31.InteractionElements,
	memoryAddressToIdElements m31.InteractionElements,
	memoryIdToBigElements m31.InteractionElements,
	rangeCheck8Elements m31.InteractionElements,
	partialEcMulElements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim PedersenBuiltinClaim,
	interactionClaim PedersenBuiltinInteractionClaim,
) *PedersenBuiltinComponent {
	columnSize := computeColumnSize(api, claim.LogSize)

	return &PedersenBuiltinComponent{
		qm31:                      qm31Chip,
		rangeCheck54Elements:      rangeCheck54Elements,
		memoryAddressToIdElements: memoryAddressToIdElements,
		memoryIdToBigElements:     memoryIdToBigElements,
		rangeCheck8Elements:       rangeCheck8Elements,
		partialEcMulElements:      partialEcMulElements,
		claimedSum:                interactionClaim.ClaimedSum,
		segmentStart:              m31.NewQM31FromM31(m31.NewM31Unchecked(uint64(claim.PedersenBuiltinSegmentStart))),
		columnSizeInv:             qm31Chip.Inverse(columnSize),
		vanishEvalInv:             vanishEvalInv,
		logSize:                   claim.LogSize,
	}
}

func (c *PedersenBuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 { // FORMAT
	traceSampledValues, interactionSampledValues := traces.Take(pedersenBuiltinTraceColumns, pedersenBuiltinInteractionColumns)

	trace := traceSampledValues

	// ╔══════════════════════════════════╗
	// ║        Preprocessed Trace        ║
	// ╚══════════════════════════════════╝
	seqColumn := NewPreprocessedColumnSeq(c.logSize)
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

	var valueA [27]m31.QM31
	for i := range valueA {
		valueA[i] = nextTrace()
	}
	msLowA := nextTrace()
	msHighA := nextTrace()
	pedersenAID := nextTrace()

	var valueB [27]m31.QM31
	for i := range valueB {
		valueB[i] = nextTrace()
	}
	msLowB := nextTrace()
	msHighB := nextTrace()
	pedersenBID := nextTrace()

	msIsMaxA := nextTrace()
	msAndMidMaxA := nextTrace()
	rcInputA := nextTrace()
	msIsMaxB := nextTrace()
	msAndMidMaxB := nextTrace()
	rcInputB := nextTrace()

	const partialOutputLen = 71
	var partialOutputs [4][partialOutputLen]m31.QM31
	for block := 0; block < len(partialOutputs); block++ {
		for i := 0; i < partialOutputLen; i++ {
			partialOutputs[block][i] = nextTrace()
		}
	}

	pedersenResultID := nextTrace()

	if cursor != pedersenBuiltinTraceColumns {
		panic("unexpected trace column count")
	}

	qm31 := c.qm31
	zero := qm31.Zero()

	addConst := func(value m31.QM31, constant uint64) m31.QM31 {
		return qm31.Add(value, qm31Const(constant))
	}
	combine := func(elements m31.InteractionElements, values []m31.QM31) m31.QM31 {
		result, err := qm31.Combine(elements, values)
		if err != nil {
			panic(err)
		}
		return result
	}

	baseAddress := qm31.Add(c.segmentStart, qm31.Mul(seq, qm31Const(3)))
	addressNext := addConst(baseAddress, 1)

	readA := sub.ReadSplitEvaluate(
		qm31,
		baseAddress,
		valueA[:],
		msLowA,
		msHighA,
		pedersenAID,
		c.rangeCheck54Elements,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = readA.Sum
	rangeCheck54Sum0 := readA.RangeCheckSum
	memoryAddressToIdSum1 := readA.AddressLookupSum
	memoryIdToBigSum2 := readA.IdToBigLookupSum

	readB := sub.ReadSplitEvaluate(
		qm31,
		addressNext,
		valueB[:],
		msLowB,
		msHighB,
		pedersenBID,
		c.rangeCheck54Elements,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = readB.Sum
	rangeCheck54Sum3 := readB.RangeCheckSum
	memoryAddressToIdSum4 := readB.AddressLookupSum
	memoryIdToBigSum5 := readB.IdToBigLookupSum

	limbsA := make([]m31.QM31, 28)
	copy(limbsA, valueA[:])
	limbsA[27] = readA.MostSignificantRaw
	verifyA := sub.VerifyReduced252Evaluate(
		qm31,
		limbsA,
		msIsMaxA,
		msAndMidMaxA,
		rcInputA,
		c.rangeCheck8Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = verifyA.Sum
	rangeCheck8Sum6 := verifyA.RangeCheckSums[0]
	rangeCheck8Sum7 := verifyA.RangeCheckSums[1]

	limbsB := make([]m31.QM31, 28)
	copy(limbsB, valueB[:])
	limbsB[27] = readB.MostSignificantRaw
	verifyB := sub.VerifyReduced252Evaluate(
		qm31,
		limbsB,
		msIsMaxB,
		msAndMidMaxB,
		rcInputB,
		c.rangeCheck8Elements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = verifyB.Sum
	rangeCheck8Sum8 := verifyB.RangeCheckSums[0]
	rangeCheck8Sum9 := verifyB.RangeCheckSums[1]

	chainBase := qm31.Mul(seq, qm31Const(4))
	chainPlus1 := qm31.Add(chainBase, qm31Const(1))
	chainPlus2 := qm31.Add(chainPlus1, qm31Const(1))
	chainPlus3 := qm31.Add(chainPlus2, qm31Const(1))

	scale512 := qm31Const(512)
	values := make([]m31.QM31, 0, 73)

	values = append(values, chainBase, zero, zero)
	for i := 0; i < 13; i++ {
		pair := qm31.Add(valueA[2*i], qm31.Mul(valueA[2*i+1], scale512))
		values = append(values, pair)
	}
	values = append(values, qm31.Add(valueA[26], qm31.Mul(msLowA, scale512)))
	for _, constant := range pedersenPartialEcMulSum10Constants {
		values = append(values, qm31Const(constant))
	}
	partialEcMulSum10 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainBase, qm31Const(14))
	values = append(values, partialOutputs[0][:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_11 length mismatch")
	}
	partialEcMulSum11 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus1, zero, qm31Const(3670016), msHighA)
	for i := 0; i < 13; i++ {
		values = append(values, zero)
	}
	values = append(values, partialOutputs[0][15:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_12 length mismatch")
	}
	partialEcMulSum12 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus1, qm31Const(1))
	values = append(values, partialOutputs[1][:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_13 length mismatch")
	}
	partialEcMulSum13 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus2, zero, qm31Const(3670032))
	for i := 0; i < 13; i++ {
		pair := qm31.Add(valueB[2*i], qm31.Mul(valueB[2*i+1], scale512))
		values = append(values, pair)
	}
	values = append(values, qm31.Add(valueB[26], qm31.Mul(msLowB, scale512)))
	values = append(values, partialOutputs[1][15:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_14 length mismatch")
	}
	partialEcMulSum14 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus2, qm31Const(14))
	values = append(values, partialOutputs[2][:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_15 length mismatch")
	}
	partialEcMulSum15 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus3, zero, qm31Const(7340048), msHighB)
	for i := 0; i < 13; i++ {
		values = append(values, zero)
	}
	values = append(values, partialOutputs[2][15:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_16 length mismatch")
	}
	partialEcMulSum16 := combine(c.partialEcMulElements, values)

	values = values[:0]
	values = append(values, chainPlus3, qm31Const(1))
	values = append(values, partialOutputs[3][:]...)
	if len(values) != 73 {
		panic("partial_ec_mul_sum_17 length mismatch")
	}
	partialEcMulSum17 := combine(c.partialEcMulElements, values)

	memInputs := make([]m31.QM31, 28)
	for i := 0; i < len(memInputs); i++ {
		memInputs[i] = partialOutputs[3][15+i]
	}
	memRes := sub.MemVerifyEvaluate(
		qm31,
		qm31.Add(baseAddress, qm31Const(2)),
		memInputs,
		pedersenResultID,
		c.memoryAddressToIdElements,
		c.memoryIdToBigElements,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = memRes.Sum
	memoryAddressToIdSum18 := memRes.AddressLookupSum
	memoryIdToBigSum19 := memRes.IdToBigLookupSum

	// ╔══════════════════════════════════╗
	// ║         Interaction Trace        ║
	// ╚══════════════════════════════════╝
	// Use InteractionTrace.Partial to build current/previous partials.
	var partials [10]m31.QM31
	for i := 0; i < 9; i++ {
		partials[i] = interactionSampledValues.Partial(c.qm31, i*4, 0)
	}
	// Last block (start=36) has previous/current samples.
	partials[9] = interactionSampledValues.Partial(c.qm31, 36, 1)
	partialNeg1 := interactionSampledValues.Partial(c.qm31, 36, 0)

	apply := func(constraint m31.QM31) {
		constraint = qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	constraint := qm31.Mul(partials[0], rangeCheck54Sum0)
	constraint = qm31.Mul(constraint, memoryAddressToIdSum1)
	constraint = qm31.Sub(constraint, rangeCheck54Sum0)
	constraint = qm31.Sub(constraint, memoryAddressToIdSum1)
	apply(constraint)

	diff := qm31.Sub(partials[1], partials[0])
	diff = qm31.Mul(diff, memoryIdToBigSum2)
	diff = qm31.Mul(diff, rangeCheck54Sum3)
	diff = qm31.Sub(diff, memoryIdToBigSum2)
	diff = qm31.Sub(diff, rangeCheck54Sum3)
	apply(diff)

	diff = qm31.Sub(partials[2], partials[1])
	diff = qm31.Mul(diff, memoryAddressToIdSum4)
	diff = qm31.Mul(diff, memoryIdToBigSum5)
	diff = qm31.Sub(diff, memoryAddressToIdSum4)
	diff = qm31.Sub(diff, memoryIdToBigSum5)
	apply(diff)

	diff = qm31.Sub(partials[3], partials[2])
	diff = qm31.Mul(diff, rangeCheck8Sum6)
	diff = qm31.Mul(diff, rangeCheck8Sum7)
	diff = qm31.Sub(diff, rangeCheck8Sum6)
	diff = qm31.Sub(diff, rangeCheck8Sum7)
	apply(diff)

	diff = qm31.Sub(partials[4], partials[3])
	diff = qm31.Mul(diff, rangeCheck8Sum8)
	diff = qm31.Mul(diff, rangeCheck8Sum9)
	diff = qm31.Sub(diff, rangeCheck8Sum8)
	diff = qm31.Sub(diff, rangeCheck8Sum9)
	apply(diff)

	diff = qm31.Sub(partials[5], partials[4])
	diff = qm31.Mul(diff, partialEcMulSum10)
	diff = qm31.Mul(diff, partialEcMulSum11)
	diff = qm31.Sub(diff, partialEcMulSum10)
	diff = qm31.Add(diff, partialEcMulSum11)
	apply(diff)

	diff = qm31.Sub(partials[6], partials[5])
	diff = qm31.Mul(diff, partialEcMulSum12)
	diff = qm31.Mul(diff, partialEcMulSum13)
	diff = qm31.Sub(diff, partialEcMulSum12)
	diff = qm31.Add(diff, partialEcMulSum13)
	apply(diff)

	diff = qm31.Sub(partials[7], partials[6])
	diff = qm31.Mul(diff, partialEcMulSum14)
	diff = qm31.Mul(diff, partialEcMulSum15)
	diff = qm31.Sub(diff, partialEcMulSum14)
	diff = qm31.Add(diff, partialEcMulSum15)
	apply(diff)

	diff = qm31.Sub(partials[8], partials[7])
	diff = qm31.Mul(diff, partialEcMulSum16)
	diff = qm31.Mul(diff, partialEcMulSum17)
	diff = qm31.Sub(diff, partialEcMulSum16)
	diff = qm31.Add(diff, partialEcMulSum17)
	apply(diff)

	claimedTerm := qm31.Mul(c.claimedSum, c.columnSizeInv)
	diff = qm31.Sub(partials[9], partials[8])
	diff = qm31.Sub(diff, partialNeg1)
	diff = qm31.Add(diff, claimedTerm)
	diff = qm31.Mul(diff, memoryAddressToIdSum18)
	diff = qm31.Mul(diff, memoryIdToBigSum19)
	diff = qm31.Sub(diff, memoryAddressToIdSum18)
	diff = qm31.Sub(diff, memoryIdToBigSum19)
	apply(diff)

	return sum
}
