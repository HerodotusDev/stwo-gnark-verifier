package cairo_components

import (
	sub "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components/subroutines"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

const (
	MulModBuiltinTraceColumns       = 410
	MulModBuiltinInteractionColumns = 376
)

type MulModBuiltinClaim struct {
	LogSize                   frontend.Variable
	MulModBuiltinSegmentStart frontend.Variable
}

type MulModBuiltinInteractionClaim struct {
	ClaimedSum m31.QM31
}

type MulModBuiltinComponent struct {
	api  frontend.API
	qm31 *m31.QM31Chip

	logSize frontend.Variable

	memoryAddressToIdElems m31.InteractionElements
	memoryIdToBigElems     m31.InteractionElements
	rangeCheck12Elems      m31.InteractionElements
	rangeCheck3Elems       m31.InteractionElements
	rangeCheck18Elems      m31.InteractionElements

	segmentStart  m31.QM31
	claimedSum    m31.QM31
	columnSizeInv m31.QM31
	vanishEvalInv m31.QM31
}

func padSums(qm31 *m31.QM31Chip, values []m31.QM31, size int) []m31.QM31 {
	if len(values) >= size {
		return values
	}
	padded := make([]m31.QM31, size)
	copy(padded, values)
	zero := qm31.Zero()
	for i := len(values); i < size; i++ {
		padded[i] = zero
	}
	return padded
}

func NewMulModBuiltin(
	api frontend.API,
	qm31 *m31.QM31Chip,
	memoryAddressElements m31.InteractionElements,
	memoryIdElements m31.InteractionElements,
	rangeCheck12Elements m31.InteractionElements,
	rangeCheck3Elements m31.InteractionElements,
	rangeCheck18Elements m31.InteractionElements,
	vanishEvalInv m31.QM31,
	claim MulModBuiltinClaim,
	interactionClaim MulModBuiltinInteractionClaim,
) MulModBuiltinComponent {
	columnSize := computeColumnSize(api, claim.LogSize)
	columnSizeInv := qm31.Inverse(columnSize)

	segmentStart := m31.NewQM31FromM31(
		m31.NewM31Unchecked(claim.MulModBuiltinSegmentStart),
	)

	return MulModBuiltinComponent{
		api:                    api,
		qm31:                   qm31,
		logSize:                claim.LogSize,
		memoryAddressToIdElems: memoryAddressElements,
		memoryIdToBigElems:     memoryIdElements,
		rangeCheck12Elems:      rangeCheck12Elements,
		rangeCheck3Elems:       rangeCheck3Elements,
		rangeCheck18Elems:      rangeCheck18Elements,
		segmentStart:           segmentStart,
		claimedSum:             interactionClaim.ClaimedSum,
		columnSizeInv:          columnSizeInv,
		vanishEvalInv:          vanishEvalInv,
	}
}

func (c MulModBuiltinComponent) Evaluate(sum m31.QM31, traces *Traces, randomCoeff m31.QM31) m31.QM31 {
	traceSampledValues, interactionSampledValues := traces.Take(MulModBuiltinTraceColumns, MulModBuiltinInteractionColumns)

	trace := traceSampledValues

	seq := traces.Get(NewPreprocessedColumnSeq(c.api, c.logSize))

	get := func(idx int) m31.QM31 {
		return trace[idx][0]
	}

	readPoint := func(start int) sub.ModPoint {
		point := sub.ModPoint{ID: get(start)}
		for i := 0; i < 11; i++ {
			point.Limbs[i] = get(start + 1 + i)
		}
		return point
	}

	readPointer3 := func(start int) sub.Pointer3 {
		return sub.Pointer3{
			ID: get(start),
			Limbs: [3]m31.QM31{
				get(start + 1),
				get(start + 2),
				get(start + 3),
			},
		}
	}

	readOffset := func(start int) sub.OffsetEntry {
		return sub.OffsetEntry{
			ID:          get(start),
			MSB:         get(start + 1),
			MidLimbsSet: get(start + 2),
			Limbs: [3]m31.QM31{
				get(start + 3),
				get(start + 4),
				get(start + 5),
			},
		}
	}

	isInstanceZero := get(0)

	points := [4]sub.ModPoint{
		readPoint(1),
		readPoint(13),
		readPoint(25),
		readPoint(37),
	}

	valuesPtr := readPointer3(49)
	offsetsPtr := readPointer3(53)
	offsetsPtrPrev := readPointer3(57)
	nPtr := readPointer3(61)
	nPtrPrev := readPointer3(65)

	valuesPtrPrevID := get(69)

	prevPointIDs := [4]m31.QM31{
		get(70),
		get(71),
		get(72),
		get(73),
	}

	offsets := [3]sub.OffsetEntry{
		readOffset(74),
		readOffset(80),
		readOffset(86),
	}

	aPoints := [4]sub.ModPoint{
		readPoint(92),
		readPoint(104),
		readPoint(116),
		readPoint(128),
	}

	bPoints := [4]sub.ModPoint{
		readPoint(140),
		readPoint(152),
		readPoint(164),
		readPoint(176),
	}

	cPoints := [4]sub.ModPoint{
		readPoint(188),
		readPoint(200),
		readPoint(212),
		readPoint(224),
	}

	abMinusCLimbs := make([]m31.QM31, 32)
	for i := 0; i < 32; i++ {
		abMinusCLimbs[i] = get(236 + i)
	}

	limbBlocks := make([][10]m31.QM31, 8)
	for block := 0; block < 8; block++ {
		base := 268 + block*10
		for j := 0; j < 10; j++ {
			limbBlocks[block][j] = get(base + j)
		}
	}

	carries := make([]m31.QM31, 62)
	for i := range carries {
		carries[i] = get(348 + i)
	}

	modInput := sub.ModUtilsInputs{
		BaseAddress:        c.segmentStart,
		InstanceNum:        seq,
		IsInstanceZero:     isInstanceZero,
		Points:             points,
		PrevPointIDs:       prevPointIDs,
		ValuesPointer:      valuesPtr,
		OffsetsPointer:     offsetsPtr,
		OffsetsPointerPrev: offsetsPtrPrev,
		ValuesPointerPrev:  valuesPtrPrevID,
		NPointer:           nPtr,
		NPointerPrev:       nPtrPrev,
		Offsets:            offsets,
		A:                  aPoints,
		B:                  bPoints,
		C:                  cPoints,
	}

	res := sub.ModUtilsEvaluate(
		c.qm31,
		modInput,
		c.memoryAddressToIdElems,
		c.memoryIdToBigElems,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = res.Sum

	addressRaw := res.AddressLookupSums
	idRaw := res.IdToBigLookupSums
	addressIndices := []int{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 19, 20, 21, 22, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51}
	idIndices := []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52}
	addressSums := make([]m31.QM31, 52)
	for i, idx := range addressIndices {
		if i < len(addressRaw) {
			addressSums[idx] = addressRaw[i]
		}
	}
	idSums := make([]m31.QM31, 53)
	for i, idx := range idIndices {
		if i < len(idRaw) {
			idSums[idx] = idRaw[i]
		}
	}

	rangeCheck12Sums := make([]m31.QM31, 0, 32)
	for _, limb := range abMinusCLimbs {
		sum12, err := c.qm31.Combine(c.rangeCheck12Elems, []m31.QM31{limb})
		if err != nil {
			panic(err)
		}
		rangeCheck12Sums = append(rangeCheck12Sums, sum12)
	}

	combinePoints := func(a, b sub.ModPoint) []m31.QM31 {
		input := make([]m31.QM31, 22)
		copy(input[0:11], a.Limbs[:])
		copy(input[11:], b.Limbs[:])
		return input
	}

	modWordInputs := [][]m31.QM31{
		combinePoints(points[0], points[1]),
		combinePoints(points[2], points[3]),
		combinePoints(aPoints[0], aPoints[1]),
		combinePoints(aPoints[2], aPoints[3]),
		combinePoints(bPoints[0], bPoints[1]),
		combinePoints(bPoints[2], bPoints[3]),
		combinePoints(cPoints[0], cPoints[1]),
		combinePoints(cPoints[2], cPoints[3]),
	}

	modWordOutputs := [8][16]m31.QM31{}
	rangeCheck3Sums := make([]m31.QM31, 0, 40)

	for i := 0; i < 8; i++ {
		block := limbBlocks[i]
		result := sub.ModWordsTo12BitArrayEvaluate(
			c.qm31,
			modWordInputs[i],
			block[0],
			block[1],
			block[2],
			block[3],
			block[4],
			block[5],
			block[6],
			block[7],
			block[8],
			block[9],
			c.rangeCheck3Elems,
			sum,
			c.vanishEvalInv,
			randomCoeff,
		)
		sum = result.Sum
		modWordOutputs[i] = result.Outputs
		rangeCheck3Sums = append(rangeCheck3Sums, result.RangeCheckSums[:]...)
	}

	assemble := func(indices []int) []m31.QM31 {
		out := make([]m31.QM31, 0, 16*len(indices))
		for _, idx := range indices {
			out = append(out, modWordOutputs[idx][:]...)
		}
		return out
	}

	firstKaratsubaInput := assemble([]int{2, 3, 4, 5})
	karatsubaA := sub.DoubleKaratsubaN8LimbMaxBound4095Evaluate(
		c.qm31,
		firstKaratsubaInput,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = karatsubaA.Sum
	karatsubaOutA := karatsubaA.Output

	secondKaratsubaInput := make([]m31.QM31, 0, 64)
	secondKaratsubaInput = append(secondKaratsubaInput, abMinusCLimbs...)
	secondKaratsubaInput = append(secondKaratsubaInput, assemble([]int{0, 1})...)

	karatsubaB := sub.DoubleKaratsubaN8LimbMaxBound4095Evaluate(
		c.qm31,
		secondKaratsubaInput,
		sum,
		c.vanishEvalInv,
		randomCoeff,
	)
	sum = karatsubaB.Sum
	karatsubaOutB := karatsubaB.Output

	scale := qm31Const(524288)
	offset := qm31Const(131072)
	zero := c.qm31.Zero()

	rangeCheck18Sums := make([]m31.QM31, 0, 62)

	for i := 0; i < len(carries); i++ {
		var prevCarry m31.QM31
		if i == 0 {
			prevCarry = zero
		} else {
			prevCarry = carries[i-1]
		}

		var modWordTerm m31.QM31
		switch {
		case i < 16:
			modWordTerm = modWordOutputs[6][i]
		case i < 32:
			modWordTerm = modWordOutputs[7][i-16]
		default:
			modWordTerm = zero
		}

		karatsubaDiff := c.qm31.Sub(karatsubaOutA[i], karatsubaOutB[i])
		inner := c.qm31.Sub(prevCarry, modWordTerm)
		inner = c.qm31.Add(inner, karatsubaDiff)
		scaled := c.qm31.Mul(inner, scale)
		constraint := c.qm31.Sub(carries[i], scaled)
		constraint = c.qm31.Mul(constraint, c.vanishEvalInv)
		sum = accumulateConstraint(c.qm31, sum, randomCoeff, constraint)

		rcVal, err := c.qm31.Combine(c.rangeCheck18Elems, []m31.QM31{c.qm31.Add(carries[i], offset)})
		if err != nil {
			panic(err)
		}
		rangeCheck18Sums = append(rangeCheck18Sums, rcVal)
	}

	finalConstraint := c.qm31.Sub(
		c.qm31.Add(karatsubaOutA[62], carries[61]),
		karatsubaOutB[62],
	)
	finalConstraint = c.qm31.Mul(finalConstraint, c.vanishEvalInv)
	sum = accumulateConstraint(c.qm31, sum, randomCoeff, finalConstraint)

	rangeCheck12Sums = padSums(c.qm31, rangeCheck12Sums, 32)
	rangeCheck3Sums = padSums(c.qm31, rangeCheck3Sums, 40)
	rangeCheck18Sums = padSums(c.qm31, rangeCheck18Sums, 62)

	sum = mulModLookupConstraints(
		c.qm31,
		sum,
		randomCoeff,
		c.vanishEvalInv,
		c.claimedSum,
		c.columnSizeInv,
		interactionSampledValues,
		addressSums,
		idSums,
		rangeCheck12Sums,
		rangeCheck3Sums,
		rangeCheck18Sums,
	)

	return sum
}

func mulModLookupConstraints(
	qm31 *m31.QM31Chip,
	sum m31.QM31,
	randomCoeff m31.QM31,
	vanishEvalInv m31.QM31,
	claimedSum m31.QM31,
	columnSizeInv m31.QM31,
	interactionSampledValues [][]m31.QM31,
	addressSums []m31.QM31,
	idSums []m31.QM31,
	rangeCheck12Sums []m31.QM31,
	rangeCheck3Sums []m31.QM31,
	rangeCheck18Sums []m31.QM31,
) m31.QM31 {
	if len(interactionSampledValues) != 376 {
		panic("mul_mod_builtin interaction columns mismatch")
	}

	trace := make([]m31.QM31, 376)
	var prevTail [4]m31.QM31

	for i := 0; i < 376; i++ {
		col := interactionSampledValues[i]
		switch {
		case i >= 372:
			if len(col) != 2 {
				panic("expected two interaction values for tail columns")
			}
			prevTail[i-372] = col[0]
			trace[i] = col[1]
		case len(col) == 1:
			trace[i] = col[0]
		default:
			panic("interaction column missing value")
		}
	}

	partials := make([]m31.QM31, 94)
	for i := 0; i < 94; i++ {
		base := i * 4
		partials[i] = qm31.FromPartialEvals(
			trace[base],
			trace[base+1],
			trace[base+2],
			trace[base+3],
		)
	}

	prevLastPartial := qm31.FromPartialEvals(
		prevTail[0],
		prevTail[1],
		prevTail[2],
		prevTail[3],
	)

	one := qm31.One()

	{ // Lookup constraint 0
		term := partials[0]
		sumA := addressSums[0]
		sumB := idSums[1]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 1
		term := qm31.Sub(partials[1], partials[0])
		sumA := addressSums[2]
		sumB := idSums[3]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 2
		term := qm31.Sub(partials[2], partials[1])
		sumA := addressSums[4]
		sumB := idSums[5]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 3
		term := qm31.Sub(partials[3], partials[2])
		sumA := addressSums[6]
		sumB := idSums[7]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 4
		term := qm31.Sub(partials[4], partials[3])
		sumA := addressSums[8]
		sumB := idSums[9]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 5
		term := qm31.Sub(partials[5], partials[4])
		sumA := addressSums[10]
		sumB := idSums[11]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 6
		term := qm31.Sub(partials[6], partials[5])
		sumA := addressSums[12]
		sumB := idSums[13]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 7
		term := qm31.Sub(partials[7], partials[6])
		sumA := addressSums[14]
		sumB := idSums[15]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 8
		term := qm31.Sub(partials[8], partials[7])
		sumA := addressSums[16]
		sumB := idSums[17]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 9
		term := qm31.Sub(partials[9], partials[8])
		sumA := addressSums[18]
		sumB := addressSums[19]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 10
		term := qm31.Sub(partials[10], partials[9])
		sumA := addressSums[20]
		sumB := addressSums[21]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 11
		term := qm31.Sub(partials[11], partials[10])
		sumA := addressSums[22]
		sumB := addressSums[23]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 12
		term := qm31.Sub(partials[12], partials[11])
		sumA := idSums[24]
		sumB := addressSums[25]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 13
		term := qm31.Sub(partials[13], partials[12])
		sumA := idSums[26]
		sumB := addressSums[27]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 14
		term := qm31.Sub(partials[14], partials[13])
		sumA := idSums[28]
		sumB := addressSums[29]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 15
		term := qm31.Sub(partials[15], partials[14])
		sumA := idSums[30]
		sumB := addressSums[31]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 16
		term := qm31.Sub(partials[16], partials[15])
		sumA := idSums[32]
		sumB := addressSums[33]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 17
		term := qm31.Sub(partials[17], partials[16])
		sumA := idSums[34]
		sumB := addressSums[35]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 18
		term := qm31.Sub(partials[18], partials[17])
		sumA := idSums[36]
		sumB := addressSums[37]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 19
		term := qm31.Sub(partials[19], partials[18])
		sumA := idSums[38]
		sumB := addressSums[39]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 20
		term := qm31.Sub(partials[20], partials[19])
		sumA := idSums[40]
		sumB := addressSums[41]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 21
		term := qm31.Sub(partials[21], partials[20])
		sumA := idSums[42]
		sumB := addressSums[43]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 22
		term := qm31.Sub(partials[22], partials[21])
		sumA := idSums[44]
		sumB := addressSums[45]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 23
		term := qm31.Sub(partials[23], partials[22])
		sumA := idSums[46]
		sumB := addressSums[47]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 24
		term := qm31.Sub(partials[24], partials[23])
		sumA := idSums[48]
		sumB := addressSums[49]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 25
		term := qm31.Sub(partials[25], partials[24])
		sumA := idSums[50]
		sumB := addressSums[51]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 26
		term := qm31.Sub(partials[26], partials[25])
		sumA := idSums[52]
		sumB := rangeCheck12Sums[0]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 27
		term := qm31.Sub(partials[27], partials[26])
		sumA := rangeCheck12Sums[1]
		sumB := rangeCheck12Sums[2]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 28
		term := qm31.Sub(partials[28], partials[27])
		sumA := rangeCheck12Sums[3]
		sumB := rangeCheck12Sums[4]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 29
		term := qm31.Sub(partials[29], partials[28])
		sumA := rangeCheck12Sums[5]
		sumB := rangeCheck12Sums[6]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 30
		term := qm31.Sub(partials[30], partials[29])
		sumA := rangeCheck12Sums[7]
		sumB := rangeCheck12Sums[8]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 31
		term := qm31.Sub(partials[31], partials[30])
		sumA := rangeCheck12Sums[9]
		sumB := rangeCheck12Sums[10]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 32
		term := qm31.Sub(partials[32], partials[31])
		sumA := rangeCheck12Sums[11]
		sumB := rangeCheck12Sums[12]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 33
		term := qm31.Sub(partials[33], partials[32])
		sumA := rangeCheck12Sums[13]
		sumB := rangeCheck12Sums[14]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 34
		term := qm31.Sub(partials[34], partials[33])
		sumA := rangeCheck12Sums[15]
		sumB := rangeCheck12Sums[16]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 35
		term := qm31.Sub(partials[35], partials[34])
		sumA := rangeCheck12Sums[17]
		sumB := rangeCheck12Sums[18]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 36
		term := qm31.Sub(partials[36], partials[35])
		sumA := rangeCheck12Sums[19]
		sumB := rangeCheck12Sums[20]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 37
		term := qm31.Sub(partials[37], partials[36])
		sumA := rangeCheck12Sums[21]
		sumB := rangeCheck12Sums[22]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 38
		term := qm31.Sub(partials[38], partials[37])
		sumA := rangeCheck12Sums[23]
		sumB := rangeCheck12Sums[24]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 39
		term := qm31.Sub(partials[39], partials[38])
		sumA := rangeCheck12Sums[25]
		sumB := rangeCheck12Sums[26]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 40
		term := qm31.Sub(partials[40], partials[39])
		sumA := rangeCheck12Sums[27]
		sumB := rangeCheck12Sums[28]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 41
		term := qm31.Sub(partials[41], partials[40])
		sumA := rangeCheck12Sums[29]
		sumB := rangeCheck12Sums[30]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 42
		term := qm31.Sub(partials[42], partials[41])
		sumA := rangeCheck12Sums[31]
		sumB := rangeCheck3Sums[0]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 43
		term := qm31.Sub(partials[43], partials[42])
		sumA := rangeCheck3Sums[1]
		sumB := rangeCheck3Sums[2]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 44
		term := qm31.Sub(partials[44], partials[43])
		sumA := rangeCheck3Sums[3]
		sumB := rangeCheck3Sums[4]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 45
		term := qm31.Sub(partials[45], partials[44])
		sumA := rangeCheck3Sums[5]
		sumB := rangeCheck3Sums[6]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 46
		term := qm31.Sub(partials[46], partials[45])
		sumA := rangeCheck3Sums[7]
		sumB := rangeCheck3Sums[8]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 47
		term := qm31.Sub(partials[47], partials[46])
		sumA := rangeCheck3Sums[9]
		sumB := rangeCheck3Sums[10]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 48
		term := qm31.Sub(partials[48], partials[47])
		sumA := rangeCheck3Sums[11]
		sumB := rangeCheck3Sums[12]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 49
		term := qm31.Sub(partials[49], partials[48])
		sumA := rangeCheck3Sums[13]
		sumB := rangeCheck3Sums[14]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 50
		term := qm31.Sub(partials[50], partials[49])
		sumA := rangeCheck3Sums[15]
		sumB := rangeCheck3Sums[16]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 51
		term := qm31.Sub(partials[51], partials[50])
		sumA := rangeCheck3Sums[17]
		sumB := rangeCheck3Sums[18]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 52
		term := qm31.Sub(partials[52], partials[51])
		sumA := rangeCheck3Sums[19]
		sumB := rangeCheck3Sums[20]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 53
		term := qm31.Sub(partials[53], partials[52])
		sumA := rangeCheck3Sums[21]
		sumB := rangeCheck3Sums[22]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 54
		term := qm31.Sub(partials[54], partials[53])
		sumA := rangeCheck3Sums[23]
		sumB := rangeCheck3Sums[24]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 55
		term := qm31.Sub(partials[55], partials[54])
		sumA := rangeCheck3Sums[25]
		sumB := rangeCheck3Sums[26]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 56
		term := qm31.Sub(partials[56], partials[55])
		sumA := rangeCheck3Sums[27]
		sumB := rangeCheck3Sums[28]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 57
		term := qm31.Sub(partials[57], partials[56])
		sumA := rangeCheck3Sums[29]
		sumB := rangeCheck3Sums[30]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 58
		term := qm31.Sub(partials[58], partials[57])
		sumA := rangeCheck3Sums[31]
		sumB := rangeCheck3Sums[32]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 59
		term := qm31.Sub(partials[59], partials[58])
		sumA := rangeCheck3Sums[33]
		sumB := rangeCheck3Sums[34]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 60
		term := qm31.Sub(partials[60], partials[59])
		sumA := rangeCheck3Sums[35]
		sumB := rangeCheck3Sums[36]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 61
		term := qm31.Sub(partials[61], partials[60])
		sumA := rangeCheck3Sums[37]
		sumB := rangeCheck3Sums[38]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 62
		term := qm31.Sub(partials[62], partials[61])
		sumA := rangeCheck3Sums[39]
		sumB := rangeCheck18Sums[0]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 63
		term := qm31.Sub(partials[63], partials[62])
		sumA := rangeCheck18Sums[1]
		sumB := rangeCheck18Sums[2]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 64
		term := qm31.Sub(partials[64], partials[63])
		sumA := rangeCheck18Sums[3]
		sumB := rangeCheck18Sums[4]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 65
		term := qm31.Sub(partials[65], partials[64])
		sumA := rangeCheck18Sums[5]
		sumB := rangeCheck18Sums[6]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 66
		term := qm31.Sub(partials[66], partials[65])
		sumA := rangeCheck18Sums[7]
		sumB := rangeCheck18Sums[8]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 67
		term := qm31.Sub(partials[67], partials[66])
		sumA := rangeCheck18Sums[9]
		sumB := rangeCheck18Sums[10]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 68
		term := qm31.Sub(partials[68], partials[67])
		sumA := rangeCheck18Sums[11]
		sumB := rangeCheck18Sums[12]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 69
		term := qm31.Sub(partials[69], partials[68])
		sumA := rangeCheck18Sums[13]
		sumB := rangeCheck18Sums[14]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 70
		term := qm31.Sub(partials[70], partials[69])
		sumA := rangeCheck18Sums[15]
		sumB := rangeCheck18Sums[16]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 71
		term := qm31.Sub(partials[71], partials[70])
		sumA := rangeCheck18Sums[17]
		sumB := rangeCheck18Sums[18]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 72
		term := qm31.Sub(partials[72], partials[71])
		sumA := rangeCheck18Sums[19]
		sumB := rangeCheck18Sums[20]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 73
		term := qm31.Sub(partials[73], partials[72])
		sumA := rangeCheck18Sums[21]
		sumB := rangeCheck18Sums[22]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 74
		term := qm31.Sub(partials[74], partials[73])
		sumA := rangeCheck18Sums[23]
		sumB := rangeCheck18Sums[24]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 75
		term := qm31.Sub(partials[75], partials[74])
		sumA := rangeCheck18Sums[25]
		sumB := rangeCheck18Sums[26]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 76
		term := qm31.Sub(partials[76], partials[75])
		sumA := rangeCheck18Sums[27]
		sumB := rangeCheck18Sums[28]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 77
		term := qm31.Sub(partials[77], partials[76])
		sumA := rangeCheck18Sums[29]
		sumB := rangeCheck18Sums[30]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 78
		term := qm31.Sub(partials[78], partials[77])
		sumA := rangeCheck18Sums[31]
		sumB := rangeCheck18Sums[32]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 79
		term := qm31.Sub(partials[79], partials[78])
		sumA := rangeCheck18Sums[33]
		sumB := rangeCheck18Sums[34]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 80
		term := qm31.Sub(partials[80], partials[79])
		sumA := rangeCheck18Sums[35]
		sumB := rangeCheck18Sums[36]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 81
		term := qm31.Sub(partials[81], partials[80])
		sumA := rangeCheck18Sums[37]
		sumB := rangeCheck18Sums[38]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 82
		term := qm31.Sub(partials[82], partials[81])
		sumA := rangeCheck18Sums[39]
		sumB := rangeCheck18Sums[40]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 83
		term := qm31.Sub(partials[83], partials[82])
		sumA := rangeCheck18Sums[41]
		sumB := rangeCheck18Sums[42]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 84
		term := qm31.Sub(partials[84], partials[83])
		sumA := rangeCheck18Sums[43]
		sumB := rangeCheck18Sums[44]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 85
		term := qm31.Sub(partials[85], partials[84])
		sumA := rangeCheck18Sums[45]
		sumB := rangeCheck18Sums[46]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 86
		term := qm31.Sub(partials[86], partials[85])
		sumA := rangeCheck18Sums[47]
		sumB := rangeCheck18Sums[48]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 87
		term := qm31.Sub(partials[87], partials[86])
		sumA := rangeCheck18Sums[49]
		sumB := rangeCheck18Sums[50]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 88
		term := qm31.Sub(partials[88], partials[87])
		sumA := rangeCheck18Sums[51]
		sumB := rangeCheck18Sums[52]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 89
		term := qm31.Sub(partials[89], partials[88])
		sumA := rangeCheck18Sums[53]
		sumB := rangeCheck18Sums[54]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 90
		term := qm31.Sub(partials[90], partials[89])
		sumA := rangeCheck18Sums[55]
		sumB := rangeCheck18Sums[56]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 91
		term := qm31.Sub(partials[91], partials[90])
		sumA := rangeCheck18Sums[57]
		sumB := rangeCheck18Sums[58]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 92
		term := qm31.Sub(partials[92], partials[91])
		sumA := rangeCheck18Sums[59]
		sumB := rangeCheck18Sums[60]
		constraint := qm31.Mul(term, qm31.Mul(sumA, sumB))
		constraint = qm31.Sub(constraint, qm31.Add(sumA, sumB))
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	{ // Lookup constraint 93
		term := qm31.Sub(partials[93], partials[92])
		term = qm31.Sub(term, prevLastPartial)
		term = qm31.Add(term, qm31.Mul(claimedSum, columnSizeInv))
		sumA := rangeCheck18Sums[61]
		constraint := qm31.Mul(term, sumA)
		constraint = qm31.Sub(constraint, one)
		constraint = qm31.Mul(constraint, vanishEvalInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	return sum
}
