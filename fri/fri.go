package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type FriVerifier struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U32]
	m31Chip    *m31.M31Chip
	qm31Chip   *m31.QM31Chip
	circleChip *circle.CircleChip

	friConfig           FriConfig
	FirstLayerVerifier  FriFirstLayerVerifier
	InnerLayerVerifiers []FriInnerLayerVerifier
	LastLayerPoly       circle.LinePoly
}

func NewFriVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], channelChip *channel.Channel, qm31Chip *m31.QM31Chip, circleChip *circle.CircleChip, friConfig FriConfig, friProof variables.FriProof, bounds []frontend.Variable) *FriVerifier {
	// First layer commitment
	channelChip.MixRootBytes(friProof.FirstLayerProof.Commitment[:])

	// First layer verifier
	columncommitmentDomains := make([]circle.CircleDomain, 0)
	for _, bound := range bounds {
		columncommitmentDomains = append(columncommitmentDomains, circle.NewCanonicCoset(circleChip, api.Add(bound, friConfig.LogBlowupFactor)).CircleDomain())
	}
	firstLayerVerifier := FriFirstLayerVerifier{
		columnBounds:            bounds,
		columnCommitmentDomains: columncommitmentDomains,
		proof:                   friProof.FirstLayerProof,
		foldingAlpha:            channelChip.DrawFelt(),
	}

	// Inner layer verifiers
	layerBound := api.Sub(bounds[0], 1) // first bound folded
	layerBoundBlewup := api.Add(layerBound, friConfig.LogBlowupFactor)
	layerDomain := circle.NewLineDomain(circle.NewCoset(circleChip, circle.SubgroupGenerator(circleChip, api.Add(layerBoundBlewup, 2)), layerBoundBlewup))

	innerLayerVerifiers := make([]FriInnerLayerVerifier, len(friProof.InnerLayerProofs))
	for i, innerLayerProof := range friProof.InnerLayerProofs {
		channelChip.MixRootBytes(innerLayerProof.Commitment[:])
		innerLayerVerifiers[i] = FriInnerLayerVerifier{
			degreeBound:  layerBound,
			domain:       layerDomain,
			foldingAlpha: channelChip.DrawFelt(),
			layerIndex:   i,
			proof:        innerLayerProof,
		}

		// fold layer
		layerBound = api.Sub(layerBound, 1)
		layerDomain = layerDomain.Double()
	}

	// Mix in the last layer
	channelChip.MixFelts(friProof.LastLayerPoly.Coeffs)

	return &FriVerifier{
		api:                 api,
		uapi:                uapi,
		m31Chip:             qm31Chip.M31Chip(),
		qm31Chip:            qm31Chip,
		circleChip:          circleChip,
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
	}
}

// func (f *FriVerifier) Verify(queries [][]int, evaluations [][]m31.QM31) {
// 	firstLayerEvaluations := f.verifyFirstLayer(queries, evaluations)
// 	lastEvaluations := f.verifyInnerLayers(queries, firstLayerEvaluations)
// 	f.verifyLastLayer(lastEvaluations)
// }

// ╔══════════════════════════════════╗
// ║           FRI Quotients          ║
// ╚══════════════════════════════════╝

// type SampleData struct {
// 	point            circle.Point
// 	columnIndex      int
// 	value            m31.QM31
// 	lineCoefficients [3]m31.QM31
// }

// FriQuotientEvaluations evaluates the FRI quotients returning quotient evaluations for each log size and for each query
//   - columnLogSizes: log sizes of each column (blew up) for each tree
//   - sampledValues: sampled values for each column for each tree
//   - sampledPoints: sampled points (or "mask points") for each tree, the shape should exactly match the shape of sampledValues
//   - queries: query positions per log size
//   - queriedValues: column values queried for each tree ordered by log size then by query position (same as merkle decommitments)
//   - randomCoeff: random coefficient used to batch lines with the same sample point and quotients with the same log size
// func (f *FriVerifier) FriQuotientEvaluations(
// 	columnLogSizes [][]frontend.Variable,
// 	sampledValues [][][]m31.QM31,
// 	sampledPoints cairo_components.TreeMaskPoints,
// 	queries [][]int,
// 	queriedValues [][]m31.M31,
// 	randomCoeff m31.QM31,
// ) [][]m31.QM31 {
// 	// compute number of columns per log size per tree and compute max and min log sizes
// 	nColumnsPerLogSize := make([]map[int]int, cairo_components.N_TREES)
// 	maxLogSize := 0
// 	minLogSize := 32
// 	for treeIndex, treeColumnLogSizes := range columnLogSizes {
// 		nColumnsPerLogSize[treeIndex] = make(map[int]int)
// 		for _, logSize := range treeColumnLogSizes {
// 			nColumnsPerLogSize[treeIndex][int(logSize)]++
// 			if int(logSize) > maxLogSize {
// 				maxLogSize = int(logSize)
// 			}
// 			if int(logSize) < minLogSize {
// 				minLogSize = int(logSize)
// 			}
// 		}
// 	}

// 	// compute the max number of columns per log size overall
// 	maxNColumnsPerLogSize := 0
// 	for i := 0; i < 32; i++ {
// 		nColumns := 0
// 		for treeIndex := range cairo_components.N_TREES {
// 			nColumns += nColumnsPerLogSize[treeIndex][i]
// 		}
// 		if nColumns > maxNColumnsPerLogSize {
// 			maxNColumnsPerLogSize = nColumns
// 		}
// 	}

// 	// precompute randomCoeff powers
// 	randomCoeffPowers := make([]m31.QM31, maxNColumnsPerLogSize+1)
// 	randomCoeffPowers[0] = f.qm31Chip.One()
// 	for i := 1; i < maxNColumnsPerLogSize+1; i++ {
// 		randomCoeffPowers[i] = f.qm31Chip.Mul(randomCoeffPowers[i-1], randomCoeff)
// 	}

// 	// Merge sampled values and sampled points into samples (table of SampleData)
// 	// This is not a map because order matters when iterating
// 	// dim-1 (log size): samplesByLogSize groups all columns from all trees per log size
// 	// dim-2 (point): samplesByLogSize groups sampled values of columns of same log size by sample point
// 	// dim-3 (samples)
// 	samplesByLogSize := make([][][]SampleData, 32)
// 	for i := range samplesByLogSize {
// 		samplesByLogSize[i] = make([][]SampleData, 0)
// 	}
// 	columnIndexes := make([]int, 32)
// 	for treeIndex, tree := range sampledPoints {
// 		for columnIndex, column := range tree {
// 			logSize := columnLogSizes[treeIndex][columnIndex]
// 			for pointIndex, point := range column {
// 				for range len(column) - len(samplesByLogSize[logSize]) {
// 					samplesByLogSize[logSize] = append(samplesByLogSize[logSize], make([]SampleData, 0))
// 				}
// 				// when 2 points are sampled the order is [pointNegOne, point], this contrasts with the single-sampled points order ([point])
// 				// using a map would require some encoding/decoding of the points which are just handles and not usable as keys
// 				alpha := randomCoeffPowers[len(samplesByLogSize[logSize][len(column)-pointIndex-1])+1]
// 				sampledValue := sampledValues[treeIndex][columnIndex][pointIndex]
// 				lineCoefficients := GetLineCoefficients(f.qm31Chip, point, sampledValue, alpha)
// 				samplesByLogSize[logSize][len(column)-pointIndex-1] = append(samplesByLogSize[logSize][len(column)-pointIndex-1], SampleData{
// 					point:            point,
// 					columnIndex:      columnIndexes[logSize],
// 					value:            sampledValue,
// 					lineCoefficients: lineCoefficients,
// 				})
// 			}
// 			columnIndexes[logSize]++
// 		}
// 	}

// 	// evaluate the quotient at each query position for each log size
// 	quotientEvaluations := make([][]m31.QM31, 0)
// 	queriedValuesPointer := make([]int, cairo_components.N_TREES)
// 	for logSize := maxLogSize; logSize >= minLogSize; logSize-- {
// 		samples := samplesByLogSize[logSize]
// 		circleDomain := circle.NewCanonicCoset(f.circleChip, uint32(logSize)).CircleDomain()
// 		layerQuotientEvaluations := make([]m31.QM31, 0)
// 		for _, queryPosition := range queries[logSize] {
// 			bitReversedQueryPosition := reverseBitIndex(f.api, f.uapi, uint32(queryPosition), logSize)
// 			domainPoint := circleDomain.At(bitReversedQueryPosition)
// 			// get flattened (over trees) queried values at query position
// 			valuesAtQueryPosition := make([]m31.M31, 0)
// 			for treeIndex := range cairo_components.N_TREES {
// 				nColumns := nColumnsPerLogSize[treeIndex][logSize]
// 				valuesAtQueryPosition = append(valuesAtQueryPosition, queriedValues[treeIndex][queriedValuesPointer[treeIndex]:queriedValuesPointer[treeIndex]+nColumns]...)
// 				queriedValuesPointer[treeIndex] += nColumns
// 			}
// 			// evaluate the quotient at the query position for the given log size
// 			layerQuotientEvaluations = append(layerQuotientEvaluations, f.quotientEvaluation(samples, valuesAtQueryPosition, domainPoint, randomCoeffPowers))
// 		}
// 		quotientEvaluations = append(quotientEvaluations, layerQuotientEvaluations)
// 	}

// 	return quotientEvaluations
// }

// func GetLineCoefficients(qm31Chip *m31.QM31Chip, samplePoint circle.Point, sampledValue m31.QM31, alpha m31.QM31) [3]m31.QM31 {
// 	a := qm31Chip.Sub(qm31Chip.ComplexConjugate(sampledValue), sampledValue)
// 	c := qm31Chip.Sub(qm31Chip.ComplexConjugate(samplePoint.Y), samplePoint.Y)
// 	b := qm31Chip.Sub(qm31Chip.Mul(sampledValue, c), qm31Chip.Mul(a, samplePoint.Y))
// 	return [3]m31.QM31{qm31Chip.Mul(alpha, a), qm31Chip.Mul(alpha, b), qm31Chip.Mul(alpha, c)}
// }

// func (f *FriVerifier) quotientEvaluation(samples [][]SampleData, valuesAtQueryPosition []m31.M31, domainPoint circle.BasePoint, randomCoeffPowers []m31.QM31) m31.QM31 {
// 	quotientEvaluation := f.qm31Chip.Zero()
// 	// iterate through sampling points relative to the current log size (at most two points per log size with current stwo-cairo)
// 	for _, samplesData := range samples {
// 		point := samplesData[0].point
// 		// compute the denominator (CM31)
// 		samplePointRX := m31.CM31{Real: point.X.AReal, Imag: point.X.AImag}
// 		samplePointRY := m31.CM31{Real: point.Y.AReal, Imag: point.Y.AImag}
// 		samplePointIX := m31.CM31{Real: point.X.BReal, Imag: point.X.BImag}
// 		samplePointIY := m31.CM31{Real: point.Y.BReal, Imag: point.Y.BImag}
// 		denominator := f.qm31Chip.CmSub(
// 			f.qm31Chip.CmMul(
// 				f.qm31Chip.CmSubM31(
// 					samplePointRX,
// 					domainPoint.X,
// 				),
// 				samplePointIY,
// 			),
// 			f.qm31Chip.CmMul(
// 				f.qm31Chip.CmSubM31(
// 					samplePointRY,
// 					domainPoint.Y,
// 				),
// 				samplePointIX,
// 			),
// 		)
// 		// inverse the denominator (CM31)
// 		denominatorInverse := f.qm31Chip.CM31Inverse(denominator)
// 		// compute the numerator for the sample point (batching)
// 		numerator := f.qm31Chip.Zero()
// 		for _, sampleData := range samplesData {
// 			a := sampleData.lineCoefficients[0]
// 			b := sampleData.lineCoefficients[1]
// 			c := sampleData.lineCoefficients[2]
// 			value := f.qm31Chip.MulM31(c, valuesAtQueryPosition[sampleData.columnIndex])
// 			linearTerm := f.qm31Chip.Add(f.qm31Chip.MulM31(a, domainPoint.Y), b)
// 			numerator = f.qm31Chip.Add(numerator, f.qm31Chip.Sub(value, linearTerm))
// 		}
// 		// accumulate the quotient evaluation for the sample point
// 		pointCoeff := randomCoeffPowers[len(samplesData)]
// 		frac := f.qm31Chip.MulCM31(numerator, denominatorInverse)
// 		quotientEvaluation = f.qm31Chip.Add(f.qm31Chip.Mul(quotientEvaluation, pointCoeff), frac)
// 	}
// 	return quotientEvaluation
// }

// ╔══════════════════════════════════╗
// ║           First Layer            ║
// ╚══════════════════════════════════╝

type FriFirstLayerVerifier struct {
	columnBounds            []frontend.Variable
	columnCommitmentDomains []circle.CircleDomain
	proof                   variables.FriLayerProof
	foldingAlpha            m31.QM31
}

// type SparseEvaluations struct {
// 	queryInitials []uints.U32
// 	evals         [][]m31.QM31
// }

// func (f *FriVerifier) verifyFirstLayer(queries [][]int, evaluations [][]m31.QM31) []SparseEvaluations {
// 	// compute the decommitment positions (queries and their siblings dedupped) and build the matching decommitments values
// 	decommitmentPositions := make([][]int, 32)
// 	sparseEvaluationsFlattened := make([]m31.M31, 0)
// 	sparseEvaluations := make([]SparseEvaluations, 0)
// 	previousFriWitnessIndex := 0
// 	for domainIndex, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
// 		logSize := columnCommitmentDomain.LogSize()
// 		layerQueries := queries[logSize]

// 		layerDecommitmentPositions, layerSparseEvaluationsFlattened, sparseEvaluation, friWitnessIndex := f.computeDecommitmentPositionsAndRebuildEvals(layerQueries, evaluations[domainIndex], f.FirstLayerVerifier.proof.FriWitness, previousFriWitnessIndex, int(logSize))
// 		previousFriWitnessIndex = friWitnessIndex
// 		decommitmentPositions[logSize] = layerDecommitmentPositions
// 		sparseEvaluations = append(sparseEvaluations, sparseEvaluation)
// 		sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, layerSparseEvaluationsFlattened...)
// 	}

// 	// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
// 	columnLogSizes := make([]uint8, 0)
// 	for _, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
// 		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
// 		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
// 		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
// 		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
// 	}

// 	// verify the merkle decommitment
// 	merkleVerifier := NewMerkleVerifier(f.api, f.FirstLayerVerifier.proof.Commitment, columnLogSizes)
// 	merkleVerifier.Verify(decommitmentPositions, sparseEvaluationsFlattened, f.FirstLayerVerifier.proof.Decommitment)

// 	return sparseEvaluations
// }

// func (f *FriVerifier) computeDecommitmentPositionsAndRebuildEvals(layerQueries []int, evalAtQueries []m31.QM31, witnessEvals []m31.QM31, previousFriWitnessIndex int, logSize int) ([]int, []m31.M31, SparseEvaluations, int) {
// 	friWitnessIndex := previousFriWitnessIndex
// 	// helper function replicating the rust api for iterator next() method
// 	nextFriWitness := func() m31.QM31 {
// 		if friWitnessIndex >= len(witnessEvals) {
// 			panic("fri witness exhausted")
// 		}
// 		witness := witnessEvals[friWitnessIndex]
// 		friWitnessIndex++
// 		return witness
// 	}

// 	layerDecommitmentPositions := make([]int, 0)
// 	sparseEvaluationsFlattened := make([]m31.M31, 0)
// 	evals := make([][]m31.QM31, 0)
// 	queryInitials := make([]uints.U32, 0)
// 	for i := 0; i < len(layerQueries); {
// 		subsetEvals := make([]m31.QM31, 2)
// 		queryInitial := layerQueries[i] >> 1
// 		leftCandidate := queryInitial << 1
// 		rightCandidate := leftCandidate + 1
// 		layerDecommitmentPositions = append(layerDecommitmentPositions, leftCandidate, rightCandidate)
// 		// follow the same pattern as the merkle decommitment verifier
// 		switch layerQueries[i] {
// 		case leftCandidate:
// 			subsetEvals[0] = evalAtQueries[i]
// 			if i+1 < len(layerQueries) && layerQueries[i+1] == rightCandidate {
// 				subsetEvals[1] = evalAtQueries[i+1]
// 				i += 2
// 			} else {
// 				subsetEvals[1] = nextFriWitness()
// 				i++
// 			}
// 		case rightCandidate:
// 			subsetEvals[0] = nextFriWitness()
// 			subsetEvals[1] = evalAtQueries[i]
// 			i++
// 		default:
// 			panic("unexpected query candidate")
// 		}

// 		// flatten the evaluations into 4 M31 elements for use in the merkle decommitment verifier
// 		leftEval := subsetEvals[0].Components()
// 		sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, leftEval[0], leftEval[1], leftEval[2], leftEval[3])
// 		rightEval := subsetEvals[1].Components()
// 		sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, rightEval[0], rightEval[1], rightEval[2], rightEval[3])

// 		// build the sparse evaluations for the inner layer verifier
// 		evals = append(evals, subsetEvals)
// 		queryInitials = append(queryInitials, reverseBitIndex(f.api, f.uapi, uint32(leftCandidate), logSize))
// 	}

// 	sparseEvaluation := SparseEvaluations{
// 		queryInitials: queryInitials,
// 		evals:         evals,
// 	}

// 	return layerDecommitmentPositions, sparseEvaluationsFlattened, sparseEvaluation, friWitnessIndex
// }

// ╔══════════════════════════════════╗
// ║            Inner Layers          ║
// ╚══════════════════════════════════╝
type FriInnerLayerVerifier struct {
	degreeBound  frontend.Variable
	domain       circle.LineDomain
	foldingAlpha m31.QM31
	layerIndex   int
	proof        variables.FriLayerProof
}

// func (f *FriVerifier) verifyInnerLayers(queries [][]int, firstLayerEvaluations []SparseEvaluations) []m31.QM31 {
// 	columnBoundsIndex := 0
// 	previousAlpha := f.FirstLayerVerifier.foldingAlpha
// 	//queries only contains queries for log sizes for which there exists columns of given size
// 	extendedQueries := extendQueries(queries, f.FirstLayerVerifier.columnBounds[0])
// 	// initialize the current layer evaluations with the first layer evaluations
// 	nQueriesForFirstInnerLayer := len(extendedQueries[f.FirstLayerVerifier.columnCommitmentDomains[0].LogSize()-1])
// 	currentLayerEvals := make([]m31.QM31, nQueriesForFirstInnerLayer)
// 	for i := range currentLayerEvals {
// 		currentLayerEvals[i] = f.qm31Chip.Zero()
// 	}

// 	for _, innerLayerVerifier := range f.InnerLayerVerifiers {
// 		// check if we need to fold in fri answers to this layer
// 		if columnBoundsIndex < len(f.FirstLayerVerifier.columnBounds) && f.FirstLayerVerifier.columnBounds[columnBoundsIndex]-1 == innerLayerVerifier.degreeBound {
// 			// fold the evaluations from H_i to I_i
// 			foldedColumnEvals := make([]m31.QM31, 0)

// 			for i, eval := range firstLayerEvaluations[columnBoundsIndex].evals {
// 				// queryInitial is the index of (x_i,y_i) in H_i
// 				queryInitial := firstLayerEvaluations[columnBoundsIndex].queryInitials[i]
// 				// columnDomain corresponds to the circle domain H_i
// 				columnDomain := f.FirstLayerVerifier.columnCommitmentDomains[columnBoundsIndex]
// 				// P is the point (x_i,y_i) in H_i, we only need the y coordinate for folding
// 				P := columnDomain.IndexAt(queryInitial).Point()
// 				// Calculate `evenPart` and `oddPart` such that `2h(P) = evenPart + Py * oddPart`.
// 				h0 := eval[0] // h(P) = h(x_i, y_i)
// 				h1 := eval[1] // h(-P) = h(x_i, -y_i)
// 				evenPart := f.qm31Chip.Add(h0, h1)
// 				inversePy, _ := f.m31Chip.Inverse(P.Y)
// 				oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePy)
// 				// fold the evaluations with the previous alpha
// 				folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(previousAlpha, oddPart))
// 				foldedColumnEvals = append(foldedColumnEvals, folded)
// 			}
// 			columnBoundsIndex++

// 			// build g_i(x_j) from folded column evaluations and folded g_{i-1}
// 			previousAlphaSq := f.qm31Chip.Mul(previousAlpha, previousAlpha)
// 			for i, eval := range foldedColumnEvals {
// 				currentLayerEvals[i] = f.qm31Chip.Mul(currentLayerEvals[i], previousAlphaSq)
// 				currentLayerEvals[i] = f.qm31Chip.Add(currentLayerEvals[i], eval)
// 			}
// 		}

// 		// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
// 		logSize := uint8(innerLayerVerifier.domain.LogSize())
// 		columnLogSizes := []uint8{logSize, logSize, logSize, logSize}

// 		// verify g_i(x_j) decommitments
// 		layerDecommitmentPositions, sparseEvaluationsFlattened, sparseEvaluation, _ := f.computeDecommitmentPositionsAndRebuildEvals(extendedQueries[innerLayerVerifier.degreeBound+1], currentLayerEvals, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.FriWitness, 0, int(innerLayerVerifier.degreeBound+1))
// 		decommitmentPositions := make([][]int, 32)
// 		decommitmentPositions[logSize] = layerDecommitmentPositions

// 		merkleVerifier := NewMerkleVerifier(f.api, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Commitment, columnLogSizes)
// 		merkleVerifier.Verify(decommitmentPositions, sparseEvaluationsFlattened, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Decommitment)

// 		// currentLayerEvals contains g_{i-1}(x_j) folded
// 		currentLayerEvals = make([]m31.QM31, len(extendedQueries[innerLayerVerifier.degreeBound]))

// 		// fold g_i evaluations from I_i to I_{i+1} (similar to folding over H_i to I_i but with line domains)
// 		for i, eval := range sparseEvaluation.evals {
// 			queryInitial := sparseEvaluation.queryInitials[i]
// 			domain := innerLayerVerifier.domain.Coset()
// 			queryInitialLE := uints.U32{queryInitial[3], queryInitial[2], queryInitial[1], queryInitial[0]}
// 			P := domain.IndexAt(queryInitialLE).Point()
// 			h0 := eval[0] // g_i(P) = g_i(x_i, y_i)
// 			h1 := eval[1] // g_i(-P) = g_i(x_i, -y_i)
// 			evenPart := f.qm31Chip.Add(h0, h1)
// 			inversePx, _ := f.m31Chip.Inverse(P.X) // x instead of y since we are in the line domain
// 			oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePx)
// 			folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(innerLayerVerifier.foldingAlpha, oddPart))
// 			currentLayerEvals[i] = folded
// 		}

// 		// update alpha
// 		previousAlpha = innerLayerVerifier.foldingAlpha

// 	}

// 	return currentLayerEvals
// }

// ╔══════════════════════════════════╗
// ║            Last Layer            ║
// ╚══════════════════════════════════╝

// Verifies that the last layer evaluations are equal to the last layer polynomial coefficients
// This assumes the last layer is a constant polynomial
// func (f *FriVerifier) verifyLastLayer(lastEvaluations []m31.QM31) {
// 	for _, eval := range lastEvaluations {
// 		f.qm31Chip.AssertEqual(eval, f.LastLayerPoly.Coeffs[0])
// 	}
// }

// ╔══════════════════════════════════╗
// ║            Utilities             ║
// ╚══════════════════════════════════╝

// func reverseBitIndex(api frontend.API, uapi *uints.BinaryField[uints.U32], n uint32, logSize int) uints.U32 {
// 	nNative := frontend.Variable(n)
// 	nBits := bits.ToBinary(api, nNative, bits.WithNbDigits(32))
// 	reversedBits := make([]frontend.Variable, 32)
// 	for i := 0; i < 32; i++ {
// 		reversedBits[i] = nBits[32-(i+1)]
// 	}
// 	nReversedNative := bits.FromBinary(api, reversedBits)
// 	nReversedBytes, err := conversion.NativeToBytes(api, nReversedNative)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// no need to reduce since reversed bits has 32 bits by construction
// 	nReversed := uints.U32{nReversedBytes[len(nReversedBytes)-1], nReversedBytes[len(nReversedBytes)-2], nReversedBytes[len(nReversedBytes)-3], nReversedBytes[len(nReversedBytes)-4]}
// 	result := uapi.Rshift(nReversed, 32-logSize)
// 	return uints.U32{result[3], result[2], result[1], result[0]}
// }
