package fri

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

type FriVerifier struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U32]
	qm31Chip   *m31.QM31Chip
	circleChip *circle.CircleChip

	friConfig           FriConfig
	FirstLayerVerifier  FriFirstLayerVerifier
	InnerLayerVerifiers []FriInnerLayerVerifier
	LastLayerPoly       circle.LinePoly
}

type FriInnerLayerVerifier struct {
	degreeBound uint8
	//domain       circle.LineDomain
	foldingAlpha m31.QM31
	layerIndex   int
	proof        variables.FriLayerProof
}

func NewFriVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], channelChip *channel.Channel, qm31Chip *m31.QM31Chip, circleChip *circle.CircleChip, friConfig FriConfig, friProof variables.FriProof, bounds []uint8) *FriVerifier {
	// First layer commitment
	channelChip.MixRootBytes(friProof.FirstLayerProof.Commitment[:])

	// First layer verifier
	columncommitmentDomains := make([]circle.CircleDomain, 0)
	for _, bound := range bounds {
		columncommitmentDomains = append(columncommitmentDomains, circle.NewCanonicCoset(circleChip, uint32(bound+friConfig.LogBlowupFactor)).CircleDomain())
	}
	firstLayerVerifier := FriFirstLayerVerifier{
		columnBounds:            bounds,
		columnCommitmentDomains: columncommitmentDomains,
		proof:                   friProof.FirstLayerProof,
		foldingAlpha:            channelChip.DrawFelt(),
	}

	// Inner layer verifiers
	// TODO: properly implement the line folding once the relevant circle operations are implemented
	layerBound := bounds[0] - 1 // first bound folded
	//layerDomain := circleChip.NewLineDomain(uint32(layerBound))

	innerLayerVerifiers := make([]FriInnerLayerVerifier, len(friProof.InnerLayerProofs))
	for i, innerLayerProof := range friProof.InnerLayerProofs {
		channelChip.MixRootBytes(innerLayerProof.Commitment[:])
		innerLayerVerifiers[i] = FriInnerLayerVerifier{
			degreeBound: layerBound,
			//domain:       layerDomain,
			foldingAlpha: channelChip.DrawFelt(),
			layerIndex:   i,
			proof:        innerLayerProof,
		}

		// fold layer
		layerBound--
		//layerDomain = layerDomain.double()
	}

	// Mix in the last layer
	channelChip.MixFelts(friProof.LastLayerPoly.Coeffs)

	return &FriVerifier{
		api:                 api,
		uapi:                uapi,
		qm31Chip:            qm31Chip,
		circleChip:          circleChip,
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
	}
}

func (f *FriVerifier) Verify(queries [][]int, evaluations [][]m31.QM31) {
	f.verifyFirstLayer(queries, evaluations)
}

// ╔══════════════════════════════════╗
// ║              Queries             ║
// ╚══════════════════════════════════╝

func (f *FriVerifier) GenerateBaseLayerQueries(channelChip *channel.Channel, uapi *uints.BinaryField[uints.U32], nQueries uint8) []frontend.Variable {
	maxLogSize := f.FirstLayerVerifier.columnBounds[0] + f.friConfig.LogBlowupFactor
	queries := make([]frontend.Variable, 0)
	queryCount := uint8(0)
	maxQuery := uints.NewU32((1 << maxLogSize) - 1)
	nDuplicates := uint8(0) // TODO: this should be hinted by the prover
	for queryCount < nQueries+nDuplicates {
		randomBytes := channelChip.DrawRandomBytes()
		for i := 0; i < len(randomBytes); i += 4 {
			query := uapi.PackLSB(randomBytes[i], randomBytes[i+1], randomBytes[i+2], randomBytes[i+3])
			quotientQuery := uapi.And(query, maxQuery)
			queries = append(queries, uapi.ToValue(quotientQuery))
			queryCount++
			if queryCount == nQueries+nDuplicates {
				break
			}
		}
	}
	return queries
}

// VerifyQueries verifies that the hinted queries are the base layer queries in ascending order
func (f *FriVerifier) VerifyQueries(hintedQueries []int, baseLayerQueries []frontend.Variable) {
	// Check that the hinted queries are in ascending order
	cmp := cmp.NewBoundedComparator(f.api, big.NewInt(1<<32), false)
	for i := 1; i < len(hintedQueries); i++ {
		cmp.AssertIsLess(hintedQueries[i-1], hintedQueries[i])
	}

	// To check that the hinted queries are a permutation of the base layer queries,
	// we compare the grand products evaluated on a point drawn from a new channel after mixing
	// the hinted queries.

	// Instantiate a new channel
	channel := channel.NewChannel(f.api)

	// Convert the hinted queries to bytes
	hintedQueriesBytes := make([]uints.U8, 0)
	for _, query := range hintedQueries {
		bytes, err := conversion.NativeToBytes(f.api, query)
		if err != nil {
			panic(err)
		}
		hintedQueriesBytes = append(hintedQueriesBytes, bytes[len(bytes)-4:]...)
	}

	// Mix the hinted queries into the channel
	channel.MixRootBytes(hintedQueriesBytes)

	// Build a random 248-bit (31 bytes) point from the channel
	randomBytes := channel.DrawRandomBytes()
	point, err := conversion.BytesToNative(f.api, randomBytes[:31])
	if err != nil {
		panic(err)
	}

	// Evaluate the grand products
	grandProductHint := frontend.Variable(1)
	for _, hintedQuery := range hintedQueries {
		grandProductHint = f.api.Mul(grandProductHint, f.api.Add(hintedQuery, point))
	}
	grandProductRef := frontend.Variable(1)
	for _, baseLayerQuery := range baseLayerQueries {
		grandProductRef = f.api.Mul(grandProductRef, f.api.Add(baseLayerQuery, point))
	}

	// Check that the grand products are equal
	f.api.AssertIsEqual(grandProductHint, grandProductRef)
}

// ╔══════════════════════════════════╗
// ║           FRI Quotients          ║
// ╚══════════════════════════════════╝

type SampleData struct {
	point            circle.Point
	columnIndex      int
	value            m31.QM31
	lineCoefficients [3]m31.QM31
}

// FriQuotientEvaluations evaluates the FRI quotients returning quotient evaluations for each log size and for each query
//   - columnLogSizes: log sizes of each column (blew up) for each tree
//   - sampledValues: sampled values for each column for each tree
//   - sampledPoints: sampled points (or "mask points") for each tree, the shape should exactly match the shape of sampledValues
//   - queries: query positions per log size
//   - queriedValues: column values queried for each tree ordered by log size then by query position (same as merkle decommitments)
//   - randomCoeff: random coefficient used to batch lines with the same sample point and quotients with the same log size
func (f *FriVerifier) FriQuotientEvaluations(
	columnLogSizes [][]uint8,
	sampledValues [][][]m31.QM31,
	sampledPoints cairo_components.TreeMaskPoints,
	queries [][]int,
	queriedValues [][]m31.M31,
	randomCoeff m31.QM31,
) [][]m31.QM31 {
	// compute number of columns per log size per tree and compute max and min log sizes
	nColumnsPerLogSize := make([]map[int]int, cairo_components.N_TREES)
	maxLogSize := 0
	minLogSize := 32
	for treeIndex, treeColumnLogSizes := range columnLogSizes {
		nColumnsPerLogSize[treeIndex] = make(map[int]int)
		for _, logSize := range treeColumnLogSizes {
			nColumnsPerLogSize[treeIndex][int(logSize)]++
			if int(logSize) > maxLogSize {
				maxLogSize = int(logSize)
			}
			if int(logSize) < minLogSize {
				minLogSize = int(logSize)
			}
		}
	}

	// compute the max number of columns per log size overall
	maxNColumnsPerLogSize := 0
	for i := 0; i < 32; i++ {
		nColumns := 0
		for treeIndex := range cairo_components.N_TREES {
			nColumns += nColumnsPerLogSize[treeIndex][i]
		}
		if nColumns > maxNColumnsPerLogSize {
			maxNColumnsPerLogSize = nColumns
		}
	}

	// precompute randomCoeff powers
	randomCoeffPowers := make([]m31.QM31, maxNColumnsPerLogSize+1)
	randomCoeffPowers[0] = f.qm31Chip.One()
	for i := 1; i < maxNColumnsPerLogSize+1; i++ {
		randomCoeffPowers[i] = f.qm31Chip.Mul(randomCoeffPowers[i-1], randomCoeff)
	}

	// Merge sampled values and sampled points into samples (table of SampleData)
	// This is not a map because order matters when iterating
	// dim-1 (log size): samplesByLogSize groups all columns from all trees per log size
	// dim-2 (point): samplesByLogSize groups sampled values of columns of same log size by sample point
	// dim-3 (samples)
	samplesByLogSize := make([][][]SampleData, 32)
	for i := range samplesByLogSize {
		samplesByLogSize[i] = make([][]SampleData, 0)
	}
	columnIndexes := make([]int, 32)
	for treeIndex, tree := range sampledPoints {
		for columnIndex, column := range tree {
			logSize := columnLogSizes[treeIndex][columnIndex]
			for pointIndex, point := range column {
				for range len(column) - len(samplesByLogSize[logSize]) {
					samplesByLogSize[logSize] = append(samplesByLogSize[logSize], make([]SampleData, 0))
				}
				// when 2 points are sampled the order is [pointNegOne, point], this contrasts with the single-sampled points order ([point])
				// using a map would require some encoding/decoding of the points which are just handles and not usable as keys
				alpha := randomCoeffPowers[len(samplesByLogSize[logSize][len(column)-pointIndex-1])+1]
				sampledValue := sampledValues[treeIndex][columnIndex][pointIndex]
				lineCoefficients := GetLineCoefficients(f.qm31Chip, point, sampledValue, alpha)
				samplesByLogSize[logSize][len(column)-pointIndex-1] = append(samplesByLogSize[logSize][len(column)-pointIndex-1], SampleData{
					point:            point,
					columnIndex:      columnIndexes[logSize],
					value:            sampledValue,
					lineCoefficients: lineCoefficients,
				})
			}
			columnIndexes[logSize]++
		}
	}

	// evaluate the quotient at each query position for each log size
	quotientEvaluations := make([][]m31.QM31, 0)
	queriedValuesPointer := make([]int, cairo_components.N_TREES)
	for logSize := maxLogSize; logSize >= minLogSize; logSize-- {
		samples := samplesByLogSize[logSize]
		circleDomain := circle.NewCanonicCoset(f.circleChip, uint32(logSize)).CircleDomain()
		layerQuotientEvaluations := make([]m31.QM31, 0)
		for _, queryPosition := range queries[logSize] {
			bitReversedQueryPosition := reverseBitIndex(f.api, f.uapi, uint32(queryPosition), logSize)
			domainPoint := circleDomain.At(bitReversedQueryPosition)
			// get flattened (over trees) queried values at query position
			valuesAtQueryPosition := make([]m31.M31, 0)
			for treeIndex := range cairo_components.N_TREES {
				nColumns := nColumnsPerLogSize[treeIndex][logSize]
				valuesAtQueryPosition = append(valuesAtQueryPosition, queriedValues[treeIndex][queriedValuesPointer[treeIndex]:queriedValuesPointer[treeIndex]+nColumns]...)
				queriedValuesPointer[treeIndex] += nColumns
			}
			// evaluate the quotient at the query position for the given log size
			layerQuotientEvaluations = append(layerQuotientEvaluations, f.quotientEvaluation(samples, valuesAtQueryPosition, domainPoint, randomCoeffPowers))
		}
		quotientEvaluations = append(quotientEvaluations, layerQuotientEvaluations)
	}

	return quotientEvaluations
}

func GetLineCoefficients(qm31Chip *m31.QM31Chip, samplePoint circle.Point, sampledValue m31.QM31, alpha m31.QM31) [3]m31.QM31 {
	a := qm31Chip.Sub(qm31Chip.ComplexConjugate(sampledValue), sampledValue)
	c := qm31Chip.Sub(qm31Chip.ComplexConjugate(samplePoint.Y), samplePoint.Y)
	b := qm31Chip.Sub(qm31Chip.Mul(sampledValue, c), qm31Chip.Mul(a, samplePoint.Y))
	return [3]m31.QM31{qm31Chip.Mul(alpha, a), qm31Chip.Mul(alpha, b), qm31Chip.Mul(alpha, c)}
}

func (f *FriVerifier) quotientEvaluation(samples [][]SampleData, valuesAtQueryPosition []m31.M31, domainPoint circle.BasePoint, randomCoeffPowers []m31.QM31) m31.QM31 {
	quotientEvaluation := f.qm31Chip.Zero()
	// iterate through sampling points relative to the current log size (at most two points per log size with current stwo-cairo)
	for _, samplesData := range samples {
		point := samplesData[0].point
		// compute the denominator (CM31)
		samplePointRX := m31.CM31{Real: point.X.AReal, Imag: point.X.AImag}
		samplePointRY := m31.CM31{Real: point.Y.AReal, Imag: point.Y.AImag}
		samplePointIX := m31.CM31{Real: point.X.BReal, Imag: point.X.BImag}
		samplePointIY := m31.CM31{Real: point.Y.BReal, Imag: point.Y.BImag}
		denominator := f.qm31Chip.CmSub(
			f.qm31Chip.CmMul(
				f.qm31Chip.CmSubM31(
					samplePointRX,
					domainPoint.X,
				),
				samplePointIY,
			),
			f.qm31Chip.CmMul(
				f.qm31Chip.CmSubM31(
					samplePointRY,
					domainPoint.Y,
				),
				samplePointIX,
			),
		)
		// inverse the denominator (CM31)
		denominatorInverse := f.qm31Chip.CM31Inverse(denominator)
		// compute the numerator for the sample point (batching)
		numerator := f.qm31Chip.Zero()
		for _, sampleData := range samplesData {
			a := sampleData.lineCoefficients[0]
			b := sampleData.lineCoefficients[1]
			c := sampleData.lineCoefficients[2]
			value := f.qm31Chip.MulM31(c, valuesAtQueryPosition[sampleData.columnIndex])
			linearTerm := f.qm31Chip.Add(f.qm31Chip.MulM31(a, domainPoint.Y), b)
			numerator = f.qm31Chip.Add(numerator, f.qm31Chip.Sub(value, linearTerm))
		}
		// accumulate the quotient evaluation for the sample point
		pointCoeff := randomCoeffPowers[len(samplesData)]
		frac := f.qm31Chip.MulCM31(numerator, denominatorInverse)
		quotientEvaluation = f.qm31Chip.Add(f.qm31Chip.Mul(quotientEvaluation, pointCoeff), frac)
	}
	return quotientEvaluation
}

// ╔══════════════════════════════════╗
// ║           First Layer            ║
// ╚══════════════════════════════════╝

type FriFirstLayerVerifier struct {
	columnBounds            []uint8
	columnCommitmentDomains []circle.CircleDomain
	proof                   variables.FriLayerProof
	foldingAlpha            m31.QM31
}

func (f *FriVerifier) verifyFirstLayer(queries [][]int, evaluations [][]m31.QM31) {
	friWitnessIndex := 0
	// helper function replicating the rust api for iterator next() method
	nextFriWitness := func() m31.QM31 {
		if friWitnessIndex >= len(f.FirstLayerVerifier.proof.FriWitness) {
			panic("fri witness exhausted")
		}
		witness := f.FirstLayerVerifier.proof.FriWitness[friWitnessIndex]
		friWitnessIndex++
		return witness
	}

	// compute the decommitment positions (queries and their siblings dedupped) and build the matching decommitments values
	decommitmentPositions := make([][]int, 32)
	sparseEvaluations := make([]m31.M31, 0)
	for domainIndex, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
		logSize := columnCommitmentDomain.LogSize()
		layerQueries := queries[logSize]

		layerDecommitmentPositions := make([]int, 0)
		for i := 0; i < len(layerQueries); {
			subsetEvals := make([]m31.QM31, 2)
			queryInitial := layerQueries[i] >> 1
			leftCandidate := queryInitial << 1
			rightCandidate := leftCandidate + 1
			layerDecommitmentPositions = append(layerDecommitmentPositions, leftCandidate, rightCandidate)
			// follow the same pattern as the merkle decommitment verifier
			switch layerQueries[i] {
			case leftCandidate:
				subsetEvals[0] = evaluations[domainIndex][i]
				if i+1 < len(layerQueries) && layerQueries[i+1] == rightCandidate {
					subsetEvals[1] = evaluations[domainIndex][i+1]
					i += 2
				} else {
					subsetEvals[1] = nextFriWitness()
					i++
				}
			case rightCandidate:
				subsetEvals[0] = nextFriWitness()
				subsetEvals[1] = evaluations[domainIndex][i]
				i++
			default:
				panic("unexpected query candidate")
			}

			// flatten the evaluations into 4 M31 elements for use in the merkle decommitment verifier
			leftEval := subsetEvals[0].Components()
			sparseEvaluations = append(sparseEvaluations, leftEval[0], leftEval[1], leftEval[2], leftEval[3])
			rightEval := subsetEvals[1].Components()
			sparseEvaluations = append(sparseEvaluations, rightEval[0], rightEval[1], rightEval[2], rightEval[3])
		}
		decommitmentPositions[logSize] = layerDecommitmentPositions
	}

	// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
	columnLogSizes := make([]uint8, 0)
	for _, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
		columnLogSizes = append(columnLogSizes, uint8(columnCommitmentDomain.LogSize()))
	}

	// verify the merkle decommitment
	merkleVerifier := NewMerkleVerifier(f.api, f.FirstLayerVerifier.proof.Commitment, columnLogSizes)
	merkleVerifier.Verify(decommitmentPositions, sparseEvaluations, f.FirstLayerVerifier.proof.Decommitment)
}

// ╔══════════════════════════════════╗
// ║            Utilities             ║
// ╚══════════════════════════════════╝

func reverseBitIndex(api frontend.API, uapi *uints.BinaryField[uints.U32], n uint32, logSize int) uints.U32 {
	nNative := frontend.Variable(n)
	nBits := bits.ToBinary(api, nNative, bits.WithNbDigits(32))
	reversedBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		reversedBits[i] = nBits[32-(i+1)]
	}
	nReversedNative := bits.FromBinary(api, reversedBits)
	nReversedBytes, err := conversion.NativeToBytes(api, nReversedNative)
	if err != nil {
		panic(err)
	}
	// no need to reduce since reversed bits has 32 bits by construction
	nReversed := uints.U32{nReversedBytes[len(nReversedBytes)-1], nReversedBytes[len(nReversedBytes)-2], nReversedBytes[len(nReversedBytes)-3], nReversedBytes[len(nReversedBytes)-4]}
	result := uapi.Rshift(nReversed, 32-logSize)
	return uints.U32{result[3], result[2], result[1], result[0]}
}
