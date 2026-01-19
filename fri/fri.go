package fri

import (
	"fmt"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// FriVerifier is a circuit gadget for verifying a FRI proof
type FriVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	bapi        *uints.Bytes
	m31Chip     *m31.M31Chip
	qm31Chip    *m31.QM31Chip
	circleChip  *circle.CircleChip
	blake2sChip *blake2s.Blake2sChip
	cmpU32      *cmp.BoundedComparator

	friConfig           variables.FriConfig
	FirstLayerVerifier  FriFirstLayerVerifier
	InnerLayerVerifiers []FriInnerLayerVerifier
	LastLayerPoly       circle.LinePoly

	circuitData variables.CircuitData

	bitDecompCache map[string][]frontend.Variable
}

// NewFriVerifier initializes a new FriVerifier
func NewFriVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], bapi *uints.Bytes, blake2sChip *blake2s.Blake2sChip, cmpU32 *cmp.BoundedComparator, channelChip *channel.Channel, qm31Chip *m31.QM31Chip, circleChip *circle.CircleChip, friConfig variables.FriConfig, friProof variables.FriProof, bounds []frontend.Variable, circuitData variables.CircuitData) *FriVerifier {
	// First layer commitment
	channelChip.MixRootBytes(friProof.FirstLayerProof.Commitment[:])

	// First layer verifier
	columncommitmentDomains := make([]circle.CircleDomain, 0)
	for _, bound := range bounds {
		columncommitmentDomains = append(columncommitmentDomains, circle.NewCanonicCoset(circleChip, bound).CircleDomain())
	}
	firstLayerVerifier := FriFirstLayerVerifier{
		columnBounds:            bounds,
		columnCommitmentDomains: columncommitmentDomains,
		proof:                   friProof.FirstLayerProof,
		foldingAlpha:            channelChip.DrawFelt(),
	}

	// Inner layer verifiers
	layerBound := api.Sub(bounds[0], 2) // first bound folded and blew up
	layerDomain := circle.NewLineDomain(circle.NewCoset(circleChip, circle.SubgroupGenerator(circleChip, api.Add(api.Add(layerBound, friConfig.LogBlowupFactor), 2)), api.Add(layerBound, friConfig.LogBlowupFactor)))

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
		bapi:                bapi,
		m31Chip:             qm31Chip.M31Chip(),
		qm31Chip:            qm31Chip,
		circleChip:          circleChip,
		blake2sChip:         blake2sChip,
		cmpU32:              cmpU32,
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
		circuitData:         circuitData,
		bitDecompCache:      make(map[string][]frontend.Variable),
	}
}

// Verify verifies the FRI proof for the given queries and evaluations
func (f *FriVerifier) Verify(queries [][]frontend.Variable, evaluations [][]frontend.Variable) {
	firstLayerEvaluations := f.verifyFirstLayer(queries, evaluations)
	lastEvaluations := f.verifyInnerLayers(queries, firstLayerEvaluations)
	f.verifyLastLayer(lastEvaluations)
}

// ╔══════════════════════════════════╗
// ║           FRI Quotients          ║
// ╚══════════════════════════════════╝

// SampleData is a data structure for storing sample data
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
	sampledValues [][][]m31.QM31,
	sampledPoints components.TreeMaskPoints,
	queries [][]frontend.Variable,
	queriedValues [][]m31.M31,
	randomCoeff m31.QM31,
) [][]m31.QM31 {
	// compute the orvall maximum number of columns for a log size
	maxNColumns := 0
	for i := 0; i < 32; i++ {
		nColumns := 0
		for treeIndex := 0; treeIndex < cairo_components.N_TREES; treeIndex++ {
			nColumns += f.circuitData.NColumnsPerLogSize[treeIndex][i]
		}
		if nColumns > maxNColumns {
			maxNColumns = nColumns
		}
	}

	// precompute randomCoeff powers
	randomCoeffPowers := make([]m31.QM31, maxNColumns+1)
	randomCoeffPowers[0] = f.qm31Chip.One()
	for i := 1; i < maxNColumns+1; i++ {
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
			logSize := f.circuitData.ColumnLogSizes[treeIndex][columnIndex] + 1
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
	for _, logSize := range f.circuitData.ColumnBounds {
		samples := samplesByLogSize[logSize]
		circleDomain := circle.NewCanonicCoset(f.circleChip, frontend.Variable(logSize)).CircleDomain()
		layerQuotientEvaluations := make([]m31.QM31, 0)
		for _, queryPosition := range queries[logSize] {
			bitReversedQueryPosition := f.reverseBitIndex(queryPosition, logSize)
			domainPoint := circleDomain.At(bitReversedQueryPosition)
			// get flattened (over trees) queried values at query position
			valuesAtQueryPosition := make([]m31.M31, 0)
			for treeIndex := 0; treeIndex < cairo_components.N_TREES; treeIndex++ {
				nColumns := f.circuitData.NColumnsPerLogSize[treeIndex][logSize-1]
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

// GetLineCoefficients computes the line coefficients for a given sample point and sampled value
// Specifically, `a, b, and c, s.t. a*x + b -c*y = 0` for (x,y) being (sample.y, sample.value) and
// (conj(sample.y), conj(sample.value)). Returns `[a*alpha, b*alpha, c*alpha]`.
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

// FriFirstLayerVerifier is a circuit gadget for verifying the first layer of a FRI proof
type FriFirstLayerVerifier struct {
	columnBounds            []frontend.Variable
	columnCommitmentDomains []circle.CircleDomain
	proof                   variables.FriLayerProof
	foldingAlpha            m31.QM31
}

// SparseEvaluations is a data structure for storing sparse evaluations
type SparseEvaluations struct {
	queryInitials []uints.U32
	evals         [][2]m31.QM31
}

func (f *FriVerifier) verifyFirstLayer(queries [][]frontend.Variable, evaluations [][]frontend.Variable) []SparseEvaluations {
	// compute the decommitment positions (queries and their siblings dedupped) and build the matching decommitments values
	decommitmentPositions := make([][]frontend.Variable, 32)
	sparseEvaluationsFlattened := make([]m31.M31, 0)
	sparseEvaluations := make([]SparseEvaluations, 0)
	previousFriWitnessIndex := 0

	columnBoundsIndex := 0
	maxLogSize := f.circuitData.ColumnBounds[0]

	queriesShape := make([]int, 32)

	// build the merkle tree decommitment for the fri answers
	// for each layer there either is FRI answers or not
	// if there are FRI answers, we compute the decommitment positions and the sparse evaluations from the FRI answers
	// if there are no FRI answers, we just fold the previous layer queries
	for logSize := maxLogSize; logSize >= 0; logSize-- {
		if columnBoundsIndex < len(f.circuitData.ColumnBounds) && logSize == f.circuitData.ColumnBounds[columnBoundsIndex] {
			layerQueries := queries[logSize]
			// compute local data
			layerDecommitmentPositions, layerSparseEvaluationsFlattened, sparseEvaluation, friWitnessIndex := f.computeDecommitmentPositionsAndRebuildEvals(
				layerQueries,
				evaluations[columnBoundsIndex],
				f.FirstLayerVerifier.proof.FriWitness,
				previousFriWitnessIndex,
				f.circuitData.DedupedQueriesShape[logSize-1],
				logSize,
			)
			previousFriWitnessIndex = friWitnessIndex

			// dummy values to simulate the unused children queries of the last query (if it is on the right) of a layer
			layerDecommitmentPositions = append(layerDecommitmentPositions, frontend.Variable(1<<32), frontend.Variable(1<<32))

			// update global data
			decommitmentPositions[logSize] = layerDecommitmentPositions
			sparseEvaluations = append(sparseEvaluations, sparseEvaluation)
			sparseEvaluationsFlattened = append(sparseEvaluationsFlattened, layerSparseEvaluationsFlattened...)
			// the trick here is to note that when building all the pairs of queries in a layer, we end up with
			// 2 times the number of queries in the next layer
			queriesShape[logSize] = 2 * f.circuitData.DedupedQueriesShape[logSize-1]
			columnBoundsIndex++
		} else {
			// if there are no FRI answers, we just fold the previous layer queries
			// use the previous layer query slice
			previousLayerQueriesLookup := decommitmentPositions[logSize+1]
			previousLayerQueries := make([]frontend.Variable, 0)
			nQueriesPreviousLayer := 0
			// if the previous layer contains fri answers
			if logSize+1 == f.circuitData.ColumnBounds[columnBoundsIndex-1] {
				nQueriesPreviousLayer = 2 * f.circuitData.DedupedQueriesShape[logSize]
			} else {
				nQueriesPreviousLayer = f.circuitData.DedupedQueriesShape[logSize+1]
			}
			for i := 0; i < nQueriesPreviousLayer; i++ {
				previousLayerQueries = append(previousLayerQueries, previousLayerQueriesLookup[i])
			}

			// fold the previous layer queries
			layerQueries := utils.FoldQueries(f.api, f.uapi, f.cmpU32, previousLayerQueries, f.circuitData.DedupedQueriesShape[logSize])

			layerQueries = append(layerQueries, frontend.Variable(1<<32), frontend.Variable(1<<32))

			queriesShape[logSize] = f.circuitData.DedupedQueriesShape[logSize]
			decommitmentPositions[logSize] = layerQueries
		}
		if len(decommitmentPositions[logSize]) == 0 {
			decommitmentPositions[logSize] = []frontend.Variable{frontend.Variable(1 << 32)}
		}

	}

	// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
	columnLogSizes := make([]frontend.Variable, 0)
	for _, columnCommitmentDomain := range f.FirstLayerVerifier.columnCommitmentDomains {
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
		columnLogSizes = append(columnLogSizes, f.api.Sub(columnCommitmentDomain.LogSize(), frontend.Variable(1)))
	}

	nColumnsPerLogSize := make([]int, 32)
	for _, logSize := range f.circuitData.ColumnBounds {
		nColumnsPerLogSize[logSize] = 4
	}

	// verify the merkle decommitment
	merkleVerifier := NewMerkleVerifierWithChips(f.api, f.uapi, f.bapi, f.m31Chip, f.blake2sChip, f.FirstLayerVerifier.proof.Commitment, columnLogSizes, nColumnsPerLogSize)
	firstLayerBranching := f.circuitData.FriFirstLayerBranching
	if len(firstLayerBranching) == 0 {
		panic("missing FRI first layer branching data")
	}
	merkleVerifier.Verify(decommitmentPositions, sparseEvaluationsFlattened, f.FirstLayerVerifier.proof.Decommitment, queriesShape, firstLayerBranching)

	return sparseEvaluations
}

// ╔══════════════════════════════════╗
// ║            Inner Layers          ║
// ╚══════════════════════════════════╝

// FriInnerLayerVerifier is a circuit gadget for verifying an inner layer of a FRI proof
type FriInnerLayerVerifier struct {
	degreeBound  frontend.Variable
	domain       circle.LineDomain
	foldingAlpha m31.QM31
	layerIndex   int
	proof        variables.FriLayerProof
}

// VerifyInnerLayers verifies the inner layers of a FRI proof
func (f *FriVerifier) verifyInnerLayers(queries [][]frontend.Variable, firstLayerEvaluations []SparseEvaluations) []m31.QM31 {
	columnBoundsIndex := 0
	previousAlpha := f.FirstLayerVerifier.foldingAlpha
	maxLogSize := f.circuitData.ColumnBounds[0] - 2

	// initialize the current layer evaluations with the first layer evaluations
	nQueriesForFirstInnerLayer := f.circuitData.DedupedQueriesShape[maxLogSize]
	currentLayerEvals := make([]m31.QM31, nQueriesForFirstInnerLayer)
	for i := range currentLayerEvals {
		currentLayerEvals[i] = f.qm31Chip.Zero()
	}

	for logSize := maxLogSize; logSize >= 1; logSize-- {
		innerLayerVerifier := f.InnerLayerVerifiers[maxLogSize-logSize]
		// check if we need to fold in fri answers to this layer
		if columnBoundsIndex < len(f.FirstLayerVerifier.columnBounds) && f.circuitData.ColumnBounds[columnBoundsIndex]-2 == logSize {
			// fold the evaluations from H_i to I_i
			foldedColumnEvals := make([]m31.QM31, 0)

			for i, eval := range firstLayerEvaluations[columnBoundsIndex].evals {
				// queryInitial is the index of (x_i,y_i) in H_i
				queryInitial := firstLayerEvaluations[columnBoundsIndex].queryInitials[i]
				// columnDomain corresponds to the circle domain H_i
				columnDomain := f.FirstLayerVerifier.columnCommitmentDomains[columnBoundsIndex]
				// P is the point (x_i,y_i) in H_i, we only need the y coordinate for folding
				P := columnDomain.IndexAt(queryInitial).Point()
				// Calculate `evenPart` and `oddPart` such that `2h(P) = evenPart + Py * oddPart`.
				h0 := eval[0] // h(P) = h(x_i, y_i)
				h1 := eval[1] // h(-P) = h(x_i, -y_i)
				evenPart := f.qm31Chip.Add(h0, h1)
				inversePy, _ := f.m31Chip.Inverse(P.Y)
				oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePy)
				// fold the evaluations with the previous alpha
				folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(previousAlpha, oddPart))
				foldedColumnEvals = append(foldedColumnEvals, folded)
			}
			columnBoundsIndex++

			// build g_i(x_j) from folded column evaluations and folded g_{i-1}
			previousAlphaSq := f.qm31Chip.Mul(previousAlpha, previousAlpha)
			for i, eval := range foldedColumnEvals {
				currentLayerEvals[i] = f.qm31Chip.Mul(currentLayerEvals[i], previousAlphaSq)
				currentLayerEvals[i] = f.qm31Chip.Add(currentLayerEvals[i], eval)
			}
		}

		// encode the g_i(x_j) into a slice of frontend.Variables with a dummy tail
		encodedCurrentLayerEvals := make([]frontend.Variable, 0, len(currentLayerEvals)+1)
		for _, eval := range currentLayerEvals {
			encodedCurrentLayerEvals = append(encodedCurrentLayerEvals, f.qm31Chip.EncodeNative(eval))
		}
		encodedCurrentLayerEvals = append(encodedCurrentLayerEvals, frontend.Variable(1<<32))

		// build the column log sizes (1 flattened QM31 column yields 4 M31 columns)
		columnLogSizes := []frontend.Variable{logSize, logSize, logSize, logSize}

		// verify g_i(x_j) decommitments
		layerDecommitmentPositions, sparseEvaluationsFlattened, sparseEvaluation, _ := f.computeDecommitmentPositionsAndRebuildEvals(
			queries[logSize+1],
			encodedCurrentLayerEvals,
			f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.FriWitness,
			0,
			f.circuitData.DedupedQueriesShape[logSize],
			logSize+1,
		)

		// build the decommitment positions and query shape for merkle decommitment verification
		// the merkle tree is built with just 4 columns on the largest layer
		// so decommitment positions on the largest layer are the paires queries computed in layerDecommitmentPositions
		// then the next layer is the folded queries from the previous layer
		// and the rest of the layers are the regular queries (no pairs) that can be taken from the queries table
		queryShape := make([]int, 32)

		// first layer is layerDecommitmentPositions
		decommitmentPositions := make([][]frontend.Variable, 32)
		decommitmentPositions[logSize+1] = layerDecommitmentPositions
		queryShape[logSize+1] = 2 * f.circuitData.DedupedQueriesShape[logSize]

		// fold the previous layer knowing that there are 2*f.circuitData.DedupedQueriesShape[logSize] queries
		previousLayerQueriesLookup := layerDecommitmentPositions
		previousLayerQueries := make([]frontend.Variable, 0)
		for i := 0; i < 2*f.circuitData.DedupedQueriesShape[logSize]; i++ {
			previousLayerQueries = append(previousLayerQueries, previousLayerQueriesLookup[i])
		}
		layerQueries := utils.FoldQueries(f.api, f.uapi, f.cmpU32, previousLayerQueries, f.circuitData.DedupedQueriesShape[logSize])
		layerQueries = append(layerQueries, frontend.Variable(1<<32), frontend.Variable(1<<32))
		decommitmentPositions[logSize] = layerQueries
		queryShape[logSize] = f.circuitData.DedupedQueriesShape[logSize]

		// the rest of the decommitment positions are the regular queries (no pairs)
		for i := logSize - 1; i >= 0; i-- {
			decommitmentPositions[i] = queries[i]
			queryShape[i] = f.circuitData.DedupedQueriesShape[i]
		}

		nColumnsPerLogSize := make([]int, 32)
		nColumnsPerLogSize[logSize+1] = 4

		merkleVerifier := NewMerkleVerifierWithChips(f.api, f.uapi, f.bapi, f.m31Chip, f.blake2sChip, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Commitment, columnLogSizes, nColumnsPerLogSize)
		if innerLayerVerifier.layerIndex >= len(f.circuitData.FriInnerLayerBranching) {
			panic("missing FRI inner layer branching data")
		}
		innerBranching := f.circuitData.FriInnerLayerBranching[innerLayerVerifier.layerIndex]
		merkleVerifier.Verify(decommitmentPositions, sparseEvaluationsFlattened, f.InnerLayerVerifiers[innerLayerVerifier.layerIndex].proof.Decommitment, queryShape, innerBranching)

		// currentLayerEvals contains g_{i-1}(x_j) folded
		currentLayerEvals = make([]m31.QM31, f.circuitData.DedupedQueriesShape[logSize])

		// fold g_i evaluations from I_i to I_{i+1} (similar to folding over H_i to I_i but with line domains)
		for i, eval := range sparseEvaluation.evals {
			queryInitial := sparseEvaluation.queryInitials[i]
			domain := innerLayerVerifier.domain.Coset()
			queryInitialLE := uints.U32{queryInitial[3], queryInitial[2], queryInitial[1], queryInitial[0]}
			P := domain.IndexAt(queryInitialLE).Point()
			h0 := eval[0] // g_i(P) = g_i(x_i, y_i)
			h1 := eval[1] // g_i(-P) = g_i(x_i, -y_i)
			evenPart := f.qm31Chip.Add(h0, h1)
			inversePx, _ := f.m31Chip.Inverse(P.X) // x instead of y since we are in the line domain
			oddPart := f.qm31Chip.MulM31(f.qm31Chip.Sub(h0, h1), inversePx)
			folded := f.qm31Chip.Add(evenPart, f.qm31Chip.Mul(innerLayerVerifier.foldingAlpha, oddPart))
			currentLayerEvals[i] = folded
		}

		// update alpha
		previousAlpha = innerLayerVerifier.foldingAlpha

	}

	return currentLayerEvals
}

// ╔══════════════════════════════════╗
// ║            Last Layer            ║
// ╚══════════════════════════════════╝

// Verifies that the last layer evaluations are equal to the last layer polynomial coefficients
// This assumes the last layer is a constant polynomial
func (f *FriVerifier) verifyLastLayer(lastEvaluations []m31.QM31) {
	for _, eval := range lastEvaluations {
		f.qm31Chip.AssertEqual(eval, f.LastLayerPoly.Coeffs[0])
	}
}

// ╔══════════════════════════════════╗
// ║            Utilities             ║
// ╚══════════════════════════════════╝

func (f *FriVerifier) computeDecommitmentPositionsAndRebuildEvals(
	layerQueries []frontend.Variable,
	evalAtQueries []frontend.Variable,
	witnessEvals []m31.QM31,
	previousFriWitnessIndex int,
	layerQueriesShape int,
	logSize int,
) ([]frontend.Variable, []m31.M31, SparseEvaluations, int) {
	layerDecommitmentPositions := make([]frontend.Variable, 0)
	pairedEvalsFlattened := make([]m31.M31, 0)
	pairedEvals := make([][2]m31.QM31, 0)
	queryInitials := make([]uints.U32, 0)
	offset := 0
	witnessIndex := previousFriWitnessIndex
	if logSize <= 0 {
		panic("log size must be positive for decommitment branching")
	}
	if logSize-1 >= len(f.circuitData.QueriesBranching) {
		panic("queries branching missing layer data")
	}
	branching := f.circuitData.QueriesBranching[logSize-1]
	if layerQueriesShape > len(branching) {
		panic("queries branching length mismatch")
	}

	for i := 0; i < layerQueriesShape; i++ {
		base := offset + i

		// get the query initial (query >> 1)
		leftQuery := layerQueries[base]
		rightQuery := layerQueries[base+1]
		_ = rightQuery // keep access pattern parity even though branching is static
		queryU32 := f.uapi.ValueOf(leftQuery)
		queryInitialU32 := f.uapi.Rshift(queryU32, 1)
		queryInitial := f.uapi.ToValue(queryInitialU32)

		// compute and insert the query pair
		leftCandidate := f.api.Mul(queryInitial, frontend.Variable(2))
		rightCandidate := f.api.Add(leftCandidate, frontend.Variable(1))
		layerDecommitmentPositions = append(layerDecommitmentPositions, leftCandidate, rightCandidate)

		branchCode := branching[i]
		leftPresent := branchCode&1 == 1
		rightPresent := branchCode&2 == 2

		witness := f.qm31Chip.Zero()
		if !leftPresent || !rightPresent {
			witness = witnessEvals[witnessIndex]
			witnessIndex++
		}

		eval0Native := evalAtQueries[base]
		eval0 := f.qm31Chip.DecodeNative(eval0Native)
		eval1Native := evalAtQueries[base+1]
		eval1 := f.qm31Chip.DecodeNative(eval1Native)

		var leftEval m31.QM31
		var rightEval m31.QM31
		if leftPresent {
			leftEval = eval0
			if rightPresent {
				rightEval = eval1
			} else {
				rightEval = witness
			}
		} else {
			leftEval = witness
			rightEval = eval0
		}

		// update the offset
		if leftPresent && rightPresent {
			offset++
		}

		// flatten the evaluations into 4 M31 elements for use in the merkle decommitment verifier
		leftEvalComponents := leftEval.Components()
		pairedEvalsFlattened = append(pairedEvalsFlattened, leftEvalComponents[0], leftEvalComponents[1], leftEvalComponents[2], leftEvalComponents[3])
		rightEvalComponents := rightEval.Components()
		pairedEvalsFlattened = append(pairedEvalsFlattened, rightEvalComponents[0], rightEvalComponents[1], rightEvalComponents[2], rightEvalComponents[3])

		// append the paired evaluations to the list
		pairedEvals = append(pairedEvals, [2]m31.QM31{leftEval, rightEval})

		// build the sparse evaluations for the inner layer verifier
		queryInitials = append(queryInitials, f.reverseBitIndex(leftCandidate, logSize))
	}

	sparseEvaluation := SparseEvaluations{
		queryInitials: queryInitials,
		evals:         pairedEvals,
	}

	return layerDecommitmentPositions, pairedEvalsFlattened, sparseEvaluation, witnessIndex
}

func (f *FriVerifier) reverseBitIndex(n frontend.Variable, logSize int) uints.U32 {
	key := fmt.Sprintf("%v", n)
	nBits, ok := f.bitDecompCache[key]
	if !ok {
		nBits = bits.ToBinary(f.api, n, bits.WithNbDigits(32))
		f.bitDecompCache[key] = nBits
	}
	reversedBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		reversedBits[i] = nBits[32-(i+1)]
	}
	nReversedNative := bits.FromBinary(f.api, reversedBits)
	// no need to reduce since reversed bits has 32 bits by construction
	nReversed := f.uapi.ValueOf(nReversedNative)
	result := f.uapi.Rshift(nReversed, 32-logSize)
	return uints.U32{result[3], result[2], result[1], result[0]}
}
