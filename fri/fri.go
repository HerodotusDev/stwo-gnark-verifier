package fri

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

type FriVerifier struct {
	api                 frontend.API
	friConfig           FriConfig
	FirstLayerVerifier  FriFirstLayerVerifier
	InnerLayerVerifiers []FriInnerLayerVerifier
	LastLayerPoly       circle.LinePoly
}

type FriFirstLayerVerifier struct {
	columnBounds            []uint8
	columnCommitmentDomains []circle.CanonicCoset
	proof                   variables.FriLayerProof
	foldingAlpha            m31.QM31
}

type FriInnerLayerVerifier struct {
	degreeBound uint8
	//domain       circle.LineDomain
	foldingAlpha m31.QM31
	layerIndex   int
	proof        variables.FriLayerProof
}

func NewFriVerifier(api frontend.API, channelChip *channel.Channel, circleChip *circle.CircleChip, friConfig FriConfig, friProof variables.FriProof, bounds []uint8) *FriVerifier {
	// First layer commitment
	channelChip.MixRootBytes(friProof.FirstLayerProof.Commitment[:])

	// First layer verifier
	columncommitmentDomains := make([]circle.CanonicCoset, len(bounds))
	for i, bound := range bounds {
		columncommitmentDomains[i] = circleChip.NewCanonicCoset(uint32(bound + friConfig.LogBlowupFactor))
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
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
	}
}

func (f *FriVerifier) GenerateBaseLayerQueries(channelChip *channel.Channel, uapi *uints.BinaryField[uints.U32], nQueries uint8) []frontend.Variable {
	maxLogSize := f.FirstLayerVerifier.columnBounds[0]
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
