package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
)

type FriVerifier struct {
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

func NewFriVerifier(channelChip *channel.Channel, circleChip *circle.CircleChip, friConfig FriConfig, friProof variables.FriProof, bounds []uint8) *FriVerifier {
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
		friConfig:           friConfig,
		FirstLayerVerifier:  firstLayerVerifier,
		InnerLayerVerifiers: innerLayerVerifiers,
		LastLayerPoly:       friProof.LastLayerPoly,
	}
}
