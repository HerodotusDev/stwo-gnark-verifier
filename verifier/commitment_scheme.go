package verifier

import (
	"sort"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api       frontend.API
	pcsConfig fri.PcsConfig
	trees     [cairo_components.N_TREES]*fri.MerkleVerifier
}

// NewCommitmentSchemeVerifier initializes the commitment scheme verifier.
func NewCommitmentSchemeVerifier(api frontend.API, pcsConfig fri.PcsConfig) *CommitmentSchemeVerifier {
	return &CommitmentSchemeVerifier{
		api:       api,
		pcsConfig: pcsConfig,
	}
}

// Commit mixes the Merkle root into the channel and stores the verifier for the tree.
func (v *CommitmentSchemeVerifier) Commit(treeIndex int, root [32]uints.U8, logSizes []uint32, ch *channel.Channel) {
	if treeIndex < 0 || treeIndex >= len(v.trees) {
		panic("invalid tree index")
	}
	if ch == nil {
		panic("channel must not be nil")
	}

	ch.MixRootBytes(root[:])
	columnLogSizes := v.extendLogSizes(logSizes)
	v.trees[treeIndex] = fri.NewMerkleVerifier(v.api, root, columnLogSizes)
}

func (v *CommitmentSchemeVerifier) extendLogSizes(logSizes []uint32) []uint8 {
	if len(logSizes) == 0 {
		return nil
	}
	blowup := v.pcsConfig.FriConfig.LogBlowupFactor
	out := make([]uint8, len(logSizes))
	for i, size := range logSizes {
		out[i] = uint8(size) + blowup
	}
	return out
}

func (v *CommitmentSchemeVerifier) columnLogSizes() [][]uint8 {
	columnLogSizes := make([][]uint8, 4)
	for treeIndex, merkleVerifier := range v.trees {
		columnLogSizes[treeIndex] = merkleVerifier.ColumnLogSizes
	}
	return columnLogSizes
}

func (v *CommitmentSchemeVerifier) bounds() []uint8 {
	uniqueBounds := make(map[uint8]struct{})
	for _, columnLogSizes := range v.columnLogSizes() {
		for _, columnLogSize := range columnLogSizes {
			uniqueBounds[columnLogSize-v.pcsConfig.FriConfig.LogBlowupFactor] = struct{}{}
		}
	}
	bounds := make([]uint8, 0, len(uniqueBounds))
	for bound := range uniqueBounds {
		bounds = append(bounds, bound)
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] > bounds[j] })
	return bounds
}
