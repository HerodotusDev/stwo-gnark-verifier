package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	PcsConfig   PcsConfig
	Trees       [cairo_components.N_TREES]*MerkleVerifier
	circuitData variables.CircuitData
}

// NewCommitmentSchemeVerifier initializes the commitment scheme verifier.
func NewCommitmentSchemeVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], pcsConfig PcsConfig, circuitData variables.CircuitData) *CommitmentSchemeVerifier {
	return &CommitmentSchemeVerifier{
		api:         api,
		uapi:        uapi,
		PcsConfig:   pcsConfig,
		circuitData: circuitData,
	}
}

// Commit mixes the Merkle root into the channel and stores the verifier for the tree.
func (v *CommitmentSchemeVerifier) Commit(treeIndex int, root [32]uints.U8, logSizes []frontend.Variable, ch *channel.Channel) {
	if treeIndex < 0 || treeIndex >= len(v.Trees) {
		panic("invalid tree index")
	}
	if ch == nil {
		panic("channel must not be nil")
	}

	ch.MixRootBytes(root[:])
	columnLogSizes := utils.BlowupLogSizes(v.api, logSizes, v.PcsConfig.FriConfig.LogBlowupFactor)
	v.Trees[treeIndex] = NewMerkleVerifier(v.api, v.uapi, root, columnLogSizes, v.circuitData.NColumnsPerLogSize[treeIndex])
}

func (v *CommitmentSchemeVerifier) ColumnLogSizes(blowup bool) [][]frontend.Variable {
	columnLogSizes := make([][]frontend.Variable, 4)
	for treeIndex, merkleVerifier := range v.Trees {
		if blowup {
			blewupColumnLogSizes := make([]frontend.Variable, len(merkleVerifier.ColumnLogSizes))
			for i, logSize := range merkleVerifier.ColumnLogSizes {
				blewupColumnLogSizes[i] = v.api.Add(logSize, v.PcsConfig.FriConfig.LogBlowupFactor)
			}
			columnLogSizes[treeIndex] = blewupColumnLogSizes
		} else {
			columnLogSizes[treeIndex] = merkleVerifier.ColumnLogSizes
		}
	}
	return columnLogSizes
}

func (v *CommitmentSchemeVerifier) Bounds() []frontend.Variable {
	columnLogSizes := v.ColumnLogSizes(false)
	columnLogSizesFlattened := utils.FlattenTree(columnLogSizes)
	dedupedLogSizes, err := v.api.Compiler().NewHint(utils.DeduplicationHint, v.circuitData.BoundsLength, columnLogSizesFlattened...)
	if err != nil {
		panic(err)
	}
	dedupedOrderedLogSizes, err := v.api.Compiler().NewHint(utils.DescendingOrderHint, v.circuitData.BoundsLength, dedupedLogSizes...)
	if err != nil {
		panic(err)
	}
	utils.AssertDescendingOrder(v.api, dedupedOrderedLogSizes)
	utils.AssertPartialDeduplication(v.api, dedupedOrderedLogSizes, columnLogSizesFlattened)
	return dedupedOrderedLogSizes
}
