package fri

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	bapi        *uints.Bytes
	m31Chip     *m31.M31Chip
	blake2sChip *blake2s.Blake2sChip
	cmpU32      *cmp.BoundedComparator
	PcsConfig   variables.PcsConfig
	Trees       [cairo_components.N_TREES]*MerkleVerifier
	circuitData variables.CircuitData
}

// NewCommitmentSchemeVerifier initializes the commitment scheme verifier.
func NewCommitmentSchemeVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], pcsConfig variables.PcsConfig, circuitData variables.CircuitData) *CommitmentSchemeVerifier {
	// Backward-compatible constructor: create per-instance chips.
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}
	m31Chip := m31.NewM31Chip(api)
	blake2sChip := blake2s.NewBlake2sChip(api)
	cmpU32 := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)

	return NewCommitmentSchemeVerifierWithChips(api, uapi, bapi, m31Chip, blake2sChip, cmpU32, pcsConfig, circuitData)
}

// NewCommitmentSchemeVerifierWithChips initializes the commitment scheme verifier using shared chip instances.
func NewCommitmentSchemeVerifierWithChips(api frontend.API, uapi *uints.BinaryField[uints.U32], bapi *uints.Bytes, m31Chip *m31.M31Chip, blake2sChip *blake2s.Blake2sChip, cmpU32 *cmp.BoundedComparator, pcsConfig variables.PcsConfig, circuitData variables.CircuitData) *CommitmentSchemeVerifier {
	return &CommitmentSchemeVerifier{
		api:         api,
		uapi:        uapi,
		bapi:        bapi,
		m31Chip:     m31Chip,
		blake2sChip: blake2sChip,
		cmpU32:      cmpU32,
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
	// NOTE: This hardcodes the blowup factor to 1 for now
	nColumnsPerLogSize := v.circuitData.NColumnsPerLogSize[treeIndex]
	nDomainPerLogSize := make([]int, len(nColumnsPerLogSize)+1)
	for i, nColumns := range nColumnsPerLogSize {
		nDomainPerLogSize[i+1] = nColumns
	}
	v.Trees[treeIndex] = NewMerkleVerifierWithChips(v.api, v.uapi, v.bapi, v.m31Chip, v.blake2sChip, root, columnLogSizes, nDomainPerLogSize)
}

// ColumnLogSizes returns the column log sizes for the given tree (and optionally blew up)
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

// Bounds returns the deduplicated and ordered column bounds
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
	utils.AssertDescendingOrder(v.cmpU32, dedupedOrderedLogSizes)
	utils.AssertDeduplicationSoundness(v.api, dedupedOrderedLogSizes, columnLogSizesFlattened)
	return dedupedOrderedLogSizes
}
