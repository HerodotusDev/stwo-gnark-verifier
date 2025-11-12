package verifier

import (
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

	ch.MixRoot(byteArrayToHash(root))
	columnLogSizes := v.extendLogSizes(logSizes)
	v.trees[treeIndex] = fri.NewMerkleVerifier(v.api, root, columnLogSizes)
}

func (v *CommitmentSchemeVerifier) extendLogSizes(logSizes []uint32) []uint8 {
	if len(logSizes) == 0 {
		return nil
	}
	blowup := byteValue(v.pcsConfig.FriConfig.LogBlowupFactor[0])
	out := make([]uint8, len(logSizes))
	for i, size := range logSizes {
		out[i] = uint8(size) + blowup
	}
	return out
}

// TODO: byteValue is meant to be removed once CairoClaim is updated to use uint8 instead of uints.U8
func byteValue(value uints.U8) uint8 {
	switch v := value.Val.(type) {
	case uint8:
		return v
	case uint16:
		return uint8(v)
	case uint32:
		return uint8(v)
	case uint64:
		return uint8(v)
	case int:
		return uint8(v)
	default:
		panic("unsupported byte representation")
	}
}

func byteArrayToHash(bytes [32]uints.U8) channel.Blake2sHash {
	var hash channel.Blake2sHash
	for i := 0; i < len(hash); i++ {
		offset := i * 4
		b0 := uint32(byteValue(bytes[offset]))
		b1 := uint32(byteValue(bytes[offset+1]))
		b2 := uint32(byteValue(bytes[offset+2]))
		b3 := uint32(byteValue(bytes[offset+3]))
		word := b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
		hash[i] = uints.NewU32(word)
	}
	return hash
}
