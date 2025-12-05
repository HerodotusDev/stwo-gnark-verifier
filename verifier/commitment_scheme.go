package verifier

import (
	"math/big"
	"sort"

	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

func init() {
	solver.RegisterHint(DedupplicationHint)
	solver.RegisterHint(OrderingHint)
}

// CommitmentSchemeVerifier mirrors the prover-side Merkle commitment verifier.
type CommitmentSchemeVerifier struct {
	api         frontend.API
	uapi        *uints.BinaryField[uints.U32]
	pcsConfig   fri.PcsConfig
	trees       [cairo_components.N_TREES]*fri.MerkleVerifier
	circuitData variables.CircuitData
}

// NewCommitmentSchemeVerifier initializes the commitment scheme verifier.
func NewCommitmentSchemeVerifier(api frontend.API, uapi *uints.BinaryField[uints.U32], pcsConfig fri.PcsConfig, circuitData variables.CircuitData) *CommitmentSchemeVerifier {
	return &CommitmentSchemeVerifier{
		api:         api,
		uapi:        uapi,
		pcsConfig:   pcsConfig,
		circuitData: circuitData,
	}
}

// Commit mixes the Merkle root into the channel and stores the verifier for the tree.
func (v *CommitmentSchemeVerifier) Commit(treeIndex int, root [32]uints.U8, logSizes []frontend.Variable, ch *channel.Channel) {
	if treeIndex < 0 || treeIndex >= len(v.trees) {
		panic("invalid tree index")
	}
	if ch == nil {
		panic("channel must not be nil")
	}

	ch.MixRootBytes(root[:])
	columnLogSizes := v.blowupLogSizes(logSizes)
	v.trees[treeIndex] = fri.NewMerkleVerifier(v.api, v.uapi, root, columnLogSizes)
}

func (v *CommitmentSchemeVerifier) blowupLogSizes(logSizes []frontend.Variable) []frontend.Variable {
	if len(logSizes) == 0 {
		return nil
	}
	out := make([]frontend.Variable, len(logSizes))
	for i, size := range logSizes {
		out[i] = v.api.Add(size, v.pcsConfig.FriConfig.LogBlowupFactor)
	}
	return out
}

func (v *CommitmentSchemeVerifier) columnLogSizes(blowup bool) [][]frontend.Variable {
	columnLogSizes := make([][]frontend.Variable, 4)
	for treeIndex, merkleVerifier := range v.trees {
		if blowup {
			blewupColumnLogSizes := make([]frontend.Variable, len(merkleVerifier.ColumnLogSizes))
			for i, logSize := range merkleVerifier.ColumnLogSizes {
				blewupColumnLogSizes[i] = v.api.Add(logSize, v.pcsConfig.FriConfig.LogBlowupFactor)
			}
			columnLogSizes[treeIndex] = blewupColumnLogSizes
		} else {
			columnLogSizes[treeIndex] = merkleVerifier.ColumnLogSizes
		}
	}
	return columnLogSizes
}

func U32SliceToNativeSlice(api frontend.API, uapi *uints.BinaryField[uints.U32], l []uints.U32) []frontend.Variable {
	out := make([]frontend.Variable, len(l))
	for i, e := range l {
		out[i] = uapi.ToValue(e)
	}
	return out
}

func (v *CommitmentSchemeVerifier) bounds() []frontend.Variable {
	columnLogSizes := v.columnLogSizes(true)
	columnLogSizesFlattened := cairo_components.FlattenTree(columnLogSizes)
	dedupedLogSizes, err := v.api.Compiler().NewHint(DedupplicationHint, v.circuitData.BoundsLength, columnLogSizesFlattened...)
	if err != nil {
		panic(err)
	}
	dedupedOrderedLogSizes, err := v.api.Compiler().NewHint(OrderingHint, v.circuitData.BoundsLength, dedupedLogSizes...)
	if err != nil {
		panic(err)
	}
	AssertAscendingOrder(v.api, dedupedOrderedLogSizes)
	AssertPartialDeduplication(v.api, dedupedOrderedLogSizes, columnLogSizesFlattened)
	bounds := make([]frontend.Variable, len(dedupedOrderedLogSizes))
	for i, e := range dedupedOrderedLogSizes {
		bounds[i] = v.uapi.ValueOf(e)
	}
	return bounds
}

func DedupplicationHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	seen := make(map[string]bool)
	unique := make([]*big.Int, 0)
	for _, e := range inputs {
		key := e.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}
	for i := 0; i < len(results) && i < len(unique); i++ {
		results[i] = new(big.Int).Set(unique[i])
	}
	return nil
}

func OrderingHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Cmp(inputs[j]) < 0 })
	for i := 0; i < len(results) && i < len(inputs); i++ {
		results[i] = new(big.Int).Set(inputs[i])
	}
	return nil
}

// AssertAscendingOrder verifies that `l` is in ascending order (elements need to be less than 1<<32)
func AssertAscendingOrder(api frontend.API, l []frontend.Variable) {
	cmp := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)
	for i := 1; i < len(l); i++ {
		cmp.AssertIsLess(l[i-1], l[i])
	}
}

// AssertPermutation verifies that `permuted` is a permutation of `original`
// To check that permuted is a permutation of original,
// we compare the grand products evaluated on a point drawn
// from a new channel after mixing the permuted slice.
func AssertPermutation(api frontend.API, permuted []frontend.Variable, original []frontend.Variable) {
	// Instantiate a new channel
	channel := channel.NewChannel(api)

	// Convert the hinted queries to bytes
	permutedBytes := make([]uints.U8, 0)
	for _, e := range permuted {
		bytes, err := conversion.NativeToBytes(api, e)
		if err != nil {
			panic(err)
		}
		permutedBytes = append(permutedBytes, bytes[len(bytes)-4:]...)
	}

	// Mix the permuted slice into the channel
	channel.MixRootBytes(permutedBytes)

	// Build a random 248-bit (31 bytes) point from the channel
	randomBytes := channel.DrawRandomBytes()
	point, err := conversion.BytesToNative(api, randomBytes[:31])
	if err != nil {
		panic(err)
	}

	// Evaluate the grand products
	grandProductPermuted := frontend.Variable(1)
	for _, e := range permuted {
		grandProductPermuted = api.Mul(grandProductPermuted, api.Add(e, point))
	}
	grandProductOriginal := frontend.Variable(1)
	for _, e := range original {
		grandProductOriginal = api.Mul(grandProductOriginal, api.Add(e, point))
	}

	// Check that the grand products are equal
	api.AssertIsEqual(grandProductPermuted, grandProductOriginal)
}

// AssertPartialDeduplication verifies that `partiallyDeduplicated` contains all elements of `original` but
// appearing less or as many times as in `original`.
// We check that all elements of original are roots of the polynomial that vanishes on the elements of partiallyDeduplicated.
func AssertPartialDeduplication(api frontend.API, partiallyDeduplicated []frontend.Variable, original []frontend.Variable) {
	for _, e := range original {
		prod := frontend.Variable(1)
		for _, d := range partiallyDeduplicated {
			prod = api.Mul(prod, api.Sub(d, e))
		}
		api.AssertIsEqual(prod, frontend.Variable(0))
	}
}
