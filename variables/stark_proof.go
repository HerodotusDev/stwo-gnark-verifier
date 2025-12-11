package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║         Structure Types          ║
// ╚══════════════════════════════════╝

// StarkProof is the proof emitted by the Stwo Backend
type StarkProof struct {
	// Commitments are the four commmitment roots. len(Commitments) = 4.
	Commitments [][32]uints.U8
	// SampledValues are the sampled values for each column of each tree.
	// len(sampledValues) = 4. len(sampledValues[tree]) = number of columns in the tree.
	// There can be up to 2 values per column (at OODS-1 and OODS for the 4 last interaction columns of a component).
	SampledValues [][][]m31.QM31
	// QueriedValues are the column values queried for the decommitment of the four merkle commitments.
	// len(queriedValues) = 4.
	// len(queriedValues[tree]) = sum for each log size of the number of columns of that log size times the number of deduped queries for that layer.
	QueriedValues [][]m31.M31
	// Decommitments are the decommitments for the four merkle commitments. len(decommitments) = 4.
	Decommitments []MerkleDecommitment
	// FriProof contains the FRI proof data.
	FriProof FriProof
	// ProofOfWork is the FRI proof of work (done by the prover after committing to the FRI layers)
	ProofOfWork uints.U64
}

// MerkleDecommitment stores the witness bytes and column values emitted by the prover.
type MerkleDecommitment struct {
	// HashWitness is a stack containing the hash values of nodes required to compute the parent one.
	HashWitness [][32]uints.U8
	// ColumnWitness is unused and could be removed. It is introduced in stwo to have a generic merkle decommitment so that a verifier can
	// ask only for certain column values. However, in practice all columns need to be queried to build the FRI answers.
	ColumnWitness []m31.M31
}

// FriProof stores the FRI proof data
type FriProof struct {
	// FirstLayerProof is the FRI proof for the first layer.
	FirstLayerProof FriLayerProof
	// InnerLayerProofs contains the FRI proofs for the inner layers.
	InnerLayerProofs []FriLayerProof
	// LastLayerPoly is the FRI proof for the last layer which is just a constant polynomial.
	LastLayerPoly circle.LinePoly
}

// FriLayerProof stores the FRI layer proof data
type FriLayerProof struct {
	// Used for layers containing fri answers to get the sibling value of a given query.
	// Typically we might have f(x) but we also need f(-x) for FRI, this accounts for that.
	FriWitness []m31.QM31
	// Decommitment is the decommitment for the FRI layer merkle commitment.
	Decommitment MerkleDecommitment
	// Commitment is the commitment to the FRI layer.
	Commitment [32]uints.U8
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildStarkProof builds a StarkProof from its raw representation.
func BuildStarkProof(starkProofRaw *StarkProofRaw) StarkProof {
	if starkProofRaw == nil {
		return StarkProof{}
	}

	return StarkProof{
		Commitments:   buildCommitments(starkProofRaw.Commitments),
		SampledValues: buildSampledValues(starkProofRaw.SampledValues),
		QueriedValues: buildQueriedValues(starkProofRaw.QueriedValues),
		Decommitments: buildDecommitments(starkProofRaw.Decommitments),
		FriProof:      buildFriProof(starkProofRaw.FriProof),
		ProofOfWork:   uints.NewU64(starkProofRaw.ProofOfWork),
	}
}

func buildCommitments(raw [][]uint8) [][32]uints.U8 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][32]uints.U8, len(raw))
	for i, entry := range raw {
		if len(entry) != 32 {
			panic("commitment root must be 32 bytes")
		}
		var root [32]uints.U8
		for j, b := range entry {
			root[j] = uints.NewU8(b)
		}
		result[i] = root
	}

	return result
}

func buildSampledValues(raw SampledValuesRaw) [][][]m31.QM31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][][]m31.QM31, len(raw))
	for domainIdx, columns := range raw {
		if len(columns) == 0 {
			continue
		}

		domainValues := make([][]m31.QM31, len(columns))
		for columnIdx, evaluations := range columns {
			if len(evaluations) == 0 {
				continue
			}

			columnValues := make([]m31.QM31, 0, len(evaluations))
			for _, entry := range evaluations {
				columnValues = append(columnValues, m31.NewQM31FromArrays(entry))
			}
			domainValues[columnIdx] = columnValues
		}
		result[domainIdx] = domainValues
	}

	return result
}

func buildQueriedValues(raw [][]uint64) [][]m31.M31 {
	if len(raw) == 0 {
		return nil
	}

	result := make([][]m31.M31, len(raw))
	for groupIdx, group := range raw {
		if len(group) == 0 {
			continue
		}

		result[groupIdx] = convertUintSliceToM31(group)
	}

	return result
}

func buildDecommitments(raw []MerkleDecommitmentRaw) []MerkleDecommitment {
	if len(raw) == 0 {
		return nil
	}

	result := make([]MerkleDecommitment, len(raw))
	for i, entry := range raw {
		result[i] = MerkleDecommitment{
			HashWitness:   buildHashWitness(entry.HashWitness),
			ColumnWitness: convertUintSliceToM31(entry.ColumnWitness),
		}
	}

	return result
}

func buildHashWitness(raw [][]uint8) [][32]uints.U8 {
	if len(raw) == 0 {
		return nil
	}

	hashes := make([][32]uints.U8, len(raw))
	for i, bytes := range raw {
		var hash [32]uints.U8
		for j := 0; j < len(hash) && j < len(bytes); j++ {
			hash[j] = uints.NewU8(bytes[j])
		}
		hashes[i] = hash
	}

	return hashes
}

func buildFriProof(raw FriProofRaw) FriProof {
	return FriProof{
		FirstLayerProof:  buildFirstLayerProof(raw.FirstLayerProof),
		InnerLayerProofs: buildInnerLayerProofs(raw.InnerLayerProofs),
		LastLayerPoly:    buildLastLayerPoly(raw.LastLayerPoly),
	}
}

func buildFirstLayerProof(raw FriLayerProofRaw) FriLayerProof {
	firstLayerProof := buildInnerLayerProof(raw)
	return firstLayerProof
}

func buildInnerLayerProofs(raw []FriLayerProofRaw) []FriLayerProof {
	result := make([]FriLayerProof, len(raw))
	for i, entry := range raw {
		result[i] = buildInnerLayerProof(entry)
	}
	return result
}

func buildInnerLayerProof(raw FriLayerProofRaw) FriLayerProof {
	friWitness := make([]m31.QM31, len(raw.FriWitness))
	for i, entry := range raw.FriWitness {
		friWitness[i] = m31.NewQM31FromArrays(entry)
	}

	decommitment := buildDecommitments([]MerkleDecommitmentRaw{raw.Decommitment})[0]

	commitment := buildCommitments([][]uint8{raw.Commitment})[0]
	return FriLayerProof{
		FriWitness:   friWitness,
		Decommitment: decommitment,
		Commitment:   commitment,
	}
}

func buildLastLayerPoly(raw LinePolyRaw) circle.LinePoly {
	coeffs := m31.NewQM31FromArrays(raw.Coeffs[0])
	return circle.LinePoly{
		Coeffs:  []m31.QM31{coeffs},
		LogSize: uints.NewU8(raw.LogSize),
	}
}
