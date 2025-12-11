package variables

import (
	"encoding/json"
	"io"
	"os"

	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║         Structure Types          ║
// ╚══════════════════════════════════╝

// Proof is the proof emitted by the Stwo-Cairo
type Proof struct {
	Claim            CairoClaim
	InteractionPow   uints.U64
	InteractionClaim CairoInteractionClaim
	StarkProof       StarkProof
}

// ╔══════════════════════════════════╗
// ║              Reading             ║
// ╚══════════════════════════════════╝

// ReadCairoProof loads a Cairo proof from the given path.
func ReadCairoProof(path string) (*ProofRaw, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return readCairoProofFromReader(file)
}

// ReadCairoProofFromReader decodes a Cairo proof from the supplied reader.
func readCairoProofFromReader(r io.Reader) (*ProofRaw, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var proof ProofRaw
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}

	return &proof, nil
}

// ╔══════════════════════════════════╗
// ║             Building             ║
// ╚══════════════════════════════════╝

// BuildProof builds a Proof (used in circuits) from a ProofRaw (from json)
func BuildProof(proofRaw ProofRaw) Proof {
	var proof Proof

	proof.Claim = BuildClaim(&proofRaw.Claim)
	proof.InteractionPow = uints.NewU64(proofRaw.InteractionPow)
	proof.InteractionClaim = BuildInteractionClaim(&proofRaw.InteractionClaim)
	proof.StarkProof = BuildStarkProof(&proofRaw.StarkProof)

	return proof
}
