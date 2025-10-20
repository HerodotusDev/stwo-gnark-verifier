package variables

import (
	"encoding/json"
	"io"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

// ╔══════════════════════════════════╗
// ║          Proof Reading           ║
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

	return ReadCairoProofFromReader(file)
}

// ReadCairoProofFromReader decodes a Cairo proof from the supplied reader.
func ReadCairoProofFromReader(r io.Reader) (*ProofRaw, error) {
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
// ║        Proof Construction        ║
// ╚══════════════════════════════════╝

// ConstructProof constructs a StarkProof (used in circuits) from a ProofRaw (from json)
func ConstructProof(proofRaw *ProofRaw) *StarkProof {
	if proofRaw == nil {
		return nil
	}

	var proof StarkProof

	proof.Claim = ConstructClaim(&proofRaw.Claim)
	proof.InteractionClaims = ConstructInteractionClaims(&proofRaw.InteractionClaim)

	// TODO: Construct StarkProof from StarkProofRaw

	return &proof
}

// ConstructClaim constructs a CairoClaim from a ClaimRaw
func ConstructClaim(claimRaw *ClaimRaw) CairoClaim {
	if claimRaw == nil {
		return CairoClaim{}
	}

	var claim CairoClaim

	claim.MemoryAddressToId = cairo_components.MemoryAddressToIdClaim{LogSize: uints.NewU8(uint8(claimRaw.MemoryAddressToId.LogSize))}

	return claim
}

// ConstructInteractionClaims constructs a CairoInteractionClaim from a InteractionClaimRaw
func ConstructInteractionClaims(interactionClaimRaw *InteractionClaimRaw) CairoInteractionClaim {
	if interactionClaimRaw == nil {
		return CairoInteractionClaim{}
	}

	var interactionClaim CairoInteractionClaim

	interactionClaim.MemoryAddressToId = cairo_components.MemoryIDToValueInteractionClaim{ClaimedSum: m31.NewQM31FromArrays(interactionClaimRaw.MemoryAddressToId.ClaimedSum)}

	return interactionClaim
}
