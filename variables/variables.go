package variables

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

const (
	PREPROCESSED_IDX = 0
	MAIN_IDX         = 1
	INTERACTION_IDX  = 2
	CP_IDX           = 3
)

type StarkProof struct {
	Claim             CairoClaim
	InteractionClaims CairoInteractionClaim
	SampledValues     [][][]m31.QM31
}

type CairoInteractionElements struct {
	MemoryAddressToId m31.InteractionElements
}

type CairoClaim struct {
	MemoryAddressToId uint32
}

type CairoInteractionClaim struct {
	MemoryAddressToId m31.QM31
}
