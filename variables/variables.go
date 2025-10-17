package variables

import (
	cairo_components "github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
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
	MemoryAddressToId cairo_components.MemoryAddressToIdClaim
}

type CairoInteractionClaim struct {
	MemoryAddressToId cairo_components.MemoryIDToValueInteractionClaim
}
