package cairo_components

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type MemoryIdToValueInteractionClaim struct {
	BigClaimedSums  []m31.QM31
	SmallClaimedSum m31.QM31
}
