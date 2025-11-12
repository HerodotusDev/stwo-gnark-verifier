package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/consensys/gnark/std/math/uints"
)

// FriConfig mirrors the prover-side configuration for the FRI protocol.
type FriConfig struct {
	LogBlowupFactor         uints.U32
	LogLastLayerDegreeBound uints.U32
	NQueries                uints.U32
}

var zero = uints.NewU8(0)

// MixInto absorbs the FRI configuration words into the Fiat-Shamir channel.
func (cfg FriConfig) MixInto(ch *channel.Channel) {
	ch.MixU64(uints.U64{cfg.LogBlowupFactor[0], cfg.LogBlowupFactor[1], cfg.LogBlowupFactor[2], cfg.LogBlowupFactor[3], zero, zero, zero, zero})
	ch.MixU64(uints.U64{cfg.NQueries[0], cfg.NQueries[1], cfg.NQueries[2], cfg.NQueries[3], zero, zero, zero, zero})
	ch.MixU64(uints.U64{cfg.LogLastLayerDegreeBound[0], cfg.LogLastLayerDegreeBound[1], cfg.LogLastLayerDegreeBound[2], cfg.LogLastLayerDegreeBound[3], zero, zero, zero, zero})
}

// PcsConfig stores the polynomial commitment scheme parameters.
// TODO: known right after VM execution so should be a constant
type PcsConfig struct {
	PowBits   uints.U32
	FriConfig FriConfig
}

// MixInto feeds the PCS configuration into the channel transcript.
func (cfg PcsConfig) MixInto(ch *channel.Channel) {
	ch.MixU64(uints.U64{cfg.PowBits[0], cfg.PowBits[1], cfg.PowBits[2], cfg.PowBits[3], zero, zero, zero, zero})
	cfg.FriConfig.MixInto(ch)
}

// DefaultPcsConfig returns the canonical PCS configuration used by the prover.
func DefaultPcsConfig() PcsConfig {
	return PcsConfig{
		PowBits: uints.NewU32(26),
		FriConfig: FriConfig{
			LogBlowupFactor:         uints.NewU32(1),
			LogLastLayerDegreeBound: uints.NewU32(0),
			NQueries:                uints.NewU32(10),
		},
	}
}
