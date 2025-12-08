package fri

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// FriConfig mirrors the prover-side configuration for the FRI protocol.
type FriConfig struct {
	LogBlowupFactor         frontend.Variable
	LogLastLayerDegreeBound uint8
	NQueries                uint8
}

var zero = uints.NewU8(0)

// MixInto absorbs the FRI configuration words into the Fiat-Shamir channel.
func (cfg FriConfig) MixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32]) {
	ch.MixU32s([]uints.U32{uapi32.ValueOf(cfg.LogBlowupFactor), uints.NewU32(0)})
	ch.MixU64(uints.U64{uints.NewU8(cfg.NQueries), zero, zero, zero, zero, zero, zero, zero})
	ch.MixU64(uints.U64{uints.NewU8(cfg.LogLastLayerDegreeBound), zero, zero, zero, zero, zero, zero, zero})
}

// PcsConfig stores the polynomial commitment scheme parameters.
// TODO: known right after VM execution so should be a constant
type PcsConfig struct {
	PowBits   uint8
	FriConfig FriConfig
}

// MixInto feeds the PCS configuration into the channel transcript.
func (cfg PcsConfig) MixInto(ch *channel.Channel, uapi32 *uints.BinaryField[uints.U32]) {
	ch.MixU64(uints.U64{uints.NewU8(cfg.PowBits), zero, zero, zero, zero, zero, zero, zero})
	cfg.FriConfig.MixInto(ch, uapi32)
}

// DefaultPcsConfig returns the canonical PCS configuration used by the prover.
func DefaultPcsConfig() PcsConfig {
	return PcsConfig{
		PowBits: 26,
		FriConfig: FriConfig{
			LogBlowupFactor:         frontend.Variable(1),
			LogLastLayerDegreeBound: 0,
			NQueries:                10,
		},
	}
}
