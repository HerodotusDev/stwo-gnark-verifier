package variables

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
)

// MixInto absorbs the Cairo interaction claim into the transcript channel.
func (claim CairoInteractionClaim) MixInto(ch *channel.Channel) {
	claim.Opcodes.mixInto(ch)
	ch.MixFelts([]m31.QM31{claim.VerifyInstruction.ClaimedSum})
	claim.BlakeContext.mixInto(ch)
	claim.Builtins.mixInto(ch)
	claim.PedersenContext.mixInto(ch)
	claim.PoseidonContext.mixInto(ch)
	ch.MixFelts([]m31.QM31{claim.MemoryAddressToId.ClaimedSum})
	mixMemoryIdToValueInteractionClaim(ch, claim.MemoryIDToValue)
	claim.RangeChecks.mixInto(ch)
	ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor4.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor7.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor8.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.VerifyBitwiseXor9.ClaimedSum})
}

func (claims OpcodeInteractionClaim) mixInto(ch *channel.Channel) {
	for _, entry := range claims.Add {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.AddSmall {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.AddAp {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.AssertEq {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.AssertEqImm {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.AssertEqDoubleDeref {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Blake {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Call {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.CallRelImm {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Generic {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Jnz {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.JnzTaken {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Jump {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.JumpDoubleDeref {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.JumpRel {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.JumpRelImm {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Mul {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.MulSmall {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Qm31 {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
	for _, entry := range claims.Ret {
		ch.MixFelts([]m31.QM31{entry.ClaimedSum})
	}
}

func (claim BlakeContextInteractionClaim) mixInto(ch *channel.Channel) {
	if claim.InteractionClaim == nil {
		return
	}
	sub := claim.InteractionClaim
	ch.MixFelts([]m31.QM31{sub.BlakeRound.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.BlakeG.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.BlakeRoundSigma.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.TripleXor32.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.VerifyBitwiseXor12.ClaimedSum})
}

func (claim BuiltinsInteractionClaim) mixInto(ch *channel.Channel) {
	if claim.AddModBuiltin != nil {
		ch.MixFelts([]m31.QM31{claim.AddModBuiltin.ClaimedSum})
	}
	if claim.BitwiseBuiltin != nil {
		ch.MixFelts([]m31.QM31{claim.BitwiseBuiltin.ClaimedSum})
	}
	if claim.MulModBuiltin != nil {
		ch.MixFelts([]m31.QM31{claim.MulModBuiltin.ClaimedSum})
	}
	if claim.PedersenBuiltin != nil {
		ch.MixFelts([]m31.QM31{claim.PedersenBuiltin.ClaimedSum})
	}
	if claim.PoseidonBuiltin != nil {
		ch.MixFelts([]m31.QM31{claim.PoseidonBuiltin.ClaimedSum})
	}
	if claim.RangeCheck96 != nil {
		ch.MixFelts([]m31.QM31{claim.RangeCheck96.ClaimedSum})
	}
	if claim.RangeCheck128 != nil {
		ch.MixFelts([]m31.QM31{claim.RangeCheck128.ClaimedSum})
	}
}

func (claim PedersenContextInteractionClaim) mixInto(ch *channel.Channel) {
	if claim.InteractionClaim == nil {
		return
	}
	sub := claim.InteractionClaim
	ch.MixFelts([]m31.QM31{sub.PartialEcMul.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.PedersenPointsTable.ClaimedSum})
}

func (claim PoseidonContextInteractionClaim) mixInto(ch *channel.Channel) {
	if claim.InteractionClaim == nil {
		return
	}
	sub := claim.InteractionClaim
	ch.MixFelts([]m31.QM31{sub.Poseidon3PartialRoundsChain.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.PoseidonFullRoundChain.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.Cube252.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.PoseidonRoundKeys.ClaimedSum})
	ch.MixFelts([]m31.QM31{sub.RangeCheckFelt252Width27.ClaimedSum})
}

func (claim RangeChecksInteractionClaim) mixInto(ch *channel.Channel) {
	ch.MixFelts([]m31.QM31{claim.RC6.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC8.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC11.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC12.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC18.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC19.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC4_3.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC4_4.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC5_4.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC9_9.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC7_2_5.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC3_6_6_3.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC4_4_4_4.ClaimedSum})
	ch.MixFelts([]m31.QM31{claim.RC3_3_3_3_3.ClaimedSum})
}

func mixMemoryIdToValueInteractionClaim(ch *channel.Channel, claim cairo_components.MemoryIdToValueInteractionClaim) {
	if len(claim.BigClaimedSums) > 0 {
		ch.MixFelts(claim.BigClaimedSums)
	}
	ch.MixFelts([]m31.QM31{claim.SmallClaimedSum})
}
