package verifier

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/channel"
	"github.com/HerodotusDev/stwo-gnark-verifier/circle"
	"github.com/HerodotusDev/stwo-gnark-verifier/components"
	"github.com/HerodotusDev/stwo-gnark-verifier/components/cairo_components"
	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// VerifierChip is a circuit gadget for verifying a Stwo proof
type VerifierChip struct {
	api     frontend.API `gnark:"-"`
	uapi    *uints.BinaryField[uints.U32]
	uapi64  *uints.BinaryField[uints.U64]
	bapi    *uints.Bytes
	blake2s *blake2s.Blake2sChip
	channel *channel.Channel
	m31     *m31.M31Chip
	qm31    *m31.QM31Chip
	circle  *circle.CircleChip
	cmpU32  *cmp.BoundedComparator `gnark:"-"`
	cmpU8   *cmp.BoundedComparator `gnark:"-"`
}

// Blake2sChip returns the Blake2s chip instance owned by this verifier.
// Exposed to allow higher-level circuits to reuse the same gadget instead of re-initializing it.
func (c *VerifierChip) Blake2sChip() *blake2s.Blake2sChip {
	return c.blake2s
}

// NewVerifierChip initializes a new VerifierChip
func NewVerifierChip(api frontend.API) *VerifierChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	uapi64, err := uints.New[uints.U64](api)
	if err != nil {
		panic(err)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}

	// Shared comparators (reused across sub-chips).
	cmpU32 := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)
	cmpU8 := cmp.NewBoundedComparator(api, big.NewInt(1<<8), false)

	blake2sChip := blake2s.NewBlake2sChipWithUAPI(api, uapi, cmpU32)
	m31Chip := m31.NewM31Chip(api)
	qm31Chip := m31.NewQM31Chip(m31Chip)
	circleChip := circle.NewCircleChipWithUAPI(api, uapi, cmpU32, m31Chip, qm31Chip)
	channelChip := channel.NewChannelWithChips(api, blake2sChip, m31Chip, uapi, cmpU32)
	return &VerifierChip{
		api:     api,
		uapi:    uapi,
		uapi64:  uapi64,
		bapi:    bapi,
		blake2s: blake2sChip,
		channel: channelChip,
		m31:     m31Chip,
		qm31:    qm31Chip,
		circle:  circleChip,
		cmpU32:  cmpU32,
		cmpU8:   cmpU8,
	}
}

// Verify verifies a Stwo proof
//   - proof is the Cairo proof to verify
//   - pcsConfig is the PCS configuration (default or production)
//   - circuitData are the circuit shapes (obtained from a rust verifier run)
func (c *VerifierChip) Verify(proof variables.Proof, pcsConfig variables.PcsConfig, circuitData variables.CircuitData) {
	// Mix PCS configuration into the channel
	pcsConfig.MixInto(c.channel, c.uapi)

	// ╔══════════════════════════════════╗
	// ║        Trace Commitment (1)      ║
	// ╚══════════════════════════════════╝

	// Initialize commitment verifier
	commitmentVerifier := fri.NewCommitmentSchemeVerifierWithChips(c.api, c.uapi, c.bapi, c.m31, c.blake2s, c.cmpU32, pcsConfig, circuitData)
	logSizes := components.LogSizes(proof.Claim, circuitData)

	// We assume that all components have `max_constraint_log_degree_bound()` returning `log_size() + 1`.
	// This should not include the preprocessed trace (hence calling MAX before adding preprocessed trace log sizes)
	compositionLogDegreeBound := components.MaxLogSize(c.api, c.cmpU8, logSizes)

	// Verify preprocessed trace commitment
	logSizes[cairo_components.PREPROCESSED_IDX] = components.PreprocessedLogSizes()
	preprocessedLogSizes := logSizes[cairo_components.PREPROCESSED_IDX]
	commitmentVerifier.Commit(cairo_components.PREPROCESSED_IDX, proof.StarkProof.Commitments[0], preprocessedLogSizes, c.channel)

	// Mix claim into channel
	proof.Claim.MixIntoWithUAPI(c.channel, c.api, c.uapi, c.uapi64, circuitData)

	// Verify main trace commitment
	commitmentVerifier.Commit(cairo_components.MAIN_IDX, proof.StarkProof.Commitments[1], logSizes[cairo_components.MAIN_IDX], c.channel)

	// Check Proof-of-Work nonce
	c.channel.MixAndCheckPowNonce(proof.InteractionPow, 24)

	// ╔══════════════════════════════════╗
	// ║             Logup Sum            ║
	// ╚══════════════════════════════════╝

	// Draw interaction elements
	var cairoInteractionElements variables.CairoInteractionElements
	cairoInteractionElements.Draw(c.channel, c.qm31)

	// Verify Logup sum
	sum := components.LogupSum(c.qm31, proof.Claim, cairoInteractionElements, proof.InteractionClaim, circuitData)
	c.qm31.AssertEqual(sum, c.qm31.Zero())

	// ╔══════════════════════════════════╗
	// ║        Trace Commitment (2)      ║
	// ╚══════════════════════════════════╝

	// Mix interaction claim into channel
	proof.InteractionClaim.MixInto(c.channel, circuitData)

	// Verify interaction trace commitment
	commitmentVerifier.Commit(cairo_components.INTERACTION_IDX, proof.StarkProof.Commitments[cairo_components.INTERACTION_IDX], logSizes[cairo_components.INTERACTION_IDX], c.channel)

	// Draw random coeff from channel for OODS
	randomCoeff := c.channel.DrawFelt()

	// Verify composition polynomial commitment
	compositionLogSizes := []frontend.Variable{compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound, compositionLogDegreeBound}
	commitmentVerifier.Commit(cairo_components.CP_IDX, proof.StarkProof.Commitments[cairo_components.CP_IDX], compositionLogSizes, c.channel)

	// ╔══════════════════════════════════╗
	// ║               OODS               ║
	// ╚══════════════════════════════════╝

	// Verify OODS
	oodsPoint := c.circle.GetRandomPoint(c.channel)
	cairoComponents := components.NewComponents(c.api, c.m31, c.qm31, c.circle, cairoInteractionElements, proof.Claim, proof.InteractionClaim, oodsPoint, circuitData)

	// Extract CP evaluation from sampled values
	compositionOodsEval := c.qm31.FromPartialEvals(
		proof.StarkProof.SampledValues[cairo_components.CP_IDX][0][0],
		proof.StarkProof.SampledValues[cairo_components.CP_IDX][1][0],
		proof.StarkProof.SampledValues[cairo_components.CP_IDX][2][0],
		proof.StarkProof.SampledValues[cairo_components.CP_IDX][3][0],
	)

	// evaluate constraints using sampled values
	constraintsOodsEval := cairoComponents.Evaluate(proof.StarkProof.SampledValues, randomCoeff, circuitData)

	// verify OODS
	c.qm31.AssertEqual(compositionOodsEval, constraintsOodsEval)

	// ╔══════════════════════════════════╗
	// ║          FRI Commitment          ║
	// ╚══════════════════════════════════╝

	// Mix flatten sampled values into channel
	flattenedSampledValues := utils.FlattenTree(utils.FlattenTree(proof.StarkProof.SampledValues))
	c.channel.MixFelts(flattenedSampledValues)

	// Draw random coeff for FRI
	randomCoeff = c.channel.DrawFelt()

	// Compute bounds (column log sizes deduped, in decreasing order and not blew up)
	bounds := commitmentVerifier.Bounds()

	// Verification of commitment stage of FRI
	friVerifier := fri.NewFriVerifier(c.api, c.uapi, c.bapi, c.blake2s, c.cmpU32, c.channel, c.qm31, c.circle, commitmentVerifier.PcsConfig.FriConfig, proof.StarkProof.FriProof, bounds, circuitData)

	// Proof of work
	c.channel.MixAndCheckPowNonce(proof.StarkProof.ProofOfWork, int(commitmentVerifier.PcsConfig.PowBits))

	// ╔══════════════════════════════════╗
	// ║              Queries             ║
	// ╚══════════════════════════════════╝

	// Generate base layer queries and verify they match the hinted queries
	maxLogSize := bounds[0]
	baseLayerQueries := c.channel.GenerateBaseLayerQueries(maxLogSize, commitmentVerifier.PcsConfig.FriConfig.NQueries)
	queries := utils.GenerateQueries(c.api, c.uapi, c.cmpU32, baseLayerQueries, commitmentVerifier.PcsConfig.FriConfig.NQueries, circuitData.DedupedQueriesShape, circuitData.MaxLogSize)
	queriesWithDummy := utils.AppendDummy(queries, frontend.Variable(1<<32))

	// ╔══════════════════════════════════╗
	// ║        Trace decommitments       ║
	// ╚══════════════════════════════════╝

	// Verify merkle decommitments
	for treeIndex, tree := range commitmentVerifier.Trees {
		tree.Verify(queriesWithDummy, proof.StarkProof.QueriedValues[treeIndex], proof.StarkProof.Decommitments[treeIndex], circuitData.DedupedQueriesShape, circuitData.QueriesBranching)
	}

	// ╔══════════════════════════════════╗
	// ║               FRI                ║
	// ╚══════════════════════════════════╝

	// Compute mask points
	maskPoints := components.MaskPoints(c.api, proof.Claim, oodsPoint, c.circle, circuitData)

	// Verify FRI quotients
	friAnswers := friVerifier.FriQuotientEvaluations(proof.StarkProof.SampledValues, maskPoints, queries, proof.StarkProof.QueriedValues, randomCoeff)
	friAnswersEncoded := fri.EncodeFriAnswers(c.qm31, friAnswers)
	friAnswersWithDummy := utils.AppendDummy(friAnswersEncoded, frontend.Variable(1<<32))
	friVerifier.Verify(queriesWithDummy, friAnswersWithDummy)
}
