package variables

import (
	"encoding/json"
	"fmt"
)

// ╔══════════════════════════════════╗
// ║          Proof Containers        ║
// ╚══════════════════════════════════╝

// ProofRaw mirrors the serialized Cairo proof emitted by the prover.
type ProofRaw struct {
	Claim            ClaimRaw            `json:"claim"`
	InteractionPow   uint64              `json:"interaction_pow"`
	InteractionClaim InteractionClaimRaw `json:"interaction_claim"`
	StarkProof       StarkProofRaw       `json:"stark_proof"`
	CircuitHints     CircuitHintsRaw     `json:"hints"`
}

// ╔══════════════════════════════════╗
// ║          Claim Structures        ║
// ╚══════════════════════════════════╝

// ClaimRaw contains the verifier-facing statement for the proof.
type ClaimRaw struct {
	PublicData        PublicDataRaw               `json:"public_data"`
	Opcodes           OpcodeClaimRaw              `json:"opcodes"`
	VerifyInstruction VerifyInstructionClaimRaw   `json:"verify_instruction"`
	BlakeContext      BlakeContextClaimRawWrapper `json:"blake_context"`
	Builtins          BuiltinsClaimRaw            `json:"builtins"`
	PedersenContext   PedersenContextClaimRaw     `json:"pedersen_context"`
	PoseidonContext   PoseidonContextClaimRaw     `json:"poseidon_context"`
	MemoryAddressToId MemoryAddressToIdClaimRaw   `json:"memory_address_to_id"`
	MemoryIDToValue   MemoryIDToValueClaimRaw     `json:"memory_id_to_value"`
	RangeChecks       RangeChecksClaimRaw         `json:"range_checks"`
	VerifyBitwiseXor4 VerifyBitwiseXorClaimRaw    `json:"verify_bitwise_xor_4"`
	VerifyBitwiseXor7 VerifyBitwiseXorClaimRaw    `json:"verify_bitwise_xor_7"`
	VerifyBitwiseXor8 VerifyBitwiseXorClaimRaw    `json:"verify_bitwise_xor_8"`
	VerifyBitwiseXor9 VerifyBitwiseXorClaimRaw    `json:"verify_bitwise_xor_9"`
}

// OpcodeClaimRaw captures log-size information for each opcode component.
type OpcodeClaimRaw struct {
	Add                 []OpcodeLogSizeEntryRaw `json:"add"`
	AddSmall            []OpcodeLogSizeEntryRaw `json:"add_small"`
	AddAp               []OpcodeLogSizeEntryRaw `json:"add_ap"`
	AssertEq            []OpcodeLogSizeEntryRaw `json:"assert_eq"`
	AssertEqImm         []OpcodeLogSizeEntryRaw `json:"assert_eq_imm"`
	AssertEqDoubleDeref []OpcodeLogSizeEntryRaw `json:"assert_eq_double_deref"`
	Blake               []OpcodeLogSizeEntryRaw `json:"blake"`
	Call                []OpcodeLogSizeEntryRaw `json:"call"`
	CallRelImm          []OpcodeLogSizeEntryRaw `json:"call_rel_imm"`
	Generic             []OpcodeLogSizeEntryRaw `json:"generic"`
	Jnz                 []OpcodeLogSizeEntryRaw `json:"jnz"`
	JnzTaken            []OpcodeLogSizeEntryRaw `json:"jnz_taken"`
	Jump                []OpcodeLogSizeEntryRaw `json:"jump"`
	JumpDoubleDeref     []OpcodeLogSizeEntryRaw `json:"jump_double_deref"`
	JumpRel             []OpcodeLogSizeEntryRaw `json:"jump_rel"`
	JumpRelImm          []OpcodeLogSizeEntryRaw `json:"jump_rel_imm"`
	Mul                 []OpcodeLogSizeEntryRaw `json:"mul"`
	MulSmall            []OpcodeLogSizeEntryRaw `json:"mul_small"`
	Qm31                []OpcodeLogSizeEntryRaw `json:"qm31"`
	Ret                 []OpcodeLogSizeEntryRaw `json:"ret"`
}

// OpcodeLogSizeEntryRaw stores a single opcode log size entry.
type OpcodeLogSizeEntryRaw struct {
	LogSize uint64 `json:"log_size"`
}

// VerifyInstructionClaimRaw stores the log size of the verify-instruction component.
type VerifyInstructionClaimRaw struct {
	LogSize uint64 `json:"log_size"`
}

// BlakeContextClaimRaw bundles the log-size claims for the Blake2s context tables.
type BlakeContextClaimRawWrapper struct {
	Claim *BlakeContextClaimRaw `json:"claim"`
}

// BlakeContextClaim enumerates the per-table log sizes used by the prover.
type BlakeContextClaimRaw struct {
	BlakeG             *ComponentLogSizeEntry `json:"blake_g"`
	BlakeRound         *ComponentLogSizeEntry `json:"blake_round"`
	BlakeSigma         *ComponentLogSizeEntry `json:"blake_sigma"`
	TripleXor32        *ComponentLogSizeEntry `json:"triple_xor_32"`
	VerifyBitwiseXor12 *ComponentLogSizeEntry `json:"verify_bitwise_xor_12"`
}

// PedersenContextClaimRaw mirrors the pedersen context claims.
type PedersenContextClaimRaw struct {
	Claim PedersenContextClaimEntriesRaw `json:"claim"`
}

// PedersenContextClaim maps component names to their log-size entries.
type PedersenContextClaimEntriesRaw map[string]*ComponentLogSizeEntry

// PoseidonContextClaimRaw bundles the log-size claims for the Poseidon context tables.
type PoseidonContextClaimRaw struct {
	Claim *PoseidonContextClaimDetailsRaw `json:"claim"`
}

// PoseidonContextClaim enumerates the log sizes for each Poseidon sub-component.
type PoseidonContextClaimDetailsRaw struct {
	Poseidon3PartialRoundsChain *ComponentLogSizeEntry `json:"poseidon_3_partial_rounds_chain"`
	PoseidonFullRoundChain      *ComponentLogSizeEntry `json:"poseidon_full_round_chain"`
	Cube252                     *ComponentLogSizeEntry `json:"cube_252"`
	PoseidonRoundKeys           *ComponentLogSizeEntry `json:"poseidon_round_keys"`
	RangeCheckFelt252Width27    *ComponentLogSizeEntry `json:"range_check_felt_252_width_27"`
}

// BuiltinsClaimRaw contains the log-size declarations for each builtin.
type BuiltinsClaimRaw map[string]*BuiltinClaimEntryRaw

// BuiltinClaimEntryRaw records the configuration for a builtin claim.
type BuiltinClaimEntryRaw struct {
	LogSize                       *uint64 `json:"log_size,omitempty"`
	AddModBuiltinSegmentStart     *uint64 `json:"add_mod_builtin_segment_start,omitempty"`
	BitwiseBuiltinSegmentStart    *uint64 `json:"bitwise_builtin_segment_start,omitempty"`
	MulModBuiltinSegmentStart     *uint64 `json:"mul_mod_builtin_segment_start,omitempty"`
	PedersenBuiltinSegmentStart   *uint64 `json:"pedersen_builtin_segment_start,omitempty"`
	PoseidonBuiltinSegmentStart   *uint64 `json:"poseidon_builtin_segment_start,omitempty"`
	RangeCheckBuiltinSegmentStart *uint64 `json:"range_check_builtin_segment_start,omitempty"`
}

// RangeChecksClaimRaw maps range-check identifiers to their log-size claims.
type RangeChecksClaimRaw map[string]*ComponentLogSizeEntry

// VerifyBitwiseXorClaimRaw stores the claim metadata for a bitwise xor component.
type VerifyBitwiseXorClaimRaw struct {
	LogSize uint64 `json:"log_size"`
}

// MemoryAddressToIdClaimRaw stores the log size for the memory-address-to-id table.
type MemoryAddressToIdClaimRaw struct {
	LogSize uint64 `json:"log_size"`
}

// MemoryIDToValueClaimRaw stores the log sizes for the memory-id-to-value component.
type MemoryIDToValueClaimRaw struct {
	BigLogSizes  []uint64 `json:"big_log_sizes"`
	SmallLogSize uint64   `json:"small_log_size"`
}

// ComponentLogSizeEntry captures the log size declared for a sub-component.
type ComponentLogSizeEntry struct {
	LogSize uint64 `json:"log_size"`
}

// ╔══════════════════════════════════╗
// ║        Public Data Claim         ║
// ╚══════════════════════════════════╝

// PublicDataRaw captures the Cairo program's public inputs/outputs.
type PublicDataRaw struct {
	PublicMemory PublicMemoryRaw  `json:"public_memory"`
	InitialState RegisterStateRaw `json:"initial_state"`
	FinalState   RegisterStateRaw `json:"final_state"`
}

// RegisterStateRaw holds the pc/ap/fp register values.
type RegisterStateRaw struct {
	PC uint32 `json:"pc"`
	AP uint32 `json:"ap"`
	FP uint32 `json:"fp"`
}

// PublicMemoryRaw exposes the program, output and auxiliary memory segments.
type PublicMemoryRaw struct {
	Program        []MemoryCellRaw             `json:"program"`
	Output         []MemoryCellRaw             `json:"output"`
	PublicSegments map[string]*SegmentRangeRaw `json:"public_segments"`
	SafeCall       []MemoryCellRaw             `json:"safe_call"`
}

// SegmentRangeRaw captures the start and stop pointers of a builtin segment.
type SegmentRangeRaw struct {
	StartPtr *SegmentPointerRaw `json:"start_ptr"`
	StopPtr  *SegmentPointerRaw `json:"stop_ptr"`
}

// SegmentPointerRaw stores the segment identifier and value.
type SegmentPointerRaw struct {
	ID    uint32 `json:"id"`
	Value uint32 `json:"value"`
}

// MemoryCellRaw represents a (address, word) pair from the public memory tables.
type MemoryCellRaw struct {
	Address uint32
	Value   []uint32
}

// UnmarshalJSON decodes the Cairo memory cell format `[addr, [values...]]`.
func (c *MemoryCellRaw) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) != 2 {
		return fmt.Errorf("memory cell expects 2 elements, got %d", len(raw))
	}

	if err := json.Unmarshal(raw[0], &c.Address); err != nil {
		return err
	}

	if err := json.Unmarshal(raw[1], &c.Value); err != nil {
		return err
	}

	return nil
}

// ╔══════════════════════════════════╗
// ║       Interaction Structures     ║
// ╚══════════════════════════════════╝

// InteractionClaimRaw collects the interaction claims for each component.
type InteractionClaimRaw struct {
	Opcodes           map[string][]OpcodeInteractionEntryRaw `json:"opcodes"`
	VerifyInstruction VerifyInstructionInteractionClaimRaw   `json:"verify_instruction"`
	BlakeContext      BlakeContextInteractionClaimRaw        `json:"blake_context"`
	Builtins          BuiltinsInteractionClaimRaw            `json:"builtins"`
	PedersenContext   PedersenContextInteractionClaimRaw     `json:"pedersen_context"`
	PoseidonContext   PoseidonContextInteractionClaimRaw     `json:"poseidon_context"`
	MemoryAddressToId MemoryAddressToIdInteractionClaimRaw   `json:"memory_address_to_id"`
	MemoryIDToValue   MemoryIDToValueInteractionClaimRaw     `json:"memory_id_to_value"`
	RangeChecks       RangeChecksInteractionClaimRaw         `json:"range_checks"`
	VerifyBitwiseXor4 VerifyBitwiseXorInteractionClaimRaw    `json:"verify_bitwise_xor_4"`
	VerifyBitwiseXor7 VerifyBitwiseXorInteractionClaimRaw    `json:"verify_bitwise_xor_7"`
	VerifyBitwiseXor8 VerifyBitwiseXorInteractionClaimRaw    `json:"verify_bitwise_xor_8"`
	VerifyBitwiseXor9 VerifyBitwiseXorInteractionClaimRaw    `json:"verify_bitwise_xor_9"`
}

// BlakeContextInteractionClaimRaw bundles the interaction claims for the Blake2s context tables.
type BlakeContextInteractionClaimRaw struct {
	Claim *BlakeInteractionClaimRaw `json:"claim"`
}

// BlakeContextInteractionClaim captures the claimed sums for each Blake2s sub-table.
type BlakeInteractionClaimRaw struct {
	BlakeG             *ComponentClaimedSumEntry `json:"blake_g"`
	BlakeRound         *ComponentClaimedSumEntry `json:"blake_round"`
	BlakeSigma         *ComponentClaimedSumEntry `json:"blake_sigma"`
	TripleXor32        *ComponentClaimedSumEntry `json:"triple_xor_32"`
	VerifyBitwiseXor12 *ComponentClaimedSumEntry `json:"verify_bitwise_xor_12"`
}

// PedersenContextInteractionClaimRaw captures the interaction claims for the pedersen context.
type PedersenContextInteractionClaimRaw struct {
	Claim PedersenInteractionClaimRaw `json:"claim"`
}

// PedersenContextInteractionClaim maps component names to their claimed sums.
type PedersenInteractionClaimRaw map[string]*ComponentClaimedSumEntry

// PoseidonContextInteractionClaimRaw collects the interaction claims for Poseidon context tables.
type PoseidonContextInteractionClaimRaw struct {
	Claim *PoseidonInteractionClaimRaw `json:"claim"`
}

// PoseidonContextInteractionClaim enumerates the claimed sums for the Poseidon sub-components.
type PoseidonInteractionClaimRaw struct {
	Poseidon3PartialRoundsChain *ComponentClaimedSumEntry `json:"poseidon_3_partial_rounds_chain"`
	PoseidonFullRoundChain      *ComponentClaimedSumEntry `json:"poseidon_full_round_chain"`
	Cube252                     *ComponentClaimedSumEntry `json:"cube_252"`
	PoseidonRoundKeys           *ComponentClaimedSumEntry `json:"poseidon_round_keys"`
	RangeCheckFelt252Width27    *ComponentClaimedSumEntry `json:"range_check_felt_252_width_27"`
}

// BuiltinsInteractionClaimRaw maps builtin names to their interaction claims.
type BuiltinsInteractionClaimRaw map[string]*ComponentClaimedSumEntry

// RangeChecksInteractionClaimRaw maps range-check identifiers to their interaction claims.
type RangeChecksInteractionClaimRaw map[string]*ComponentClaimedSumEntry

// VerifyInstructionInteractionClaimRaw stores the claimed sum for the verify-instruction component.
type VerifyInstructionInteractionClaimRaw struct {
	ClaimedSum [][]uint64 `json:"claimed_sum"`
}

// OpcodeInteractionEntryRaw stores the claimed sum emitted for an opcode table.
type OpcodeInteractionEntryRaw struct {
	ClaimedSum [][]uint64 `json:"claimed_sum"`
}

// MemoryAddressToIdInteractionClaimRaw stores the claimed sum emitted by the prover.
type MemoryAddressToIdInteractionClaimRaw struct {
	ClaimedSum [][]uint64 `json:"claimed_sum"`
}

// MemoryIDToValueInteractionClaimRaw stores the claimed sums for the memory-id-to-value component.
type MemoryIDToValueInteractionClaimRaw struct {
	BigClaimedSums  [][][]uint64 `json:"big_claimed_sums"`
	SmallClaimedSum [][]uint64   `json:"small_claimed_sum"`
}

// VerifyBitwiseXorInteractionClaimRaw carries the claimed sum for the verify_bitwise_xor components.
type VerifyBitwiseXorInteractionClaimRaw struct {
	ClaimedSum [][]uint64 `json:"claimed_sum"`
}

// ComponentClaimedSumEntry captures the claimed sum emitted for a sub-component.
type ComponentClaimedSumEntry struct {
	ClaimedSum [][]uint64 `json:"claimed_sum"`
}

// ╔══════════════════════════════════╗
// ║        Stark Proof Structures    ║
// ╚══════════════════════════════════╝

// StarkProofRaw mirrors the serialized Stark proof payload emitted by the prover.
type StarkProofRaw struct {
	Config        json.RawMessage         `json:"config"`
	Commitments   [][]uint8               `json:"commitments"`
	Decommitments []MerkleDecommitmentRaw `json:"decommitments"`
	FriProof      FriProofRaw             `json:"fri_proof"`
	ProofOfWork   uint64                  `json:"proof_of_work"`
	QueriedValues [][]uint64              `json:"queried_values"`
	SampledValues SampledValuesRaw        `json:"sampled_values"`
}

// SampledValuesRaw stores the sampled values grouped by table, column and evaluation.
type SampledValuesRaw [][][][][]uint64

// ╔══════════════════════════════════╗
// ║    Merkle Decommitment Layout    ║
// ╚══════════════════════════════════╝

// MerkleDecommitmentRaw mirrors the serialized Merkle decommitment payload.
type MerkleDecommitmentRaw struct {
	HashWitness   [][]uint8 `json:"hash_witness"`
	ColumnWitness []uint64  `json:"column_witness"`
}

// ╔══════════════════════════════════╗
// ║        FRI Proof Structure       ║
// ╚══════════════════════════════════╝
// FriProofRaw mirrors the serialized FRI proof payload.
type FriProofRaw struct {
	FirstLayerProof  FriLayerProofRaw   `json:"first_layer"`
	InnerLayerProofs []FriLayerProofRaw `json:"inner_layers"`
	LastLayerPoly    LinePolyRaw        `json:"last_layer_poly"`
}

// FriLayerProofRaw mirrors the serialized FRI layer proof payload.
type FriLayerProofRaw struct {
	FriWitness   [][][]uint64          `json:"fri_witness"`
	Decommitment MerkleDecommitmentRaw `json:"decommitment"`
	Commitment   []uint8               `json:"commitment"`
}

// LinePolyRaw mirrors the serialized line polynomial payload.
type LinePolyRaw struct {
	Coeffs  [][][]uint64 `json:"coeffs"`
	LogSize uint8        `json:"log_size"`
}

// ╔══════════════════════════════════╗
// ║       Circuit Hints Structure    ║
// ╚══════════════════════════════════╝

// CircuitHintsRaw stores the circuit hints for the proof.
type CircuitHintsRaw struct {
	QueryPositionsByLogSize map[string][]int `json:"query_positions_by_log_size"`
}
