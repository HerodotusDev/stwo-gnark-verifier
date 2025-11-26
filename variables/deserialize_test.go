package variables

import (
	"testing"
)

// ╔══════════════════════════════════╗
// ║        Proof Reading Tests       ║
// ╚══════════════════════════════════╝

func TestReadHDPProof(t *testing.T) {
	proof, err := ReadCairoProof(ProofFixturePath(HdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	assertProofBasics(t, proof)
}

func TestReadAllComponentsProof(t *testing.T) {
	proof, err := ReadCairoProof(ProofFixturePath(AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	assertProofBasics(t, proof)
}

func assertProofBasics(t *testing.T, proof *ProofRaw) {
	t.Helper()

	if proof == nil {
		t.Fatalf("proof is nil")
	}

	if proof.InteractionPow == 0 {
		t.Fatalf("interaction pow should not be zero")
	}

	if proof.Claim.PublicData.InitialState.PC == 0 {
		t.Fatalf("initial PC was zero")
	}

	if len(proof.Claim.PublicData.PublicMemory.Program) == 0 {
		t.Fatalf("program memory is empty")
	}

	if len(proof.InteractionClaim.Opcodes) == 0 {
		t.Fatalf("opcode interaction claim empty")
	}

	if len(proof.StarkProof.SampledValues) == 0 {
		t.Fatalf("stark proof sampled values missing")
	}
}

// ╔══════════════════════════════════╗
// ║       BuildProof Assertions      ║
// ╚══════════════════════════════════╝

func TestBuildProofHDP(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(HdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	build := BuildProof(raw)
	if build == nil {
		t.Fatalf("built proof is nil")
	}

	if build.Claim.MemoryAddressToId.LogSize.Val != uint8(20) {
		t.Fatalf("unexpected log size: got %v, want %d", build.Claim.MemoryAddressToId.LogSize.Val, 20)
	}

	components := build.InteractionClaim.MemoryAddressToId.ClaimedSum.Components()
	expected := [4]uint64{836386349, 2039445746, 1962189857, 1579868635}
	for idx, want := range expected {
		if got := components[idx].Variable(); got != want {
			t.Fatalf("unexpected MemoryAddressToId interaction component[%d]: got %v, want %d", idx, got, want)
		}
	}
}

func TestBuildProofAllComponents(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(AllComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	build := BuildProof(raw)
	if build == nil {
		t.Fatalf("built proof is nil")
	}

	if build.Claim.MemoryAddressToId.LogSize.Val != uint8(9) {
		t.Fatalf("unexpected log size: got %v, want %d", build.Claim.MemoryAddressToId.LogSize.Val, 9)
	}

	components := build.InteractionClaim.MemoryAddressToId.ClaimedSum.Components()
	expected := [4]uint64{1295835890, 1110824088, 1812637607, 687778173}
	for idx, want := range expected {
		if got := components[idx].Variable(); got != want {
			t.Fatalf("unexpected MemoryAddressToId interaction component[%d]: got %v, want %d", idx, got, want)
		}
	}
}

func TestConstructProofNil(t *testing.T) {
	if proof := BuildProof(nil); proof != nil {
		t.Fatalf("expected nil proof from nil input")
	}
}

func TestBuildProofAllComponentsStatic(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(AllComponentsStaticProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	proof := BuildProof(raw)
	if proof == nil {
		t.Fatalf("built proof is nil")
	}

	if len(proof.StarkProof.QueriedValues) == 0 {
		t.Fatalf("expected queried values")
	}
	if len(proof.StarkProof.Decommitments) == 0 {
		t.Fatalf("expected decommitments")
	}

	firstValue := proof.StarkProof.QueriedValues[0][0].Variable()
	switch v := firstValue.(type) {
	case uint32:
		if v != 505308499 {
			t.Fatalf("unexpected first queried value: got %v, want %d", v, 505308499)
		}
	case uint64:
		if v != 505308499 {
			t.Fatalf("unexpected first queried value: got %v, want %d", v, 505308499)
		}
	default:
		t.Fatalf("unexpected first queried value type: %T", firstValue)
	}

	firstHashByte := proof.StarkProof.Decommitments[0].HashWitness[0][0].Val
	byteValue, ok := firstHashByte.(uint8)
	if !ok {
		t.Fatalf("expected hash witness byte to be uint8, got %T", firstHashByte)
	}
	if byteValue != 237 {
		t.Fatalf("unexpected hash witness byte: got %d, want %d", byteValue, 237)
	}
}
