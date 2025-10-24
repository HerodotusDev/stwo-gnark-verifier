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

	if len(proof.Proof) == 0 {
		t.Fatalf("stark proof payload missing")
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
