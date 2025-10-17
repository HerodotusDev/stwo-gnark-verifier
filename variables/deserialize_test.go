package variables

import (
	"path/filepath"
	"runtime"
	"testing"
)

func proofFixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "test_data", name)
}

const (
	hdpProofFixture           = "hdp_prood.json"
	allComponentsProofFixture = "all_components_proof.json"
)

// ╔══════════════════════════════════╗
// ║        Proof Reading Tests       ║
// ╚══════════════════════════════════╝

func TestReadHDPProof(t *testing.T) {
	proof, err := ReadCairoProof(proofFixturePath(hdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	assertProofBasics(t, proof)
}

func TestReadAllComponentsProof(t *testing.T) {
	proof, err := ReadCairoProof(proofFixturePath(allComponentsProofFixture))
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

	if len(proof.StarkProof) == 0 {
		t.Fatalf("stark proof payload missing")
	}
}

// ╔══════════════════════════════════╗
// ║      ConstructProof Assertions   ║
// ╚══════════════════════════════════╝

func TestConstructProofHDP(t *testing.T) {
	raw, err := ReadCairoProof(proofFixturePath(hdpProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	constructed := ConstructProof(raw)
	if constructed == nil {
		t.Fatalf("constructed proof is nil")
	}

	if constructed.Claim.MemoryAddressToId.LogSize.Val != uint8(20) {
		t.Fatalf("unexpected log size: got %v, want %d", constructed.Claim.MemoryAddressToId.LogSize.Val, 20)
	}

	components := constructed.InteractionClaims.MemoryAddressToId.ClaimedSum.Components()
	expected := [4]uint64{836386349, 2039445746, 1962189857, 1579868635}
	for idx, want := range expected {
		if got := components[idx].Variable(); got != want {
			t.Fatalf("unexpected MemoryAddressToId interaction component[%d]: got %v, want %d", idx, got, want)
		}
	}
}

func TestConstructProofAllComponents(t *testing.T) {
	raw, err := ReadCairoProof(proofFixturePath(allComponentsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	constructed := ConstructProof(raw)
	if constructed == nil {
		t.Fatalf("constructed proof is nil")
	}

	if constructed.Claim.MemoryAddressToId.LogSize.Val != uint8(9) {
		t.Fatalf("unexpected log size: got %v, want %d", constructed.Claim.MemoryAddressToId.LogSize.Val, 9)
	}

	components := constructed.InteractionClaims.MemoryAddressToId.ClaimedSum.Components()
	expected := [4]uint64{1295835890, 1110824088, 1812637607, 687778173}
	for idx, want := range expected {
		if got := components[idx].Variable(); got != want {
			t.Fatalf("unexpected MemoryAddressToId interaction component[%d]: got %v, want %d", idx, got, want)
		}
	}
}

func TestConstructProofNil(t *testing.T) {
	if proof := ConstructProof(nil); proof != nil {
		t.Fatalf("expected nil proof from nil input")
	}
}
