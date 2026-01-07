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

func TestReadAllComponentsHintsProof(t *testing.T) {
	proof, err := ReadCairoProof(ProofFixturePath(AllComponentsHintsProofFixture))
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

	_ = BuildProof(*raw)
	_ = BuildCircuitData(raw)
}

func TestBuildProofAllComponentsHints(t *testing.T) {
	raw, err := ReadCairoProof(ProofFixturePath(AllComponentsHintsProofFixture))
	if err != nil {
		t.Fatalf("failed to read proof: %v", err)
	}

	_ = BuildProof(*raw)
	_ = BuildCircuitData(raw)
}
