package main

import (
	"fmt"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/fri"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/HerodotusDev/stwo-gnark-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type VerifierCircuit struct {
	proof       variables.Proof       `gnark:"-"`
	circuitData variables.CircuitData `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api)
	verifierChip.Verify(c.proof, fri.DefaultPcsConfig(), c.circuitData)

	return nil
}

func main() {
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponentsHintsProofFixture))
	if err != nil {
		fmt.Println("Error in reading proof:", err)
		os.Exit(1)
	}

	cairoProof := variables.BuildProof(*cairoProofRaw)
	circuitData := variables.BuildCircuitData(cairoProofRaw)
	circuit := VerifierCircuit{
		proof:       cairoProof,
		circuitData: circuitData,
	}

	// ╔══════════════════════════════════╗
	// ║        Circuit Compilation       ║
	// ╚══════════════════════════════════╝
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Error in building circuit:", err)
		os.Exit(1)
	}

	// ╔══════════════════════════════════╗
	// ║          Circuit Setup           ║
	// ╚══════════════════════════════════╝
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println("Error in setup:", err)
		os.Exit(1)
	}

	// ╔══════════════════════════════════╗
	// ║        Witness Generation        ║
	// ╚══════════════════════════════════╝
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error in witness generation:", err)
		os.Exit(1)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Error in public witness generation:", err)
		os.Exit(1)
	}

	// ╔══════════════════════════════════╗
	// ║         Proof Generation         ║
	// ╚══════════════════════════════════╝
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println("Error in proof generation:", err)
		os.Exit(1)
	}

	// ╔══════════════════════════════════╗
	// ║           Verification           ║
	// ╚══════════════════════════════════╝
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Println("Error in verification:", err)
		os.Exit(1)
	}
	fmt.Println("Proof verified")
}
