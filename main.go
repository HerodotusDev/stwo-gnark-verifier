package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/HerodotusDev/stwo-gnark-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type VerifierCircuit struct {
	Proof       variables.Proof
	CircuitData variables.CircuitData `gnark:"-"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifier.NewVerifierChip(api).Verify(c.Proof, variables.DefaultPcsConfig(), c.CircuitData)

	// Flatten [][32]uints.U8 -> []frontend.Variable for Commit
	var flattenedVars []frontend.Variable
	for _, digest := range c.Proof.StarkProof.Commitments {
		for _, u8 := range digest {
			flattenedVars = append(flattenedVars, u8.Val)
		}
	}

	commitment, err := api.(frontend.Committer).Commit(flattenedVars...)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

type SolidityCallData struct {
	Proof         [8]string `json:"proof"`
	Commitments   [2]string `json:"commitments"`
	CommitmentPok [2]string `json:"commitmentPok"`
	Input         []string  `json:"input"`
}

func main() {
	// 1. Load Data
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponents1QueryProofFixture))
	if err != nil {
		panic(err)
	}
	shapeRaw, err := variables.ReadCircuitShape(variables.ShapeFixturePath(variables.AllComponents1QueryProofFixture))
	if err != nil {
		panic(err)
	}

	cData := variables.BuildCircuitData(shapeRaw)
	circuit := VerifierCircuit{Proof: variables.BuildProof(*cairoProofRaw), CircuitData: cData}
	assignment := VerifierCircuit{Proof: variables.BuildProof(*cairoProofRaw), CircuitData: cData}

	// 2. Compile & Setup
	fmt.Println(">> Compiling & Setup...")
	compileOpts, err := utils.CompileOptionsFromEnv()
	if err != nil {
		panic(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, compileOpts...)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// 3. Export Solidity
	f, err := os.Create("contract_g16.sol")
	if err != nil {
		panic(err)
	}
	if err := vk.ExportSolidity(f, solidity.WithHashToFieldFunction(sha256.New())); err != nil {
		panic(err)
	}
	f.Close()

	// 4. Prove
	fmt.Println(">> Proving...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}

	// 5. Verify
	fmt.Println(">> Verifying...")
	if err := groth16.Verify(proof, vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha256.New())); err != nil {
		panic(err)
	}

	// 6. Generate JSON
	fmt.Println(">> Generating JSON...")

	// Helper closure to slice bytes into BigInt strings
	const fp = 32
	parse := func(src []byte, count int) []string {
		res := make([]string, count)
		for i := 0; i < count; i++ {
			res[i] = new(big.Int).SetBytes(src[i*fp : (i+1)*fp]).String()
		}
		return res
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteRawTo(&proofBuf); err != nil {
		panic(err)
	}
	proofBytes := proofBuf.Bytes()
	if err := os.WriteFile("proof.bin", proofBytes, 0600); err != nil {
		panic(err)
	}

	var witnessBuf bytes.Buffer
	if _, err := pubWitness.WriteTo(&witnessBuf); err != nil {
		panic(err)
	}
	pubBytes := witnessBuf.Bytes()
	if err := os.WriteFile("witness.bin", pubBytes, 0600); err != nil {
		panic(err)
	}

	// Offsets: 8 points (A,B,C) + 4 byte header -> Commitments -> PoK
	commStart := 8*fp + 4
	pokStart := commStart + 2*fp

	data := SolidityCallData{
		Input: parse(pubBytes[12:], int(binary.BigEndian.Uint32(pubBytes[:4]))),
	}
	copy(data.Proof[:], parse(proofBytes, 8))
	copy(data.Commitments[:], parse(proofBytes[commStart:], 2))
	copy(data.CommitmentPok[:], parse(proofBytes[pokStart:], 2))

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile("calldata.json", jsonData, 0600); err != nil {
		panic(err)
	}
	fmt.Println(">> Done.")
}
