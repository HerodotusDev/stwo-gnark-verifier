package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/HerodotusDev/stwo-gnark-verifier/variables"
	"github.com/HerodotusDev/stwo-gnark-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

type verifierCircuit struct {
	Proof       variables.Proof
	CircuitData variables.CircuitData `gnark:"-"`
}

func (c *verifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api)
	verifierChip.Verify(c.Proof, variables.DefaultPcsConfig(), c.CircuitData)

	return nil
}

func loadFixture() (variables.Proof, variables.CircuitData, error) {
	cairoProofRaw, err := variables.ReadCairoProof(variables.ProofFixturePath(variables.AllComponents1QueryProofFixture))
	if err != nil {
		return variables.Proof{}, variables.CircuitData{}, err
	}
	shapeRaw, err := variables.ReadCircuitShape(variables.ShapeFixturePath(variables.AllComponents1QueryProofFixture))
	if err != nil {
		return variables.Proof{}, variables.CircuitData{}, err
	}

	return variables.BuildProof(*cairoProofRaw), variables.BuildCircuitData(shapeRaw), nil
}

func main() {
	proof, circuitData, err := loadFixture()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load fixture: %v\n", err)
		os.Exit(1)
	}

	var prof *profile.Profile
	if path := os.Getenv("GNARK_PROFILE_PATH"); path != "" {
		prof = profile.Start(profile.WithPath(path))
	} else if os.Getenv("GNARK_PROFILE") != "" {
		prof = profile.Start()
	}
	if prof != nil {
		defer prof.Stop()
	}

	start := time.Now()
	compileOpts, err := utils.CompileOptionsFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile options: %v\n", err)
		os.Exit(1)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &verifierCircuit{
		Proof:       proof,
		CircuitData: circuitData,
	}, compileOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile circuit: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(start)
	fmt.Printf("constraints=%d\n", cs.GetNbConstraints())
	fmt.Printf("compile_ms=%d\n", elapsed.Milliseconds())
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Printf("heap_alloc_bytes=%d\n", mem.HeapAlloc)
	fmt.Printf("heap_sys_bytes=%d\n", mem.HeapSys)
	fmt.Printf("total_alloc_bytes=%d\n", mem.TotalAlloc)
	if prof != nil {
		fmt.Printf("profile_constraints=%d\n", prof.NbConstraints())
		if os.Getenv("GNARK_PROFILE_TOP") != "" {
			fmt.Print(prof.Top())
		}
	}
}
