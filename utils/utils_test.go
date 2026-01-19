package utils

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type hashSplitRebuildCircuit struct{}

func (c *hashSplitRebuildCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	hash := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		//nolint:gosec // test data is bounded by loop index.
		hash[i] = uints.NewU8(uint8(i))
	}

	lo, hi := SplitHash(api, hash)
	rebuiltHash := RebuildHash(api, lo, hi)

	for i := 0; i < 32; i++ {
		uapi.AssertIsEqual(hash[i], rebuiltHash[i])
	}

	return nil
}

// TestHashSplitRebuild tests that RebuildHash(SplitHash(hash)) = hash.
func TestHashSplitRebuild(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &hashSplitRebuildCircuit{}
	witness := &hashSplitRebuildCircuit{}
	assert.ProverSucceeded(circuit, witness, test.WithCurves(ecc.BN254), test.NoFuzzing(), test.NoProverChecks())
}
