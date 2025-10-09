package m31_test

import (
	"testing"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type RC16Circuit struct {
	Collected [3]frontend.Variable
}

func (c *RC16Circuit) Define(api frontend.API) error {
	rc16 := m31.NewRC16Chip(api)
	for _, in := range c.Collected {
		rc16.Check16(in)
	}
	return nil
}

func TestRC16(t *testing.T) {
	witness := RC16Circuit{
		Collected: [3]frontend.Variable{
			0, 1, (1 << 16) - 1,
		},
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&RC16Circuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}

func TestRC16Fails(t *testing.T) {
	badWitness := RC16Circuit{
		Collected: [3]frontend.Variable{
			0, 0, 1 << 16,
		},
	}
	assert := test.NewAssert(t)
	assert.ProverFailed(&RC16Circuit{}, &badWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoProverChecks(),
		test.NoFuzzing())
}
