package m31

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/gnark/logderivarg"
	"github.com/consensys/gnark/frontend"
)

type RC16Chip struct {
	api frontend.API

	collected []frontend.Variable // collected variables to RC16
}

func NewRC16Chip(api frontend.API) *RC16Chip {
	rc16Chip := &RC16Chip{api: api}
	// defer the commit to the end of the circuit
	api.Compiler().Defer(rc16Chip.commit)
	return rc16Chip
}

func (c *RC16Chip) Check16(in frontend.Variable) {
	c.collected = append(c.collected, in)
}

func (c *RC16Chip) commit(api frontend.API) error {
	if len(c.collected) == 0 {
		return nil
	}
	return logderivarg.Build(api, logderivarg.AsTable(c.buildTable(1<<16)), logderivarg.AsTable(c.collected))
}

func (c *RC16Chip) buildTable(nbTable int) []frontend.Variable {
	tbl := make([]frontend.Variable, nbTable)
	for i := 0; i < nbTable; i++ {
		tbl[i] = i
	}
	return tbl
}
