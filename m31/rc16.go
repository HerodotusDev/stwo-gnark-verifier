package m31

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/gnark/logderivarg"
	"github.com/consensys/gnark/frontend"
)

// ╔══════════════════════════════════╗
// ║        RC16 Chip                 ║
// ╚══════════════════════════════════╝
// A chip for RC16 field operations. This chip replicates the logic of the commitChecker in
// https://github.com/Consensys/gnark/blob/55b0e54d2ae15e886ad37300a8d2b00ad00a8023/std/rangecheck/rangecheck_commit.go#L26.
// Having two range checkers has a greater fixed cost (build two tables) but we need an efficient range checker for both
// * M31 (2 RC 16) to deal with constant M31 operations;
// * u8 operations for the blake2s chip.
type RC16Chip struct {
	api frontend.API

	collected []frontend.Variable // collected variables to RC16
}

// Creates a new RC16 chip
func NewRC16Chip(api frontend.API) *RC16Chip {
	rc16Chip := &RC16Chip{api: api}
	// defer the commit to the end of the circuit
	api.Compiler().Defer(rc16Chip.commit)
	return rc16Chip
}

// Adds a variable to the collected variables to be checked by the RC16 chip
func (c *RC16Chip) Check16(in frontend.Variable) {
	c.collected = append(c.collected, in)
}

// Commits the collected variables to the RC16 chip at the end of the circuit
func (c *RC16Chip) commit(api frontend.API) error {
	if len(c.collected) == 0 {
		return nil
	}
	return logderivarg.Build(api, logderivarg.AsTable(c.buildTable(1<<16)), logderivarg.AsTable(c.collected))
}

// Builds the table for the RC16 chip
func (c *RC16Chip) buildTable(nbTable int) []frontend.Variable {
	tbl := make([]frontend.Variable, nbTable)
	for i := 0; i < nbTable; i++ {
		tbl[i] = i
	}
	return tbl
}
