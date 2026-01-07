package circle

import (
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	// CircleLogOrder is the order of the circle in log2.
	CircleLogOrder = 31
)

// ╔══════════════════════════════════╗
// ║            Circle Chip           ║
// ╚══════════════════════════════════╝

// CircleChip wires circle operations into the circuit.
type CircleChip struct {
	api        frontend.API
	uapi       *uints.BinaryField[uints.U32]
	comparator *cmp.BoundedComparator
	m31        *m31.M31Chip
	qm31       *m31.QM31Chip
}

// NewCircleChip instantiates a circle chip backed by the provided field chips.
func NewCircleChip(api frontend.API, m31Chip *m31.M31Chip, qm31Chip *m31.QM31Chip) *CircleChip {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	comparator := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)

	return &CircleChip{
		api:        api,
		uapi:       uapi,
		comparator: comparator,
		m31:        m31Chip,
		qm31:       qm31Chip,
	}
}
