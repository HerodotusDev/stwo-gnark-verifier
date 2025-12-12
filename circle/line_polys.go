package circle

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

// LinePoly represents a line polynomial (used for FRI last layer polynomial)
type LinePoly struct {
	Coeffs  []m31.QM31
	LogSize uints.U8
}
