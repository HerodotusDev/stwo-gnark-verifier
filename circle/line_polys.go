package circle

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

type LinePoly struct {
	Coeffs  []m31.QM31
	LogSize uints.U8
}
