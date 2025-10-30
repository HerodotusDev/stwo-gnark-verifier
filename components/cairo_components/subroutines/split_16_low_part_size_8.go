package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

func Split16LowPartSize8Evaluate(
	qm31 *m31.QM31Chip,
	input m31.QM31,
	msb m31.QM31,
) m31.QM31 {
	return qm31.Sub(input, qm31.Mul(msb, qm31Const(256)))
}
