package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/frontend"
)

func newVerifyBitwiseXorLookupComponent(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claimedSum m31.QM31,
	logSize frontend.Variable,
	termBits frontend.Variable,
	vanishEvalInv m31.QM31,
) lookupConstraintComponent {
	columns := []PreprocessedColumn{
		NewPreprocessedColumnBitwiseXor(termBits, 0),
		NewPreprocessedColumnBitwiseXor(termBits, 1),
		NewPreprocessedColumnBitwiseXor(termBits, 2),
	}
	return newLookupConstraintComponent(api, qm31, interactionElements, claimedSum, logSize, columns, vanishEvalInv)
}
