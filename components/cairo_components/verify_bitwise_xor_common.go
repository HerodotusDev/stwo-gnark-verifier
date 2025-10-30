package cairo_components

import (
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/consensys/gnark/std/math/uints"
)

func newVerifyBitwiseXorLookupComponent(
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claimedSum m31.QM31,
	logSize uint8,
	termBits uint8,
) *lookupConstraintComponent {
	columns := []PreprocessedColumn{
		NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(0)),
		NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(1)),
		NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(2)),
	}
	return newLookupConstraintComponent(qm31, interactionElements, claimedSum, logSize, columns)
}
