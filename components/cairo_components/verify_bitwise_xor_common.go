package cairo_components

import (
    "github.com/HerodotusDev/stwo-gnark-verifier/m31"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/math/uints"
)

func newVerifyBitwiseXorLookupComponent(
	api frontend.API,
	qm31 *m31.QM31Chip,
	interactionElements m31.InteractionElements,
	claimedSum m31.QM31,
	logSize uint8,
	termBits uint8,
	vanishEvalInv m31.QM31,
) *lookupConstraintComponent {
    columns := []PreprocessedColumn{
        NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(0)),
        NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(1)),
        NewPreprocessedColumnBitwiseXor(uints.NewU8(termBits), uints.NewU8(2)),
    }
	return newLookupConstraintComponent(api, qm31, interactionElements, claimedSum, uints.NewU8(logSize), columns, vanishEvalInv)
}
