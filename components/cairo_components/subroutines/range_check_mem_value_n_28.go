package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type RangeCheckMemValueN28Result struct {
	Sum         m31.QM31
	RangeSums14 [14]m31.QM31
}

func RangeCheckMemValueN28Evaluate(
	qm31 *m31.QM31Chip,
	limbs []m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) RangeCheckMemValueN28Result {
	if len(limbs) != 28 {
		panic("RangeCheckMemValueN28Evaluate expects 28 limbs")
	}

	var rangeSums [14]m31.QM31
	for i := 0; i < 14; i++ {
		pair := limbs[i*2 : i*2+2]
		res, err := qm31.Combine(rangeCheckElements, pair)
		if err != nil {
			panic(err)
		}
		rangeSums[i] = res
	}

	return RangeCheckMemValueN28Result{
		Sum:         sum,
		RangeSums14: rangeSums,
	}
}
