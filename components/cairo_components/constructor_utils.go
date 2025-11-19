package cairo_components

import (
    "github.com/HerodotusDev/stwo-gnark-verifier/m31"
    "github.com/consensys/gnark/frontend"
    gnarkbits "github.com/consensys/gnark/std/math/bits"
    "github.com/consensys/gnark/std/math/uints"
)

// computeColumnSize computes 2^logSize inside the circuit and returns it as QM31.
// It uses square-and-multiply over the binary decomposition of the 8-bit value.
func computeColumnSize(api frontend.API, logSize uints.U8) m31.QM31 {
    bytesAPI, err := uints.NewBytes(api)
    if err != nil {
        panic(err)
    }

    logSizeValue := bytesAPI.Value(logSize)
    logSizeBits := gnarkbits.ToBinary(api, logSizeValue, gnarkbits.WithNbDigits(8))

    // Square and multiply to compute the column size
    columnSize := frontend.Variable(1)
    for i := 7; i >= 0; i-- {
        columnSize = api.Mul(columnSize, columnSize)
        candidate := api.Mul(columnSize, 2)
        columnSize = api.Select(logSizeBits[i], candidate, columnSize)
    }
    return m31.NewQM31FromM31(m31.NewM31Unchecked(columnSize))
}
