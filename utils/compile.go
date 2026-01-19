package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend"
)

// CompileOptionsFromEnv builds compile options from environment variables.
// Profiles:
//   - GNARK_COMPILE_PROFILE=dev (default): no options unless explicitly set.
//   - GNARK_COMPILE_PROFILE=release: apply explicit options below.
//
// Options:
//   - GNARK_COMPILE_CAPACITY=<int>
//   - GNARK_COMPRESS_THRESHOLD=<int>
func CompileOptionsFromEnv() ([]frontend.CompileOption, error) {
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("GNARK_COMPILE_PROFILE")))
	if profile == "" {
		profile = "dev"
	}

	var opts []frontend.CompileOption
	hasCapacity := false
	hasThreshold := false
	if capRaw := strings.TrimSpace(os.Getenv("GNARK_COMPILE_CAPACITY")); capRaw != "" {
		capacity, err := strconv.Atoi(capRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid GNARK_COMPILE_CAPACITY: %w", err)
		}
		if capacity > 0 {
			opts = append(opts, frontend.WithCapacity(capacity))
			hasCapacity = true
		}
	}

	if thresholdRaw := strings.TrimSpace(os.Getenv("GNARK_COMPRESS_THRESHOLD")); thresholdRaw != "" {
		threshold, err := strconv.Atoi(thresholdRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid GNARK_COMPRESS_THRESHOLD: %w", err)
		}
		if threshold > 0 {
			opts = append(opts, frontend.WithCompressThreshold(threshold))
			hasThreshold = true
		}
	}

	if profile != "dev" && profile != "release" {
		return nil, fmt.Errorf("invalid GNARK_COMPILE_PROFILE: %q", profile)
	}

	if profile == "release" {
		if !hasCapacity {
			opts = append(opts, frontend.WithCapacity(30_000_000))
		}
		if !hasThreshold {
			opts = append(opts, frontend.WithCompressThreshold(200))
		}
	}

	return opts, nil
}
