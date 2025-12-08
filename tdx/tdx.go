package tdx

import (
	"github.com/kvinwang/dstack-mr/internal"
)

// Measurements Re-export the measurements type so callers don’t see/internal dependencies.
type Measurements = internal.TdxMeasurements

// MeasureTdxQemu Public wrapper that forwards to the internal implementation.
func MeasureTdxQemu(
	fwData []byte,
	kernelData []byte,
	initrdData []byte,
	memorySize uint64,
	cpuCount uint8,
	kernelCmdline string,
) (*Measurements, error) {
	return internal.MeasureTdxQemu(fwData, kernelData, initrdData, memorySize, cpuCount, kernelCmdline)
}
