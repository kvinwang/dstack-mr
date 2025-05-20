package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kvinwang/dstack-mr/internal"
)

type DStackMetadata struct {
	Bios    string `json:"bios"`
	Kernel  string `json:"kernel"`
	Cmdline string `json:"cmdline"`
	Initrd  string `json:"initrd"`
}

type measurementOutput struct {
	MRTD         string `json:"mrtd"`
	RTMR0        string `json:"rtmr0"`
	RTMR1        string `json:"rtmr1"`
	RTMR2        string `json:"rtmr2"`
}

const (
	GB = 1024 * 1024 * 1024 // in bytes
	MB = 1024 * 1024
)

var knownKeyProviders = map[string]string{
	"sgx-v0": "0x4888adb026ff91c1320c4f544a9f5d9e0561e13fc64947a10aa1556d0071b2cc",
	"none":   "0x3369c4d32b9f1320ebba5ce9892a283127b7e96e1d511d7f292e5d9ed2c10b8c",
}

// parseMemorySize parses a human readable memory size (e.g., "1G", "512M") into bytes
func parseMemorySize(size string) (uint64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))
	if len(size) == 0 {
		return 0, fmt.Errorf("empty memory size")
	}

	// Check if the input is purely numeric (no unit)
	if _, err := strconv.ParseUint(size, 10, 64); err == nil {
		// If it's a valid number with no unit, interpret as MB
		num, _ := strconv.ParseUint(size, 10, 64)
		return num, nil
	}

	// Get the unit (last character)
	unit := size[len(size)-1:]
	// Get the number (everything except the last character)
	numStr := size[:len(size)-1]

	// Parse the number
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size number: %v", err)
	}

	// Convert to bytes based on unit
	switch unit {
	case "G":
		return num * GB, nil // Convert GB to bytes
	case "M":
		return num * MB, nil // Convert MB to bytes
	default:
		return 0, fmt.Errorf("invalid memory unit '%s', must be one of: G, M", unit)
	}
}

type memoryValue uint64

func (m *memoryValue) String() string {
	m_bytes := uint64(*m)
	if m_bytes >= GB && m_bytes%GB == 0 {
		return fmt.Sprintf("%dG", m_bytes/GB)
	}
	if m_bytes >= MB && m_bytes%MB == 0 {
		return fmt.Sprintf("%dM", m_bytes/MB)
	}
	return fmt.Sprintf("%d", m_bytes)
}

func (m *memoryValue) Set(value string) error {
	m_bytes, err := parseMemorySize(value)
	if err != nil {
		return err
	}
	*m = memoryValue(m_bytes)
	return nil
}

func main() {
	const defaultMrKeyProvider = "0x0000000000000000000000000000000000000000000000000000000000000000"
	var (
		fwPath        string
		kernelPath    string
		initrdPath    string
		memorySize    memoryValue
		cpuCountUint  uint
		kernelCmdline string
		jsonOutput    bool
		metadataPath  string
		mrKeyProvider string = defaultMrKeyProvider
	)

	flag.StringVar(&fwPath, "fw", "", "Path to firmware file")
	flag.StringVar(&kernelPath, "kernel", "", "Path to kernel file")
	flag.StringVar(&initrdPath, "initrd", "", "Path to initrd file")
	flag.Var(&memorySize, "memory", "Memory size (e.g., 512M, 1G, 2G)")
	flag.UintVar(&cpuCountUint, "cpu", 1, "Number of CPUs")
	flag.StringVar(&kernelCmdline, "cmdline", "", "Kernel command line")
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.StringVar(&metadataPath, "metadata", "", "Path to DStack metadata.json file")
	flag.StringVar(&mrKeyProvider, "mrkp", defaultMrKeyProvider, "Measurement of key provider")
	flag.Parse()

	// If the mrKeyProvider is in the knownKeyProviders, replace it with the value
	if knownKeyProvider, ok := knownKeyProviders[mrKeyProvider]; ok {
		mrKeyProvider = knownKeyProvider
	}

	// If metadata file is provided, read it and override other options
	if metadataPath != "" {
		metadataDir := filepath.Dir(metadataPath)
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			fmt.Printf("Error reading metadata file: %v\n", err)
			os.Exit(1)
		}

		var metadata DStackMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			fmt.Printf("Error parsing metadata file: %v\n", err)
			os.Exit(1)
		}

		// Override paths with metadata values
		if fwPath == "" {
			fwPath = filepath.Join(metadataDir, metadata.Bios)
		}
		if kernelPath == "" {
			kernelPath = filepath.Join(metadataDir, metadata.Kernel)
		}
		if initrdPath == "" && metadata.Initrd != "" {
			initrdPath = filepath.Join(metadataDir, metadata.Initrd)
		}
		if kernelCmdline == "" {
			kernelCmdline = metadata.Cmdline
			if metadata.Initrd != "" {
				kernelCmdline += " initrd=initrd"
			}
		}
	}

	if fwPath == "" || kernelPath == "" {
		fmt.Println("Error: firmware and kernel paths are required (either directly or via metadata.json)")
		flag.Usage()
		os.Exit(1)
	}

	// Read files
	fwData, err := os.ReadFile(fwPath)
	if err != nil {
		fmt.Printf("Error reading firmware file: %v\n", err)
		os.Exit(1)
	}

	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		fmt.Printf("Error reading kernel file: %v\n", err)
		os.Exit(1)
	}

	var initrdData []byte
	if initrdPath != "" {
		initrdData, err = os.ReadFile(initrdPath)
		if err != nil {
			fmt.Printf("Error reading initrd file: %v\n", err)
			os.Exit(1)
		}
	}

	// Calculate measurements
	measurements, err := internal.MeasureTdxQemu(fwData, kernelData, initrdData, uint64(memorySize), uint8(cpuCountUint), kernelCmdline)
	if err != nil {
		fmt.Printf("Error calculating measurements: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output := measurementOutput{
			MRTD:         fmt.Sprintf("%x", measurements.MRTD),
			RTMR0:        fmt.Sprintf("%x", measurements.RTMR0),
			RTMR1:        fmt.Sprintf("%x", measurements.RTMR1),
			RTMR2:        fmt.Sprintf("%x", measurements.RTMR2),
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Printf("Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("MRTD: %x\n", measurements.MRTD)
		fmt.Printf("RTMR0: %x\n", measurements.RTMR0)
		fmt.Printf("RTMR1: %x\n", measurements.RTMR1)
		fmt.Printf("RTMR2: %x\n", measurements.RTMR2)
	}
}
