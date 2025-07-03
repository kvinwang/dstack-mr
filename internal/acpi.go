package internal

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

//go:embed *.json.gz
var templates embed.FS

// GenerateTablesQemu generates ACPI tables for the given TD configuration.
//
// Returns the raw ACPI tables, RSDP and QEMU table loader command blob.
func GenerateTablesQemu(memorySize uint64, cpuCount uint8, dstackVersion uint32) ([]byte, []byte, []byte, error) {
	if cpuCount == 0 {
		return nil, nil, nil, fmt.Errorf("cpuCount must be greater than 0")
	}
	// Load and decompress template data
	templateGz, err := templates.ReadFile(fmt.Sprintf("templates-v%d.json.gz", dstackVersion))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read template data: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(templateGz))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	templateJSON, err := io.ReadAll(gr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decompress template data: %w", err)
	}

	type TemplateData struct {
		Tables  []string `json:"tables"`
		Offsets []int    `json:"offsets"`
	}
	templates := TemplateData{}
	if err := json.Unmarshal(templateJSON, &templates); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse template data: %w", err)
	}

	if len(templates.Tables) < int(cpuCount) {
		return nil, nil, nil, fmt.Errorf("template for %d CPUs is not available", cpuCount)
	}

	tplData := templates.Tables[cpuCount]
	if tplData == "" {
		return nil, nil, nil, fmt.Errorf("template for %d CPUs is not available", cpuCount)
	}

	tpl, err := hex.DecodeString(tplData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("malformed ACPI table template, %w", err)
	}

	// Find all required ACPI tables.
	dsdtOffset, dsdtCsum, dsdtLen, err := findAcpiTable(tpl, "DSDT")
	if err != nil {
		return nil, nil, nil, err
	}

	rangeMinimumOffset := templates.Offsets[cpuCount]
	lengthOffset := templates.Offsets[cpuCount] + 12

	// Handle memory split at 2816 MiB (0xB0000000).
	if memorySize >= 0xB0000000 {
		binary.LittleEndian.PutUint32(tpl[rangeMinimumOffset:], 0x80000000)
		binary.LittleEndian.PutUint32(tpl[lengthOffset:], 0x60000000)
	} else {
		memSizeBytes := uint32(memorySize)
		binary.LittleEndian.PutUint32(tpl[rangeMinimumOffset:], memSizeBytes)
		binary.LittleEndian.PutUint32(tpl[lengthOffset:], 0xe0000000-memSizeBytes)
	}

	facpOffset, facpCsum, facpLen, err := findAcpiTable(tpl, "FACP")
	if err != nil {
		return nil, nil, nil, err
	}
	apicOffset, apicCsum, apicLen, err := findAcpiTable(tpl, "APIC")
	if err != nil {
		return nil, nil, nil, err
	}
	mcfgOffset, mcfgCsum, mcfgLen, err := findAcpiTable(tpl, "MCFG")
	if err != nil {
		return nil, nil, nil, err
	}
	waetOffset, waetCsum, waetLen, err := findAcpiTable(tpl, "WAET")
	if err != nil {
		return nil, nil, nil, err
	}
	rsdtOffset, rsdtCsum, rsdtLen, err := findAcpiTable(tpl, "RSDT")
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate RSDP.
	rsdp := append([]byte{},
		0x52, 0x53, 0x44, 0x20, 0x50, 0x54, 0x52, 0x20, // Signature ("RSDP PTR ").
		0x00,                               // Checksum.
		0x42, 0x4F, 0x43, 0x48, 0x53, 0x20, // OEM ID ("BOCHS ").
		0x00, // Revision.
	)

	// Update RSDP with RSDT address.
	var rsdtAddress [4]byte
	binary.LittleEndian.PutUint32(rsdtAddress[:], rsdtOffset)
	rsdp = append(rsdp, rsdtAddress[:]...)

	// Generate table loader commands.
	const ldrLength = 4096
	ldr := qemuLoaderAppend(nil, &qemuLoaderCmdAllocate{"etc/acpi/rsdp", 16, 2})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAllocate{"etc/acpi/tables", 64, 1})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", dsdtCsum, dsdtOffset, dsdtLen}) // DSDT
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", facpOffset + 36, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", facpOffset + 40, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", facpOffset + 140, 8})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", facpCsum, facpOffset, facpLen}) // FACP
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", apicCsum, apicOffset, apicLen}) // APIC
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", mcfgCsum, mcfgOffset, mcfgLen}) // MCFG
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", waetCsum, waetOffset, waetLen}) // WAET
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", rsdtOffset + 36, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", rsdtOffset + 40, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", rsdtOffset + 44, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/tables", "etc/acpi/tables", rsdtOffset + 48, 4})
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/tables", rsdtCsum, rsdtOffset, rsdtLen}) // RSDT
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddPtr{"etc/acpi/rsdp", "etc/acpi/tables", 16, 4})             // RSDT address
	ldr = qemuLoaderAppend(ldr, &qemuLoaderCmdAddChecksum{"etc/acpi/rsdp", 8, 0, 20})                        // RSDP
	if len(ldr) < ldrLength {
		ldr = append(ldr, bytes.Repeat([]byte{0x00}, ldrLength-len(ldr))...)
	}

	return tpl, rsdp, ldr, nil
}

// findAcpiTable searches for the ACPI table with the given signature and returns its offset,
// checksum offset and length.
func findAcpiTable(tables []byte, signature string) (uint32, uint32, uint32, error) {
	if len(tables) < 12 {
		return 0, 0, 0, fmt.Errorf("ACPI table is too short")
	}
	// Walk the tables to find the right one.
	var offset int
	for {
		if offset >= len(tables) {
			return 0, 0, 0, fmt.Errorf("ACPI table '%s' not found", signature)
		}

		tblSig := string(tables[offset : offset+4])
		tblLen := int(binary.LittleEndian.Uint32(tables[offset+4 : offset+8]))
		if tblSig == signature {
			return uint32(offset), uint32(offset + 9), uint32(tblLen), nil
		}
		if tblLen == 0 {
			return 0, 0, 0, fmt.Errorf("ACPI table '%s' not found at offset %d", tblSig, offset)
		}
		// Skip other tables.
		offset += tblLen
	}
}

type qemuLoaderCmdAllocate struct {
	file      string
	alignment uint32
	zone      uint8
}

type qemuLoaderCmdAddPtr struct {
	pointerFile   string
	pointeeFile   string
	pointerOffset uint32
	pointerSize   uint8
}

type qemuLoaderCmdAddChecksum struct {
	file         string
	resultOffset uint32
	start        uint32
	length       uint32
}

func qemuLoaderAppend(data []byte, cmd interface{}) []byte {
	appendFixedString := func(str string) {
		const fixedLength = 56
		data = append(data, []byte(str)...)
		if len(str) < fixedLength {
			data = append(data, bytes.Repeat([]byte{0x00}, fixedLength-len(str))...)
		}
	}

	switch c := cmd.(type) {
	case *qemuLoaderCmdAllocate:
		data = append(data, 0x01, 0x00, 0x00, 0x00)

		appendFixedString(c.file)

		var val [4]byte
		binary.LittleEndian.PutUint32(val[:], c.alignment)
		data = append(data, val[:]...)

		data = append(data, c.zone)
		data = append(data, bytes.Repeat([]byte{0x00}, 63)...) // Padding.
	case *qemuLoaderCmdAddPtr:
		data = append(data, 0x02, 0x00, 0x00, 0x00)

		appendFixedString(c.pointerFile)
		appendFixedString(c.pointeeFile)

		var val [4]byte
		binary.LittleEndian.PutUint32(val[:], c.pointerOffset)
		data = append(data, val[:]...)
		data = append(data, c.pointerSize)
		data = append(data, bytes.Repeat([]byte{0x00}, 7)...) // Padding.
	case *qemuLoaderCmdAddChecksum:
		data = append(data, 0x03, 0x00, 0x00, 0x00)

		appendFixedString(c.file)

		var val [4]byte
		binary.LittleEndian.PutUint32(val[:], c.resultOffset)
		data = append(data, val[:]...)

		binary.LittleEndian.PutUint32(val[:], c.start)
		data = append(data, val[:]...)

		binary.LittleEndian.PutUint32(val[:], c.length)
		data = append(data, val[:]...)

		data = append(data, bytes.Repeat([]byte{0x00}, 56)...) // Padding.
	default:
		panic("unsupported command")
	}
	return data
}
