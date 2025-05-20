package internal

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/foxboron/go-uefi/authenticode"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// measureSha384 computes a SHA384 of the given blob.
func measureSha384(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

// measureTdxKernelCmdline measures the kernel cmdline.
func measureTdxKernelCmdline(cmdline string) []byte {
	// Add a NUL byte at the end.
	d := append([]byte(cmdline), 0x00)
	// Convert to UTF-16LE.
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	xr := transform.NewReader(bytes.NewReader(d), utf16le)
	converted, _ := io.ReadAll(xr)
	return measureSha384(converted)
}

// measureTdxQemuTdHob measures the TD HOB.
func measureTdxQemuTdHob(memorySize uint64, meta *tdvfMetadata) []byte {
	// Construct a TD hob in the same way as QEMU does. Note that all fields are little-endian.
	// See: https://github.com/intel-staging/qemu-tdx/blob/tdx-qemu-next/hw/i386/tdvf-hob.c
	var tdHob []byte
	// Discover the TD HOB base address from TDVF metadata.
	tdHobBaseAddr := uint64(0x809000) // TD HOB base address.
	if meta != nil {
		for _, s := range meta.sections {
			if s.secType == tdvfSectionTdHob {
				tdHobBaseAddr = s.memoryAddress
				break
			}
		}
	}

	// Start with EFI_HOB_TYPE_HANDOFF.
	tdHob = append(tdHob,
		0x01, 0x00, // Header.HobType (EFI_HOB_TYPE_HANDOFF)
		0x38, 0x00, // Header.HobLength (56 bytes)
		0x00, 0x00, 0x00, 0x00, // Header.Reserved
		0x09, 0x00, 0x00, 0x00, // Version (EFI_HOB_HANDOFF_TABLE_VERSION)
		0x00, 0x00, 0x00, 0x00, // BootMode
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiMemoryTop
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiMemoryBottom
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiFreeMemoryTop
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiFreeMemoryBottom
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiEndOfHobList (filled later)
	)

	// The rest of the HOBs are EFI_HOB_TYPE_RESOURCE_DESCRIPTOR.
	remainingMemory := memorySize
	addMemoryResourceHob := func(resourceType uint8, start, length uint64) {
		tdHob = append(tdHob,
			0x03, 0x00, // Header.HobType (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR)
			0x30, 0x00, // Header.HobLength (48 bytes)
			0x00, 0x00, 0x00, 0x00, // Header.Reserved
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Owner
			resourceType, 0x00, 0x00, 0x00, // ResourceType
			0x07, 0x00, 0x00, 0x00, // ResourceAttribute
		)

		var val [8]byte
		binary.LittleEndian.PutUint64(val[:], start)
		tdHob = append(tdHob, val[:]...) // PhysicalStart
		binary.LittleEndian.PutUint64(val[:], length)
		tdHob = append(tdHob, val[:]...) // Length

		// Subtract from remaining memory.
		remainingMemory -= length
	}

	addMemoryResourceHob(0x07, 0x0000000000000000, 0x0000000000800000)
	addMemoryResourceHob(0x00, 0x0000000000800000, 0x0000000000006000)
	addMemoryResourceHob(0x07, 0x0000000000806000, 0x0000000000003000)
	addMemoryResourceHob(0x00, 0x0000000000809000, 0x0000000000002000)
	addMemoryResourceHob(0x00, 0x000000000080B000, 0x0000000000002000)
	addMemoryResourceHob(0x07, 0x000000000080D000, 0x0000000000004000)
	addMemoryResourceHob(0x00, 0x0000000000811000, 0x000000000000f000)

	// Handle memory split at 2816 MiB (0xB0000000).
	if memorySize >= 0xB0000000 {
		addMemoryResourceHob(0x07, 0x0000000000820000, 0x000000007F7E0000)
		addMemoryResourceHob(0x07, 0x0000000100000000, remainingMemory)
	} else {
		addMemoryResourceHob(0x07, 0x0000000000820000, remainingMemory)
	}

	// Update EfiEndOfHobList.
	var val [8]byte
	binary.LittleEndian.PutUint64(val[:], tdHobBaseAddr+uint64(len(tdHob))+8)
	copy(tdHob[48:56], val[:])

	// Measure the TD HOB.
	return measureSha384(tdHob)
}

// measureLog computes a measurement of the given RTMR event log by simulating extending the RTMR.
func measureLog(log [][]byte) []byte {
	var mr [48]byte // Initialize to zero.
	for _, entry := range log {
		h := sha512.New384()
		_, _ = h.Write(mr[:])
		_, _ = h.Write(entry)
		copy(mr[:], h.Sum([]byte{}))
	}
	return mr[:]
}

// measureTdxQemuAcpiTables measures QEMU-generated ACPI tables for TDX.
func measureTdxQemuAcpiTables(memorySize uint64, cpuCount uint8) ([]byte, []byte, []byte, error) {
	// Generate ACPI tables
	tables, rsdp, loader, err := GenerateTablesQemu(memorySize, cpuCount)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ACPI tables: %w", err)
	}

	// Measure ACPI tables
	return measureSha384(tables), measureSha384(rsdp), measureSha384(loader), nil
}

// measureTdxQemuKernelImage measures QEMU-patched TDX kernel image.
func measureTdxQemuKernelImage(kernelData []byte, initRdSize uint32, memSize uint64, acpiDataSize uint32) ([]byte, error) {
	return MeasureTdxQemuKernelImageData(kernelData, initRdSize, memSize, acpiDataSize)
}

func MeasureTdxQemuKernelImageData(kernelData []byte, initRdSize uint32, memSizeBytes uint64, acpiDataSize uint32) ([]byte, error) {
	// Check if kernel data is long enough for all required fields
	const minKernelLength = 0x1000
	if len(kernelData) < minKernelLength {
		return nil, fmt.Errorf("kernel data too short: need at least %d bytes, got %d", minKernelLength, len(kernelData))
	}

	// Create a mutable copy of the kernel data
	kd := make([]byte, len(kernelData))
	copy(kd, kernelData)

	// Get protocol version from kernel header
	protocol := uint16(kd[0x206]) + (uint16(kd[0x207]) << 8)

	// Determine addresses based on protocol version
	var realAddr, cmdlineAddr uint32
	if protocol < 0x200 || (kd[0x211]&0x01) == 0 {
		// Low kernel
		realAddr = 0x90000
		cmdlineAddr = 0x9a000
	} else if protocol < 0x202 {
		// High but ancient kernel
		realAddr = 0x90000
		cmdlineAddr = 0x9a000
	} else {
		// High and recent kernel
		realAddr = 0x10000
		cmdlineAddr = 0x20000
	}

	if protocol >= 0x200 {
		kd[0x210] = 0xb0 // type_of_loader = Qemu v0
	}
	if protocol >= 0x201 {
		kd[0x211] |= 0x80 // loadflags |= CAN_USE_HEAP
		// heap_end_ptr
		binary.LittleEndian.PutUint32(kd[0x224:0x224+4], cmdlineAddr-realAddr-0x200)
	}

	if protocol >= 0x202 {
		// cmd_line_ptr
		binary.LittleEndian.PutUint32(kd[0x228:0x228+4], cmdlineAddr)
	} else {
		// For older protocols
		binary.LittleEndian.PutUint16(kd[0x20:0x20+2], 0xA33F)
		binary.LittleEndian.PutUint16(kd[0x22:0x22+2], uint16(cmdlineAddr-realAddr))
	}

	// Handle initrd if size is non-zero
	if initRdSize > 0 {
		// Check protocol version - must be >= 0x200 to support initrd
		if protocol < 0x200 {
			return nil, fmt.Errorf("linux kernel too old to load a ram disk (protocol version 0x%x)", protocol)
		}

		// Determine initrd_max based on protocol version
		var initrdMax uint32
		if protocol >= 0x20c {
			xlf := binary.LittleEndian.Uint16(kd[0x236 : 0x236+2])
			if (xlf & 0x40) != 0 {
				// XLF_CAN_BE_LOADED_ABOVE_4G (0x40) is set
				initrdMax = ^uint32(0) // UINT32_MAX
			} else {
				initrdMax = 0x37ffffff
			}
		} else if protocol >= 0x203 {
			initrdMax = binary.LittleEndian.Uint32(kd[0x22c : 0x22c+4])
			if initrdMax == 0 {
				initrdMax = 0x37ffffff
			}
		} else {
			initrdMax = 0x37ffffff
		}

		// Calculate below_4g_mem_size
		var below4gMemSize uint32
		lowmem := uint32(0x80000000)
		if memSizeBytes < 0xb0000000 {
			lowmem = 0xb0000000
		}
		if memSizeBytes >= uint64(lowmem) {
			below4gMemSize = lowmem
		} else {
			below4gMemSize = uint32(memSizeBytes)
		}

		// Adjust initrd_max based on memory size and ACPI data size
		if initrdMax >= below4gMemSize-acpiDataSize {
			initrdMax = below4gMemSize - acpiDataSize - 1
		}

		if initRdSize >= initrdMax {
			return nil, fmt.Errorf("initrd is too large (max: %d, need: %d)", initrdMax, initRdSize)
		}

		initrdAddr := (initrdMax - initRdSize) & ^uint32(4095)

		// Store initrd address and size in kernel header
		binary.LittleEndian.PutUint32(kd[0x218:0x218+4], initrdAddr)
		binary.LittleEndian.PutUint32(kd[0x21c:0x21c+4], initRdSize)
	}

	parsed, err := authenticode.Parse(bytes.NewReader(kd))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %w", err)
	}
	return parsed.Hash(crypto.SHA384), nil
}

// encodeGUID encodes an UEFI GUID into binary form.
func encodeGUID(guid string) []byte {
	var data []byte
	atoms := strings.Split(guid, "-")
	for idx, atom := range atoms {
		raw, err := hex.DecodeString(atom)
		if err != nil {
			panic("bad GUID")
		}

		if idx <= 2 {
			// Little-endian.
			for i := range raw {
				data = append(data, raw[len(raw)-1-i])
			}
		} else {
			// Big-endian.
			data = append(data, raw...)
		}
	}
	return data
}

// measureTdxEfiVariable measures an EFI variable event.
func measureTdxEfiVariable(vendorGUID string, varName string) []byte {
	var data []byte
	data = append(data, encodeGUID(vendorGUID)...)

	var encLen [8]byte
	binary.LittleEndian.PutUint64(encLen[:], uint64(len(varName)))
	data = append(data, encLen[:]...)
	binary.LittleEndian.PutUint64(encLen[:], 0)
	data = append(data, encLen[:]...)

	// Convert varName to UTF-16LE.
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	xr := transform.NewReader(bytes.NewReader([]byte(varName)), utf16le)
	converted, _ := io.ReadAll(xr)
	data = append(data, converted...)

	return measureSha384(data)
}

const (
	attributeMrExtend   = 0b00000000_00000000_00000000_00000001
	attributePageAug    = 0b00000000_00000000_00000000_00000010
	pageSize            = 0x1000
	mrExtendGranularity = 0x100

	tdvfSectionTdHob = 0x02
)

type tdvfSection struct {
	dataOffset     uint32
	rawDataSize    uint32
	memoryAddress  uint64
	memoryDataSize uint64
	secType        uint32
	attributes     uint32
}

type tdvfMetadata struct {
	sections []*tdvfSection
}

const (
	mrtdVariantTwoPass    = 0
	mrtdVariantSinglePass = 1
)

func (m *tdvfMetadata) computeMrtd(fw []byte, variant int) []byte {
	h := sha512.New384()

	memPageAdd := func(s *tdvfSection, page uint64) {
		if s.attributes&attributePageAug == 0 {
			// Use TDCALL [TDH.MEM.PAGE.ADD].
			//
			// Byte 0 through 11 contain the ASCII string 'MEM.PAGE.ADD'.
			// Byte 16 through 23 contain the GPA (in little-endian format).
			// All the other bytes contain 0.
			var buf [128]byte
			copy(buf[:12], []byte("MEM.PAGE.ADD"))
			binary.LittleEndian.PutUint64(buf[16:24], s.memoryAddress+page*pageSize)
			_, _ = h.Write(buf[:])
		}
	}

	mrExtend := func(s *tdvfSection, page uint64) {
		if s.attributes&attributeMrExtend != 0 {
			// Need TDCALL [TDH.MR.EXTEND].
			for i := range pageSize / mrExtendGranularity {
				// Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
				// Byte 16 through 23 contain the GPA (in little-endian format).
				// All the other bytes contain 0.
				var buf [128]byte
				copy(buf[:9], []byte("MR.EXTEND"))
				binary.LittleEndian.PutUint64(buf[16:24], s.memoryAddress+page*pageSize+uint64(i*mrExtendGranularity))
				_, _ = h.Write(buf[:])

				// The other two extension buffers contain the chunk’s content.
				chunkOffset := int(s.dataOffset) + int(page*pageSize) + i*mrExtendGranularity
				_, _ = h.Write(fw[chunkOffset : chunkOffset+mrExtendGranularity])
			}
		}
	}

	for _, s := range m.sections {
		numPages := s.memoryDataSize / pageSize

		// There are two known implementations of how QEMU is performing TD initialization:
		//
		// - First add all pages using MEM.PAGE.ADD and then in a second pass perform MR.EXTEND for
		//   for each page (Variant 0).
		//
		// - For each page first add it using MEM.PAGE.ADD and then perform MR.EXTEND for that same
		//   page (Variant 1).
		//
		// Unfortunately, changing these orders changes the MRTD computation so we need both.
		switch variant {
		case mrtdVariantTwoPass:
			for page := range numPages {
				memPageAdd(s, page)
			}
			for page := range numPages {
				mrExtend(s, page)
			}
		case mrtdVariantSinglePass:
			for page := range numPages {
				memPageAdd(s, page)
				mrExtend(s, page)
			}
		default:
			panic("unknown MRTD variant")
		}
	}
	return h.Sum(nil)
}

// parseTdvfMetadata parses the TDVF metadata from the firmware blob.
//
// See Section 11 of "Intel TDX Virtual Firmware Design Guide" for details.
func parseTdvfMetadata(fw []byte) (*tdvfMetadata, error) {
	const (
		tdxMetadataOffsetGUID = "e47a6535-984a-4798-865e-4685a7bf8ec2"
		tdxMetadataVersion    = 1
		tdvfSignature         = "TDVF"
		tableFooterGUID       = "96b582de-1fb2-45f7-baea-a366c55a082d"
		bytesAfterTableFooter = 32
	)

	offset := len(fw) - bytesAfterTableFooter
	encodedFooterGUID := encodeGUID(tableFooterGUID)
	guid := fw[offset-16 : offset]
	tablesLen := int(binary.LittleEndian.Uint16(fw[offset-16-2 : offset-16]))
	if !bytes.Equal(guid, encodedFooterGUID) {
		return nil, fmt.Errorf("malformed OVMF table footer")
	}
	if tablesLen == 0 || tablesLen > offset-16-2 {
		return nil, fmt.Errorf("malformed OVMF table footer")
	}
	tables := fw[offset-16-2-tablesLen : offset-16-2]
	offset = len(tables)

	// Find TDVF metadata table in OVMF, starting at the end.
	var data []byte
	encodedGUID := encodeGUID(tdxMetadataOffsetGUID)
	for {
		if offset < 18 {
			return nil, fmt.Errorf("missing TDVF metadata in firmware")
		}

		// The data structure is:
		//
		//   arbitrary length data
		//   2 byte length of entire entry
		//   16 byte GUID
		//
		guid = tables[offset-16 : offset]
		entryLen := int(binary.LittleEndian.Uint16(tables[offset-16-2 : offset-16]))
		if offset < 18+entryLen {
			return nil, fmt.Errorf("malformed OVMF table in firmware at offset %d", offset)
		}

		if bytes.Equal(guid, encodedGUID) {
			data = tables[offset-18-entryLen : offset-18]
			break
		}

		offset -= entryLen
	}
	if data == nil {
		return nil, fmt.Errorf("missing TDVF metadata in firmware")
	}

	// Extract and parse TDVF metadata descriptor:
	//
	//   4 byte signature
	//   4 byte length
	//   4 byte version
	//   4 byte number of section entries
	//   32 byte each section * number of sections
	//
	tdvfMetaOffset := int(binary.LittleEndian.Uint32(data[len(data)-4:]))
	tdvfMetaOffset = len(fw) - tdvfMetaOffset
	tdvfMetaDesc := fw[tdvfMetaOffset : tdvfMetaOffset+16]
	if string(tdvfMetaDesc[:4]) != tdvfSignature {
		return nil, fmt.Errorf("malformed TDVF metadata descriptor in firmware")
	}
	tdvfVersion := binary.LittleEndian.Uint32(tdvfMetaDesc[8:12])
	tdvfNumberOfSectionEntries := int(binary.LittleEndian.Uint32(tdvfMetaDesc[12:16]))
	if tdvfVersion != 1 {
		return nil, fmt.Errorf("unsupported TDVF metadata descriptor version in firmware")
	}

	// Parse section entries.
	var meta tdvfMetadata
	for section := range tdvfNumberOfSectionEntries {
		secOffset := tdvfMetaOffset + 16 + 32*section
		secData := fw[secOffset : secOffset+32]

		s := &tdvfSection{
			dataOffset:     binary.LittleEndian.Uint32(secData[:4]),
			rawDataSize:    binary.LittleEndian.Uint32(secData[4:8]),
			memoryAddress:  binary.LittleEndian.Uint64(secData[8:16]),
			memoryDataSize: binary.LittleEndian.Uint64(secData[16:24]),
			secType:        binary.LittleEndian.Uint32(secData[24:28]),
			attributes:     binary.LittleEndian.Uint32(secData[28:32]),
		}

		// Sanity check section.
		if s.memoryAddress%pageSize != 0 {
			return nil, fmt.Errorf("TDVF metadata section %d has non-aligned memory address", section)
		}
		if s.memoryDataSize < uint64(s.rawDataSize) {
			return nil, fmt.Errorf("TDVF metadata section %d memory data size is less than raw data size", section)
		}
		if s.memoryDataSize%pageSize != 0 {
			return nil, fmt.Errorf("TDVF metadata section %d has non-aligned memory data size", section)
		}
		if s.attributes&attributeMrExtend != 0 && uint64(s.rawDataSize) < s.memoryDataSize {
			return nil, fmt.Errorf("TDVF metadata section %d raw data size is less than memory data size", section)
		}

		meta.sections = append(meta.sections, s)
	}
	return &meta, nil
}

// TdxMeasurements contains all the measurement values for TDX
type TdxMeasurements struct {
	MRTD  []byte
	RTMR0 []byte
	RTMR1 []byte
	RTMR2 []byte
}

// CalculateMrAggregated calculates mr_aggregated = sha256(mrtd+rtmr0+rtmr1+rtmr2+mr_key_provider)
func (m *TdxMeasurements) CalculateMrAggregated(mrKeyProvider string) string {
	// Strip "0x" prefix if present
	mrKeyProvider = strings.TrimPrefix(mrKeyProvider, "0x")
	mrKeyProviderBytes, err := hex.DecodeString(mrKeyProvider)
	if err != nil {
		panic("invalid mr_key_provider")
	}
	h := sha256.New()
	h.Write(m.MRTD)
	h.Write(m.RTMR0)
	h.Write(m.RTMR1)
	h.Write(m.RTMR2)
	h.Write(mrKeyProviderBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// CalculateMrImage calculates mr_image = sha256(mrtd+rtmr1+rtmr2)
func (m *TdxMeasurements) CalculateMrImage() string {
	h := sha256.New()
	h.Write(m.MRTD)
	h.Write(m.RTMR1)
	h.Write(m.RTMR2)
	return hex.EncodeToString(h.Sum(nil))
}

func MeasureTdxQemu(fwData []byte, kernelData []byte, initrdData []byte, memorySize uint64, cpuCount uint8, kernelCmdline string) (*TdxMeasurements, error) {
	// Parse TDVF metadata.
	tdvfMeta, err := parseTdvfMetadata(fwData)
	if err != nil {
		return nil, err
	}

	measurements := &TdxMeasurements{}

	// Calculate MRTD
	measurements.MRTD = tdvfMeta.computeMrtd(fwData, mrtdVariantTwoPass)

	// RTMR0 calculation (existing code)
	tdHobHash := measureTdxQemuTdHob(memorySize, tdvfMeta)
	cfvImageHash, _ := hex.DecodeString("344BC51C980BA621AAA00DA3ED7436F7D6E549197DFE699515DFA2C6583D95E6412AF21C097D473155875FFD561D6790")
	boot000Hash, _ := hex.DecodeString("23ADA07F5261F12F34A0BD8E46760962D6B4D576A416F1FEA1C64BC656B1D28EACF7047AE6E967C58FD2A98BFA74C298")
	acpiTablesHash, acpiRsdpHash, acpiLoaderHash, err := measureTdxQemuAcpiTables(memorySize, cpuCount)
	if err != nil {
		return nil, err
	}

	rtmr0Log := append([][]byte{},
		tdHobHash,
		cfvImageHash,
		measureTdxEfiVariable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "SecureBoot"),
		measureTdxEfiVariable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "PK"),
		measureTdxEfiVariable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "KEK"),
		measureTdxEfiVariable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "db"),
		measureTdxEfiVariable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbx"),
		measureSha384([]byte{0x00, 0x00, 0x00, 0x00}), // Separator.
		acpiLoaderHash,
		acpiRsdpHash,
		acpiTablesHash,
		measureSha384([]byte{0x00, 0x00}), // BootOrder
		boot000Hash,                       // Boot000
	)
	measurements.RTMR0 = measureLog(rtmr0Log)

	// RTMR1 calculation
	var err2 error
	kernelAuthHash, err2 := measureTdxQemuKernelImage(kernelData, uint32(len(initrdData)), memorySize, 0x28000)
	if err2 != nil {
		return nil, err2
	}
	rtmr1Log := append([][]byte{},
		kernelAuthHash,
		measureSha384([]byte("Calling EFI Application from Boot Option")),
		measureSha384([]byte{0x00, 0x00, 0x00, 0x00}), // Separator.
		measureSha384([]byte("Exit Boot Services Invocation")),
		measureSha384([]byte("Exit Boot Services Returned with Success")),
	)
	measurements.RTMR1 = measureLog(rtmr1Log)

	// RTMR2 calculation
	rtmr2Log := append([][]byte{},
		measureTdxKernelCmdline(kernelCmdline),
		measureSha384(initrdData),
	)
	measurements.RTMR2 = measureLog(rtmr2Log)

	return measurements, nil
}
