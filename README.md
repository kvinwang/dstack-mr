# dstack-mr

A CLI tool for calculating TDX (Intel Trust Domain Extensions) measurements for Dstack images.

This project is based on [oasis-cli](https://github.com/oasisprotocol/cli) and modified for Dstack-specific TDX measurement requirements.

## Installation

```bash
go install github.com/kvinwang/dstack-mr@latest
```

## Usage

You can either specify files directly using command line options:
```bash
dstack-mr -fw firmware.bin -kernel vmlinuz [options]
```

Or use a Dstack metadata.json file:
```bash
dstack-mr -metadata metadata.json [options]
```

### Output Format
The tool outputs the following measurements:

```bash
# Text output (default)
MRTD: 1234567890abcdef...
RTMR0: abcdef1234567890...
RTMR1: 9876543210fedcba...
RTMR2: fedcba0987654321...
```

### JSON output (with -json flag)
```json
{
  "mrtd": "1234567890abcdef...",
  "rtmr0": "abcdef1234567890...",
  "rtmr1": "9876543210fedcba...",
  "rtmr2": "fedcba0987654321...",
}
```

### Measurement Details
- `MRTD`: Measured Root of Trust for Data
- `RTMR0`: Runtime Measurement Register 0
- `RTMR1`: Runtime Measurement Register 1
- `RTMR2`: Runtime Measurement Register 2

## License

Apache License 2.0
