# YARA Monster

A lightweight pattern-based malware detection system implemented in C++ using the YARA rule module. This tool performs static analysis of executable files through recursive directory traversal, matching binary content against predefined signature rulesets to identify potentially malicious software.

**Authors:** Dale Louize M. Almonia & Stefan G. Niedes  
**Course:** CMSC 131 - Special Topics  
**Platform:** Windows (MSYS2 MinGW UCRT64)  
**Project Duration:** Completed within one month of development

## Features

- **Fast Recursive Scanning**: Efficiently traverses directories and scans files (195 files/second on test corpus)
- **Multiple YARA Rules**: Includes pre-configured rules for detecting various malware families
- **Flexible File Filtering**: Scan specific file extensions or all files
- **Timeout Protection**: Per-file timeout prevents hanging on large or problematic files (capped at 10 minutes)
- **Comprehensive Reporting**: Generates JSON and CSV reports of scan results
- **Detailed Logging**: Thread-safe logging with ISO 8601 timestamps for audit trails
- **RAII Resource Management**: Safe YARA library integration with automatic cleanup
- **Defensive Error Handling**: Gracefully handles permission errors, missing files, and corrupted binaries

## Included Malware Detection Rules

The scanner includes custom YARA rules developed through static analysis for detecting:

- **clipboardHijacker**: Clipboard manipulation malware
- **cryptoshuffler**: Cryptocurrency theft malware targeting wallet addresses
- **discordia**: Discord-based cryptocurrency miner
- **fallchill**: APT malware associated with targeted attacks (tuned strict rule)
- **gh0st/locky**: Remote access trojan (RAT) and ransomware variants
- **kbot**: Information stealer with network capabilities
- **locky**: Ransomware using environment and clipboard APIs
- **magala**: Multi-function malware with grouped API conditions
- **manuscrypt**: Backdoor trojan with HTTP communication
- **rekaf**: Advanced persistent threat (APT) malware with service manipulation

All rules were developed using PE static analysis tools (PEstudio) to extract API imports and behavioral characteristics.

## Prerequisites (Windows Only)

### Required Software

- **Windows 10/11**
- **MSYS2** with MinGW UCRT64 environment
- **YARA library 4.5.5+** with development headers
- **OpenSSL** (libcrypto, libssl) - required by YARA
- **zlib** - required by YARA

### Installing MSYS2 and Dependencies

**Step 1: Install MSYS2**

1. Download MSYS2 installer from [msys2.org](https://www.msys2.org/)
2. Run the installer (e.g., `msys2-x86_64-20231026.exe`)
3. Install to default location: `C:\msys64\`
4. Complete installation wizard

**Step 2: Open MSYS2 MinGW UCRT64 Terminal**

⚠️ **IMPORTANT**: You must use the **MSYS2 MinGW UCRT64** terminal, not:
- MSYS2 MSYS
- MSYS2 MinGW32
- MSYS2 MinGW64

Find it in: Start Menu → MSYS2 → **MSYS2 MINGW UCRT64**

**Step 3: Update Package Database**

```bash
pacman -Syu
```

If prompted to close the terminal, do so and reopen MSYS2 MinGW UCRT64, then run:

```bash
pacman -Su
```

**Step 4: Install Required Packages**

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc \
          mingw-w64-ucrt-x86_64-yara \
          mingw-w64-ucrt-x86_64-openssl \
          mingw-w64-ucrt-x86_64-zlib
```

**Step 5: Verify Installation**

```bash
gcc --version
yara --version
```

Both commands should display version information without errors.

## Building the Scanner

### Clone the Repository

Open **MSYS2 MinGW UCRT64** terminal and run:

```bash
# Clone the repository
git clone https://github.com/stepanmonster/CMSC-131-YARA_Monster
cd CMSC-131-YARA_Monster
```

On Windows, the repository will typically be located at:
```
C:\Users\YourUsername\CMSC-131-YARA_Monster
```

### Compile the Project

**Step 1: Create Build Directory**

```bash
mkdir -p build
```

**Step 2: Compile Using g++**

Run this command as a **single line** in the MSYS2 MinGW UCRT64 terminal:

```bash
g++ -std=c++17 -O2 -I "yara-4.5.5/libyara/include" src/main.cpp src/yara_scan.cpp src/traverse.cpp -L "yara-4.5.5/libyara/lib" -lyara -lcrypto -lssl -lz -o build/yara_app.exe
```

**Note**: If your YARA installation is in a different location, adjust the `-I` (include) and `-L` (library) paths accordingly. Common YARA locations in MSYS2:
- `/ucrt64/include/yara.h`
- `/ucrt64/lib/libyara.a`

You can find your YARA installation with:
```bash
pacman -Ql mingw-w64-ucrt-x86_64-yara | grep include
```

### Verify Build

```bash
./build/yara_app.exe --help
```

You should see usage information displayed.

## Usage

### Basic Scan

Scan the current directory with default settings:

```bash
./build/yara_app.exe --rules rules/all.yar --root .
```

### Scan Specific Directory

```bash
./build/yara_app.exe --rules rules/all.yar --root C:/Users/YourName/Desktop/samples
```

**Windows Path Notes:**
- Use forward slashes: `C:/path/to/directory`
- Or escape backslashes: `C:\\path\\to\\directory`
- Paths with spaces need quotes: `"C:/Program Files/test"`

### Advanced Usage Examples

**Scan only executables and DLLs:**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/samples --ext .exe,.dll
```

**Scan with custom timeout (30 seconds per file):**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/samples --timeout-ms 30000
```

**Quiet mode (no console output):**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/samples --quiet
```

**Custom report location:**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/samples --report-dir C:/scan_results --report-base myscan
```

**Complete example with all options:**
```bash
./build/yara_app.exe --rules C:/CMSC-131-YARA_Monster/rules/all.yar \
                     --root C:/samples \
                     --ext .exe,.dll,.sys \
                     --timeout-ms 10000 \
                     --report-dir C:/reports \
                     --report-base scan_results \
                     --log C:/logs/scan.log
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--rules PATH` | Path to YARA rules file | `rules/all.yar` |
| `--root DIR` | Root directory to scan | `.` (current directory) |
| `--ext .ext1,.ext2` | Comma-separated file extensions to scan | All files |
| `--timeout-ms N` | Per-file scan timeout in milliseconds | `10000` (10 seconds) |
| `--report-dir DIR` | Output directory for reports | `reports` |
| `--report-base NAME` | Base name for report files | `scan` |
| `--log PATH` | Path to log file | `logs/scan.log` |
| `--quiet` | Suppress console output | `false` |
| `--help` | Display help message | - |

## Output

### Console Output

Real-time match notifications during scanning:

```
[MATCH] rule=cryptoshuffler file=C:/samples/malware.exe
[MATCH] rule=fallchill_malware file=C:/samples/backdoor.dll
Files scanned: 3090
Matches: 10
Reports: reports/scan.json and .csv
```

Use `--quiet` to suppress console output while still generating logs and reports.

### JSON Report

Location: `reports/scan.json`

```json
{
  "rule_path": "rules/all.yar",
  "root_dir": "C:/samples",
  "stats": {
    "files_scanned": 3090,
    "matches": 10,
    "errors": 0,
    "skipped": 0,
    "duration_ms": 15841
  },
  "matches": [
    {"rule": "cryptoshuffler", "file": "C:/samples/malware.exe"},
    {"rule": "fallchill_malware", "file": "C:/samples/backdoor.dll"}
  ]
}
```

### CSV Report

Location: `reports/scan.csv`

```csv
rule,file
cryptoshuffler,"C:/samples/malware.exe"
fallchill_malware,"C:/samples/backdoor.dll"
locky,"C:/samples/ransomware.dll"
```

Can be opened in Excel or any spreadsheet application.

### Log File

Location: `logs/scan.log`

```
2025-11-28T10:15:30 [INFO] start rules=rules/all.yar root=C:/samples
2025-11-28T10:15:35 [INFO] match rule=cryptoshuffler file=C:/samples/malware.exe
2025-11-28T10:15:38 [INFO] match rule=fallchill_malware file=C:/samples/backdoor.dll
2025-11-28T10:16:12 [INFO] done files_scanned=3090 matches=10 duration_ms=15841
```

Logs include ISO 8601 timestamps for audit trails.

## Performance Metrics

Based on validation testing on Windows:

- **Test Corpus:** 3,090 files
- **Scan Duration:** ~15.8 seconds (15,841 ms)
- **Throughput:** ~195 files/second
- **Average Latency:** ~5.1 ms per file
- **Detection Rate:** 10 matches on test corpus

Performance may vary based on:
- File sizes and types
- Complexity of YARA rules
- Disk I/O speed (SSD recommended)
- CPU capabilities
- Antivirus interference (Windows Defender may slow scans)

## Project Structure

```
CMSC-131-YARA_Monster/
├── README.md
├── src/
│   ├── main.cpp          # Entry point, CLI parsing, orchestration
│   ├── yara_scan.hpp     # YARA engine RAII wrapper (interface)
│   ├── yara_scan.cpp     # YARA C API integration
│   ├── traverse.hpp      # Directory traversal (interface)
│   ├── traverse.cpp      # Recursive filesystem walking
│   ├── report.hpp        # Report generation (JSON/CSV)
│   └── log.hpp           # Thread-safe logging utilities
├── rules/
│   ├── all.yar           # Combined ruleset
│   ├── clipboardhijacker.yar
│   ├── cryptoshuffler.yar
│   ├── discordiaminer.yar
│   ├── fallchill.yar
│   ├── ghost.yar
│   ├── kbot.yar
│   ├── locky.yar
│   ├── magala.yar
│   ├── manuscrypt.yar
│   └── rekaf.yar
├── build/                # Build output (not in repo)
│   └── yara_app.exe
├── logs/                 # Generated at runtime
│   └── scan.log
└── reports/              # Generated at runtime
    ├── scan.json
    └── scan.csv
```

## Creating Custom YARA Rules

### Rule Development Workflow

1. **Static Analysis**: Use PEstudio to analyze malware samples
   - Download PEstudio from [winitor.com](https://www.winitor.com/)
   - Load PE file and examine imports, strings, sections
   
2. **Extract Indicators**: Identify distinctive features
   - API imports (e.g., `VirtualAlloc`, `CreateRemoteThread`)
   - String patterns (URLs, registry keys, mutexes)
   - PE characteristics (section names, file size ranges)
   
3. **Write YARA Rule**: Create signature file
   
4. **Test & Refine**: Validate and adjust

### Example Rule Template

Create a new file in `rules/` directory (e.g., `rules/my_malware.yar`):

```yara
import "pe"

rule my_malware_detection
{
    meta:
        author = "YourName"
        description = "Detects specific malware family"
        date = "2025-11-28"
        tags = "malware, custom, trojan"
        reference = "https://example.com/analysis"
        
    strings:
        // API imports - common in malicious behavior
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        
        // String indicators
        $str1 = "malicious_string" ascii wide
        $str2 = "C:\\Windows\\Temp\\payload.exe" ascii wide
        
        // URLs or C2 domains
        $url1 = "http://malicious-c2.com" ascii
        
        // Registry keys
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        
    condition:
        // Validate PE file format
        uint16(0) == 0x5a4d and
        
        // File size constraints (reduce false positives)
        filesize > 10KB and filesize < 500KB and
        
        // Require multiple indicators
        (
            (2 of ($api*) and 1 of ($str*)) or
            (all of ($api*)) or
            (any of ($url*) and 1 of ($reg*))
        )
}
```

### Testing Your Custom Rule

```bash
# Test against single file
./build/yara_app.exe --rules rules/my_malware.yar --root C:/test_samples/

# Test against directory
./build/yara_app.exe --rules rules/my_malware.yar --root C:/samples/ --ext .exe
```

### Best Practices for Windows PE Analysis

- **Use PE-specific conditions**: `uint16(0) == 0x5a4d` validates MZ header
- **Check import tables**: Focus on suspicious API combinations
- **Add file size ranges**: Avoid matching on system files
- **Test on benign files**: Scan `C:\Windows\System32` to check for false positives
- **Combine multiple indicators**: Require 2+ matches to reduce false positives
- **Document your rules**: Use meta fields for future reference

## Troubleshooting

### Build Issues

**Error: "yara.h: No such file or directory"**

Solution:
```bash
# Find YARA installation
pacman -Ql mingw-w64-ucrt-x86_64-yara | grep include

# Update -I flag in compile command to match location
g++ -std=c++17 -O2 -I "/ucrt64/include" src/main.cpp ...
```

**Error: "cannot find -lyara"**

Solution:
```bash
# Find YARA library
pacman -Ql mingw-w64-ucrt-x86_64-yara | grep libyara.a

# Update -L flag in compile command
g++ ... -L "/ucrt64/lib" -lyara ...
```

**Wrong MSYS2 environment**

Symptoms: Build succeeds but `yara_app.exe` crashes or shows DLL errors

Solution: Ensure you're using **MSYS2 MinGW UCRT64**, not MINGW64 or MINGW32
```bash
# Verify environment
echo $MSYSTEM
# Should output: UCRT64
```

### Runtime Issues

**"rules not found" error**

Solution:
- Verify path is correct: `ls rules/all.yar`
- Use forward slashes: `--rules C:/path/to/rules.yar`
- Check file permissions (ensure read access)

**"Cannot open rules" compilation error**

Solution:
```bash
# Test rule syntax manually
yara -c rules/your_rule.yar

# Common issues:
# - Unclosed strings
# - Missing braces
# - Invalid import statements
```

**Windows Defender interferes with scanning**

Symptoms: Very slow scanning, "Access denied" errors

Solution:
1. Add exclusion for the scanner executable
2. Add exclusion for the scan target directory
3. Settings → Virus & threat protection → Exclusions

**Permission denied errors**

Solution:
- Run MSYS2 terminal as Administrator for system directories
- Or scan user-accessible directories only
- Check logs for specific files causing issues

**No matches on known malware samples**

Solution:
1. Test rule in isolation:
```bash
yara rules/specific_rule.yar C:/samples/malware.exe
```
2. Check if PE file: `file C:/samples/malware.exe`
3. Verify rule conditions aren't too strict
4. Review `logs/scan.log` for details

**Very slow scanning**

Solution:
- Reduce timeout: `--timeout-ms 5000`
- Limit file types: `--ext .exe,.dll`
- Exclude large directories: Avoid scanning `C:\Windows\`
- Use SSD storage
- Disable real-time antivirus temporarily
- Check for network-mapped drives (slow)

**Path issues with spaces**

Solution:
```bash
# Use quotes around paths
./build/yara_app.exe --root "C:/Program Files/test"

# Or use forward slashes without spaces
./build/yara_app.exe --root C:/ProgramFiles/test
```

## Testing and Quality Assurance

### Running Tests

**1. Help Display Test**
```bash
./build/yara_app.exe --help
```
Expected: Usage information displays correctly

**2. Empty Directory Test**
```bash
mkdir C:/test_empty
./build/yara_app.exe --rules rules/all.yar --root C:/test_empty
```
Expected: Completes with 0 files scanned, 0 matches

**3. Known Sample Test**
```bash
./build/yara_app.exe --rules rules/cryptoshuffler.yar --root C:/malware_samples/
```
Expected: Detects known samples, logs matches

**4. False Positive Test**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/Windows/System32 --ext .exe
```
Expected: Few or no matches on legitimate Windows files

**5. Performance Test**
```bash
./build/yara_app.exe --rules rules/all.yar --root C:/large_corpus/
```
Expected: Check `logs/scan.log` for reasonable duration

### Known Limitations

- ⚠️ No dedicated unit-test framework (tests are manual)
- ⚠️ Windows Defender may interfere with scanning performance
- ⚠️ Network-mounted drives not benchmarked
- ⚠️ Very large files (>100MB) may cause timeouts
- ⚠️ No interactive rule debugging mode

## Scope and Limitations

### What YARA-Monster Does ✅

- Static signature-based malware detection on Windows
- Recursive directory scanning with extension filtering
- Integration with YARA C API for pattern matching
- Custom rule support for multiple malware families
- Structured JSON/CSV reporting and detailed logging
- Configurable timeouts and error handling

### What YARA-Monster Does NOT Do ❌

- Dynamic analysis, sandboxing, or behavioral monitoring
- Real-time filesystem monitoring or on-access scanning
- Automatic rule generation using machine learning
- Network traffic inspection or IDS/IPS functionality
- Execution of malware samples (static analysis only)
- Full antivirus capabilities (signatures require updates)
- Cross-platform support (Windows/MSYS2 only)

### Project Constraints

- **Educational focus**: Designed for learning and small-scale analysis
- **Single-host operation**: No distributed scanning
- **Static detection only**: Relies on signature matches
- **Windows-primary**: Developed and tested exclusively on Windows with MSYS2
- **Safety-first**: No live malware execution during development

## Architecture Overview

### Core Components

1. **Command-Line Interface** (`main.cpp`)
   - Argument parsing and validation
   - Orchestrates scan workflow
   - Coordinates all modules

2. **YARA Engine Wrapper** (`yara_scan.hpp/cpp`)
   - RAII-based resource management
   - One-time rule compilation
   - Callback-based match collection

3. **Filesystem Traversal** (`traverse.hpp/cpp`)
   - Recursive directory walking
   - Extension-based filtering
   - Error-tolerant iteration

4. **Logging System** (`log.hpp`)
   - Thread-safe operations
   - ISO 8601 timestamps
   - File and console output

5. **Reporting Module** (`report.hpp`)
   - In-memory result aggregation
   - JSON and CSV export
   - Statistics tracking

### Data Flow

```
CLI Args → Configuration → YARA Compilation
    ↓
Directory Traversal → File List
    ↓
Per-File Scanning → Match Collection
    ↓
Statistics Update → Report Generation
    ↓
JSON/CSV Output + Logs
```

## License

This project is released under the **MIT License** for educational purposes.

### Copyright

Copyright (c) 2025 Dale Louize M. Almonia & Stefan G. Niedes

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

### Important Security Notes

⚠️ **Authorization Required**: Ensure you have proper authorization before scanning any systems  
⚠️ **Educational Use**: This tool is designed for learning and research purposes  
⚠️ **No Malicious Use**: Do not use for unauthorized access or malicious activities  
⚠️ **Static Analysis Only**: This scanner does not execute or detonate malware samples  
⚠️ **Windows Only**: Designed and tested exclusively for Windows with MSYS2

## Contributing

We welcome contributions! Here's how:

### How to Contribute

1. **Fork** the repository on GitHub
2. **Clone** your fork in MSYS2 MinGW UCRT64:
```bash
git clone https://github.com/your-username/CMSC-131-YARA_Monster
```
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make changes** with clear commits
5. **Test on Windows/MSYS2**:
   - Verify compilation succeeds
   - Run sample scans
   - Check logs and reports
6. **Submit pull request** with description

### Contribution Areas

- 🎯 **New YARA Rules**: Additional malware family signatures for Windows PE files
- 🚀 **Performance**: Optimization for Windows filesystem
- 🐛 **Bug Fixes**: Issue resolution and edge cases
- 📚 **Documentation**: Improved guides for Windows users
- 🧪 **Testing**: Expanded test coverage

## Acknowledgments

### Project Team

- **Dale Louize M. Almonia** - Co-designer and developer
- **Stefan G. Niedes** - Co-designer and developer

### Special Thanks

- **Sir Rene B. Jocsing** - CMSC 131 instructor, project guidance and supervision
- **YARA Project Maintainers** - For the powerful pattern-matching engine
- **MSYS2 Project** - For providing excellent MinGW-w64 toolchain for Windows
- **Open-Source Security Community** - For YARA rule collections and best practices
- **Booz Allen Hamilton** - MOTIF malware dataset for validation

### Third-Party Libraries

- **YARA (libyara)** - Pattern matching engine ([docs](https://yara.readthedocs.io/))
- **OpenSSL** - Cryptographic library
- **zlib** - Compression library
- **MSYS2 MinGW UCRT64** - Development toolchain for Windows

### Tools Used

- **PEstudio** - PE static analysis for Windows executables
- **GitHub** - Version control and collaboration
- **MSYS2 MinGW UCRT64** - Primary development environment

## References and Resources

### Official Documentation

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA C API Reference](https://yara.readthedocs.io/en/stable/capi.html)
- [MSYS2 Documentation](https://www.msys2.org/docs/)

### Research and Datasets

- [MOTIF Malware Dataset](https://github.com/boozallen/MOTIF) - Booz Allen Hamilton
- [PEstudio Overview](https://www.varonis.com/blog/pestudio) - Varonis Blog
- [What is PeStudio?](https://www.geeksforgeeks.org/dsa/what-is-pestudio/) - GeeksforGeeks

### Community Resources

- [YARA Rules Repository](https://github.com/Yara-Rules/rules) - Community rules
- [Awesome YARA](https://github.com/InQuest/awesome-yara) - Curated YARA resources

## Project Status

**Current Version:** 1.0.0  
**Status:** ✅ Complete (Course Project Submission)  
**Platform:** Windows (MSYS2 MinGW UCRT64)  
**Last Updated:** November 2025

### Future Enhancements

Potential improvements for future iterations:
- Integration with Google Test framework
- CMake build system for easier compilation
- Web-based dashboard for results (Windows-native)
- Machine learning-based rule suggestions
- Real-time filesystem monitoring using Windows APIs
- Integration with Windows Event Log

---

**Repository:** [github.com/stepanmonster/CMSC-131-YARA_Monster](https://github.com/stepanmonster/CMSC-131-YARA_Monster)  
**Course:** CMSC 131 - Special Topics  
**Platform:** Windows with MSYS2 MinGW UCRT64

---

*For questions, issues, or suggestions, please open an issue on GitHub or contact the project team.*