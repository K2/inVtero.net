# inVtero.net Architecture

## Overview

inVtero.net is a cross-platform memory forensics framework designed for Virtual Machine Introspection (VMI) and physical memory analysis. The project uses microarchitecture-independent techniques to locate and extract process information from memory dumps without relying on OS-specific structures.

## Design Philosophy

The core design principle is to **avoid OS-logical dependencies** and instead leverage low-level hardware and CPU interaction patterns that are consistent across different operating systems and versions. This approach provides:

- **Future-proofing**: Works with unknown OS versions and future updates
- **Security**: Harder for attackers to manipulate underlying detection mechanisms
- **Versatility**: Single codebase handles multiple OS types (Windows, Linux, BSD)
- **Accuracy**: Based on hardware-level invariants rather than mutable OS structures

## Key Components

### 1. Core Engine (`inVtero.net`)

The main library implementing the analysis engine.

#### Core Classes

- **`Vtero`** (`inVtero.cs`): Main orchestration class that coordinates the entire analysis process
- **`Mem`** (`Mem.cs`): Physical memory abstraction and access layer
- **`PageTable`** (`PageTable.cs`): Page table parsing and virtual-to-physical address translation
- **`DetectedProc`** (`DetectedProc.cs`): Represents a detected process with its address space
- **`Scanner`** (`Scanner.cs`): Scans physical memory for process signatures
- **`VirtualScanner`** (`VirtualScanner.cs`): Scans virtual address spaces
- **`PhysicalMemoryStream`**: Provides stream-based access to physical memory

### 2. Memory Detection Techniques

#### Self-Pointer/Recursive Page Directory Detection

The primary technique for identifying processes without OS knowledge:

```
Windows: Self-pointer in PML4 (Page Map Level 4)
*BSD:    Recursive page directory pointer
Linux:   Direct mapping regions
```

This technique works by:
1. Scanning physical memory for page table structures
2. Identifying the self-referential entry pattern
3. Extracting CR3 values (page table base pointers)
4. Validating page table hierarchies

#### VMCS (Virtual Machine Control Structure) Detection

For nested hypervisor analysis:

1. Locates VMCS pages by signature
2. Extracts EPTP (Extended Page Table Pointer) from VMCS
3. Maps guest physical to host physical memory
4. Recursively processes nested virtualization layers

### 3. Specialties Module

Format-specific memory dump handlers in `inVtero.net/Specialties/`:

- **`VMWare.cs`**: VMware memory dump format (.vmem, .vmsn)
- **`XEN.cs`**: Xen hypervisor dump format
- **`CrashDump.cs`**: Windows crash dump (PAGEDUMP64) format
- **`AMemoryRunDetector.cs`**: Base class for memory run detection
- **`BasicRunDetector.cs`**: Generic memory run detection

### 4. Type System and Symbol Resolution

#### DIA Integration (`Dia2Sharp`)

Uses Microsoft Debug Interface Access SDK for symbol resolution:

- PDB file parsing
- Type information extraction
- Structure layout resolution
- Symbol-to-address mapping

#### Dynamic Type System

Leverages .NET Dynamic Language Runtime (DLR) for:
- Python scripting interface (IronPython)
- Dynamic member access on memory structures
- Runtime type reflection and binding

### 5. Support Modules

Located in `inVtero.net/Support/`:

- **`Capstone.cs`**: Disassembly engine integration
- **`Keystone.cs`**: Assembly engine integration
- **`JunctionPoint.cs`**: File system junction management
- **`Strings.cs`**: String extraction utilities
- **`WebAPI.cs`**: HTTP API support

### 6. Hashing and Integrity

Located in `inVtero.net/Hashing/`:

- **Hash-based code page verification**
- **Cryptographic attestation** (SHA256, TIGER192)
- **DeLocate** (`DeLocate.cs`): Matches memory pages to disk hashes
- **Relocation normalization** for hash comparison

### 7. PowerShell Integration (`inVteroPS`)

PowerShell cmdlets for memory analysis:
- Process enumeration
- Memory dumping
- Type resolution
- Scripting automation

### 8. UI Components

#### Console Utilities (`ConsoleUtils`)
- Progress bars
- Colored output
- Tabular data display

#### GUI (`inVteroUI`)
- Memory editing interface
- Disassembly viewer
- Hex editor with patching
- Interactive memory navigation

## Data Flow

### Analysis Pipeline

```
┌─────────────────┐
│  Memory Dump    │
│ (.vmem, .dmp,   │
│  .raw, .dd)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Mem Class     │  ◄── Format Detection
│ (Memory Access) │  ◄── Run Detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Scanner      │  ◄── Self-Pointer Search
│                 │  ◄── VMCS Detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PageTable      │  ◄── Page Table Walking
│  Construction   │  ◄── Address Translation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ DetectedProc    │  ◄── Process Grouping
│   Collection    │  ◄── Address Space Mapping
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Symbol Loading  │  ◄── PDB Resolution
│ Type Extraction │  ◄── Structure Binding
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Analysis      │  ◄── Python Scripts
│   Scripts       │  ◄── Custom Queries
└─────────────────┘
```

## Memory Run Management

### Problem
Memory dumps may use sparse storage (only storing non-zero pages), creating gaps in physical address space.

### Solution
- **Memory Run Detection**: Identifies contiguous physical memory regions
- **Gap Handling**: Tracks which physical addresses are actually present
- **PFN Bitmap**: Maintains bitmap of valid Page Frame Numbers
- **Run Metadata**: Stores base address and page count for each run

## Process Detection Algorithm

### Phase 1: Candidate Identification
1. Scan physical memory in parallel
2. Look for page table signatures (self-pointer patterns)
3. Validate page table hierarchy
4. Extract CR3 values

### Phase 2: Page Table Walking
1. Use CR3 as root page table address
2. Walk PML4 → PDP → PD → PT hierarchy
3. Collect all valid page mappings
4. Identify kernel vs. user space pages

### Phase 3: Process Grouping
1. Compare page table overlaps between candidates
2. Group processes by correlation percentage
3. Identify hypervisor layers vs. guest processes
4. Assign process types (Windows, Linux, BSD, etc.)

### Phase 4: Address Space Extraction
1. Build complete virtual memory map
2. Handle large pages (2MB, 1GB entries)
3. Process Software PTE states
4. Extract user and kernel memory

## Hypervisor Support

### VMware
- VMCS revision field: `0x00000001` (nested) or `0x00004000`
- EPTP location: Index 14 in VMCS
- Supports nested VMware instances

### Xen
- Xen-specific page table markers
- EPT (Extended Page Tables) handling
- PV (Paravirtualization) guest support

### Generic
- VMCS scanning works for Intel VT-x based hypervisors
- Extensible to new CPU microarchitectures

## Performance Optimizations

### Parallel Processing
- Multi-threaded memory scanning
- Concurrent page table walking
- Parallel process validation

### Caching
- Page cache for frequently accessed memory
- Memory-mapped file access
- Bitmap indexing for PFN lookups

### Memory Efficiency
- Stream-based memory access
- Lazy loading of page tables
- Sparse data structures for large address spaces

## Serialization and State Management

### Protocol Buffers
- Saves analysis state to `.inVtero` files
- Fast deserialization for repeated analysis
- Checkpoint/resume capability

### State Components
- Detected processes
- Page table structures
- Symbol information
- Memory run metadata

## Cross-Platform Support

### .NET Framework (Windows)
- Full feature set
- DIA symbol support
- PowerShell integration

### .NET Core (Linux, macOS, BSD)
- Symbol servers for type resolution
- Subset of Windows features
- Core analysis functionality

## Extension Points

### Custom Memory Run Detectors
Implement `IMemAwareChecking` interface:
```csharp
public interface IMemAwareChecking
{
    bool IsSupportedFormat(Mem mem);
    MemoryDescriptor ExtractMemory(Mem mem);
}
```

### Custom Scanners
Extend `AMemoryRunDetector` base class for new dump formats.

### Python Scripting
Use IronPython to extend functionality:
- Custom memory walkers
- Structure parsers
- Analysis workflows

## Security Considerations

### Trustworthy Analysis
- Hardware-based detection resists OS-level tampering
- Cryptographic hash verification of code pages
- No dependency on potentially compromised OS structures

### Hash-Based Attestation
- Compare memory pages to known-good hashes
- Detect code modifications
- Identify injected/hooked code

### Limitations
- Assumes hardware page tables are trustworthy
- SMM (System Management Mode) not analyzed
- Firmware-level rootkits not detected

## Project Structure

```
inVtero.net/
├── inVtero.net/          # Core library
│   ├── Specialties/      # Format handlers
│   ├── Support/          # Utility classes
│   ├── Hashing/          # Integrity verification
│   ├── PS/               # PowerShell support
│   └── GUI/              # UI components
├── inVtero.core/         # .NET Core version
│   ├── inVteroCore/      # Core functionality
│   ├── Dia2Sharp/        # Symbol resolution
│   └── quickcore/        # Core quickdumps
├── quickdumps/           # Example application
├── inVteroUI/            # GUI application
├── inVteroPS/            # PowerShell module
├── ConsoleUtils/         # Console helpers
├── Dia2Sharp/            # DIA interop
├── Scripts/              # Python analysis scripts
└── Reloc.net/            # Relocation utilities
```

## Dependencies

### Required
- .NET Framework 4.6.1+ (Windows) or .NET Core 2.0+ (Cross-platform)
- msdia140.dll (Windows, for symbol resolution)

### Optional
- Capstone (disassembly)
- Keystone (assembly)
- IronPython (scripting)
- libyara (pattern matching)

## Future Directions

### Planned Enhancements
- 5-level page table support (Intel's LA57)
- ARM64 architecture support
- Enhanced nested virtualization detection
- Improved memory gap handling
- Automated EPTP index brute-forcing

### Research Areas
- SMM analysis integration
- Firmware introspection
- Real-time memory monitoring
- Automated malware detection workflows

## References

- [Actaeon Project](http://www.syssec-project.eu/m/page-media/3/raid13_graziano.pdf) - VMCS-based VM extraction
- [Rekall](https://github.com/google/rekall) - Memory forensics framework
- [Volatility](https://www.volatilityfoundation.org/) - Memory analysis framework
- Intel VT-x Specification - Virtualization extensions
- AMD-V Specification - AMD virtualization
