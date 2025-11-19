# User Guide

## Table of Contents
- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Python Scripting](#python-scripting)
- [Common Workflows](#common-workflows)
- [Output Interpretation](#output-interpretation)
- [Best Practices](#best-practices)

## Introduction

inVtero.net is a memory forensics tool that analyzes physical memory dumps to extract processes, detect hypervisors, and perform virtual machine introspection. Unlike traditional tools, it doesn't require OS-specific profiles or configuration.

### What Can inVtero.net Do?

- ✅ Detect and extract processes from memory dumps
- ✅ Identify nested hypervisors (VMware, Xen)
- ✅ Work with multiple OS types (Windows, Linux, BSD)
- ✅ Verify code integrity using cryptographic hashes
- ✅ Support multiple dump formats (.vmem, .vmsn, .dmp, .raw, .xendump)
- ✅ Provide Python scripting interface for custom analysis
- ✅ Resolve symbols automatically from Microsoft symbol server

### Supported Input Formats

| Format | Description | Source |
|--------|-------------|--------|
| `.vmem` | VMware snapshot memory | VMware Workstation/ESXi |
| `.vmsn` | VMware suspended state | VMware Workstation |
| `.dmp` | Windows crash dump | Windows blue screen |
| `.raw`, `.dd` | Raw memory dump | Various acquisition tools |
| `.xendump` | Xen memory dump | Xen hypervisor |
| Generic | Flat binary file | Custom tools |

## Quick Start

### Analyze a Memory Dump (Windows)

```cmd
# Basic analysis
quickdumps.exe -f "C:\dumps\memory.dmp"

# Save results to file
quickdumps.exe -f "C:\dumps\memory.dmp" > analysis.txt
```

### Analyze a Memory Dump (Linux/macOS)

```bash
cd inVtero.core/quickcore/bin/Release/net6.0
dotnet quickcore.dll -f "/path/to/memory.dump"
```

### Using Python Scripts

```cmd
# Windows
cd Scripts
ipy Analyze.py

# Edit MemList in Main.py or Analyze.py to point to your dumps
```

## Basic Usage

### Command-Line Analysis with quickdumps

**Syntax**:
```
quickdumps [options]
```

**Common Options**:
```
-f <file>         Specify memory dump file
--save            Save analysis state
--load            Load previous analysis state
--verbose         Enable verbose output
--generic         Force generic scanning (for unknown OS)
```

**Example**:
```cmd
quickdumps.exe -f "Windows2016.vmem" --save --verbose
```

### Understanding the Output

#### Phase 1: Detection
```
Process CR3 [00000002DD41F000] File Offset [0000000293A12000] Type [Windows]
159 candidate process page tables found
```
- **CR3**: Page table base register value (process identifier)
- **File Offset**: Location in dump file
- **Type**: Detected OS type

#### Phase 2: Hypervisor Detection
```
Hypervisor: VMCS revision field: 16384 [00004000]
Hypervisor: Windows CR3 found [00000000016A0000] @ PAGE/File Offset = [00000001262DA000]
```
- **VMCS**: Virtual Machine Control Structure detected
- Shows nested VM instances and their CR3 values

#### Phase 3: Process Grouping
```
MemberProces: Group 1 Type [Windows] Group Correlation [100.000%] PID [1AB000]
MemberProces: Group 1 Type [Windows] Group Correlation [90.909%] PID [16A0000]
```
- Groups processes by shared memory regions
- High correlation = same VM/OS instance
- Multiple groups = multiple VM instances or nested VMs

### Working with Detected Processes

After detection, processes are grouped and can be accessed via the API or scripts.

## Advanced Features

### Memory Run Detection

For dumps with sparse storage (e.g., from EnCase):

```python
copts = ConfigOptions()
copts.ForceSingleFlatMemRun = True  # Treat as contiguous
copts.FileName = "memory.dump"
```

### Type-Specific Scanning

Scan for specific OS or hypervisor types:

```python
from inVtero.net import PTType

copts.VersionsToEnable = PTType.Windows  # Windows only
copts.VersionsToEnable = PTType.LinuxS   # Linux only  
copts.VersionsToEnable = PTType.FreeBSD  # FreeBSD only
copts.VersionsToEnable = PTType.VMCS     # Hypervisors only
copts.VersionsToEnable = PTType.GENERIC  # All types
```

### Symbol Resolution

Automatic symbol downloading:

```python
from System import Environment

# Set symbol path before analysis
sympath = "SRV*C:\\Symbols*http://msdl.microsoft.com/download/symbols"
Environment.SetEnvironmentVariable("_NT_SYMBOL_PATH", sympath)

# Load symbols for a process
kvs = proc.ScanAndLoadModules()
```

### Extracting Memory Regions

```python
# Extract entire address space to file
proc.DumpASToFile("output.bin")

# Extract specific virtual address range
mem_region = proc.MemAccess.ReadVirtualMemory(0x7FF00000, 0x1000)
```

### Process Integrity Verification

```python
from inVtero.net.Hashing import HashDB

# Verify process code pages against known hashes
hashdb = HashDB()
integrity_map = proc.VerifyIntegrity(hashdb)

# Check for modifications
for addr, hash_result in integrity_map:
    if hash_result.Modified:
        print(f"Modified page at: {addr:016X}")
```

## Python Scripting

### Basic Script Structure

```python
import clr
import System
clr.AddReferenceToFileAndPath("inVtero.net.dll")
from inVtero.net import *

# Configure options
copts = ConfigOptions()
copts.FileName = "C:\\dumps\\memory.dmp"
copts.VersionsToEnable = PTType.GENERIC

# Analyze
vtero = Scan.Scanit(copts)

# Access detected processes
for proc in vtero.Processes:
    print(f"Process CR3: {proc.CR3Value:016X}")
    print(f"Type: {proc.PT.RootTableType}")
```

### Walking Process Lists

Example from `Analyze.py`:

```python
def WalkProcListExample(vtero, proc):
    """Walk the Windows EPROCESS list"""
    
    # Get kernel symbols
    kvs = proc.ScanAndLoadModules()
    
    # Find PsActiveProcessHead
    ps_head_addr = kvs.PsActiveProcessHead
    
    # Get _EPROCESS type
    eproc_type = kvs.GetTypeInfo("_EPROCESS")
    
    # Walk the list
    current = ps_head_addr
    while True:
        # Read EPROCESS structure
        eproc = proc.GetStructure(current, eproc_type)
        
        # Extract process name
        image_name = eproc.ImageFileName
        pid = eproc.UniqueProcessId
        
        print(f"PID: {pid} Name: {image_name}")
        
        # Next entry
        current = eproc.ActiveProcessLinks.Flink
        if current == ps_head_addr:
            break
```

### Scanning for Patterns

```python
# Scan physical memory for a byte pattern
pattern = b"\x4D\x5A\x90\x00"  # MZ header
matches = vtero.MemAccess.ScanFor(pattern)

for match_addr in matches:
    print(f"Found pattern at: {match_addr:016X}")
```

### Custom Memory Structures

Using dynamic types:

```python
# Define structure layout
class MyStruct:
    def __init__(self, mem, addr):
        self.field1 = mem.ReadUInt64(addr)
        self.field2 = mem.ReadUInt64(addr + 8)
        self.name = mem.ReadString(addr + 16, 32)

# Use it
my_struct = MyStruct(proc.MemAccess, 0x12345000)
print(my_struct.name)
```

## Common Workflows

### Workflow 1: Extract All Processes from VMware Memory

```python
# 1. Configure
copts = ConfigOptions()
copts.FileName = "Windows10.vmem"
copts.VersionsToEnable = PTType.GENERIC

# 2. Scan
vtero = Scan.Scanit(copts)

# 3. Group processes
groups = vtero.GroupDetectedProcesses()

# 4. For each group (VM instance)
for group_id, procs in enumerate(groups):
    print(f"\n=== VM Instance {group_id} ===")
    
    # 5. Select kernel process (lowest CR3)
    kernel_proc = min(procs, key=lambda p: p.CR3Value)
    
    # 6. Load symbols
    kvs = kernel_proc.ScanAndLoadModules()
    
    # 7. Extract process list
    # (use WalkProcListExample from above)
```

### Workflow 2: Verify System Integrity

```python
# 1. Analyze dump
vtero = Scan.Scanit(copts)
kernel_proc = vtero.KernelProc

# 2. Load symbols
kvs = kernel_proc.ScanAndLoadModules()

# 3. Verify kernel modules
for module in kvs.Modules:
    hash_matches = module.VerifyHash()
    if not hash_matches:
        print(f"MODIFIED: {module.Name}")
    else:
        print(f"OK: {module.Name}")
```

### Workflow 3: Dump Specific Process Memory

```python
# 1. Find target process
target_cr3 = 0x1AB000  # From initial scan
target_proc = next(p for p in vtero.Processes if p.CR3Value == target_cr3)

# 2. Extract full address space
output_file = "process_dump.bin"
target_proc.DumpASToFile(output_file)

# 3. Or extract specific regions
user_space = target_proc.ExtractUserSpace()
kernel_space = target_proc.ExtractKernelSpace()
```

### Workflow 4: Nested VM Analysis

```python
# 1. Scan for hypervisors
copts.VersionsToEnable = PTType.VMCS
vtero = Scan.Scanit(copts)

# 2. Extract nested VMs
for vm in vtero.VMCSDetected:
    print(f"VMCS at: {vm.PhysicalAddress:016X}")
    print(f"EPTP: {vm.EPTP:016X}")
    print(f"Guest CR3: {vm.GuestCR3:016X}")
    
    # 3. Extract guest memory
    guest_mem = vm.ExtractGuestMemory()
    
    # 4. Analyze guest memory
    # (recursive analysis possible)
```

### Workflow 5: Malware Hunt with YARA

```python
import clr
clr.AddReferenceToFileAndPath("libyaraNET.dll")
from libyaraNET import *

# 1. Compile YARA rules
rules = YaraCompiler.CompileRulesFile("malware_rules.yar")

# 2. Scan each process
for proc in vtero.Processes:
    matches = rules.ScanMemory(proc.MemAccess)
    
    if matches:
        print(f"Process CR3={proc.CR3Value:X} matched: {matches}")
```

## Output Interpretation

### Performance Metrics

```
PART RUNTIME: 00:00:08.5211677 (seconds)
INPUT DUMP SIZE: 4,303,692,448 bytes
SPEED: 466,980 KB/second
```

- **Runtime**: Time for complete analysis
- **Speed**: Processing throughput (higher is better)
- Typical speeds: 200MB/s - 1GB/s depending on hardware

### Process Correlation

```
Group Correlation [100.000%] = Perfect match (same VM)
Group Correlation [90.909%]  = Shared kernel, likely same VM
Group Correlation [< 50%]    = Different VM or corrupted data
```

### EPTP Index

```
In the above example, VMWARE's EPTP is at index 14 in its VMCS.
```

- EPTP location varies by hypervisor/version
- Once identified, can be reused for same hypervisor version
- Index 14 is common for VMware

### Process Types

- **Windows**: Detected Windows process (self-pointer found)
- **Linux**: Linux process (kernel direct map)
- **FreeBSD**: BSD process (recursive PD)
- **VMCS**: Hypervisor instance
- **GENERIC**: Unknown OS type

## Best Practices

### Before Analysis

1. **Verify dump integrity**:
   ```bash
   md5sum memory.dump
   # Compare with known hash if available
   ```

2. **Check dump size**:
   - Should match source system's RAM size
   - Smaller = incomplete or compressed dump

3. **Ensure sufficient disk space**:
   - Analysis cache: ~10% of dump size
   - Symbol cache: ~1-5 GB
   - Extracted memory: up to dump size

### During Analysis

1. **Start with conservative settings**:
   ```python
   Vtero.VerboseOutput = False  # Reduce noise
   Vtero.DisableProgressBar = False  # Monitor progress
   ```

2. **Save state for large dumps**:
   ```python
   copts.IgnoreSaveData = False  # Enable caching
   vtero.CheckpointSaveState()  # Save intermediate results
   ```

3. **Monitor resource usage**:
   - RAM: Should not exceed physical RAM + dump size
   - CPU: All cores should be utilized
   - Disk I/O: High during initial scan

### After Analysis

1. **Review detected processes**:
   - Verify process count matches expectations
   - Check for anomalous CR3 values

2. **Validate symbols**:
   - Ensure PDBs downloaded correctly
   - Check symbol cache directory

3. **Document findings**:
   - Save output to file
   - Record EPTP indices for reuse
   - Note any anomalies

### Performance Tips

1. **Use SSD** for dump storage
2. **Increase RAM** for large dumps (16GB+ recommended)
3. **Disable antivirus** scanning of dump directory
4. **Use local symbol cache** to reduce network overhead
5. **Batch process** multiple dumps with saved state

### Security Considerations

1. **Isolate analysis environment**:
   - Use VM or separate system
   - Disconnect from network if analyzing compromised system

2. **Handle dumps as sensitive data**:
   - May contain passwords, keys, private data
   - Use encryption for storage/transfer

3. **Verify dump source**:
   - Unknown dumps may contain malware
   - Sandbox analysis if suspicious

### Troubleshooting

**No processes detected**:
- Try different `PTType` settings
- Check if dump is corrupted
- Verify dump format

**Low correlation scores**:
- May indicate nested VMs
- Check for multiple OS instances
- Review memory run detection

**Symbol failures**:
- Check internet connection
- Verify `_NT_SYMBOL_PATH`
- Try alternative symbol server

**Out of memory**:
- Reduce concurrent processing
- Increase system RAM
- Use 64-bit version

## Example Session

Complete analysis session:

```cmd
C:\> cd inVtero\Scripts
C:\inVtero\Scripts> ipy

IronPython 2.7.7
>>> import Main
Current directory [C:\inVtero\Scripts]

>>> MemList = ["C:\\dumps\\win10.vmem"]
>>> test(MemList)
++++++ ANALYZING INPUT [C:\dumps\win10.vmem] ++++++
PART RUNTIME: 00:00:15.2341234
159 candidate process page tables
Hypervisor: VMCS detected
Hypervisor: Windows CR3 found [16A0000]
Group 1: Type [Windows] Correlation [100%] 
Process count: 47
++++++ DONE ++++++

>>> vtero = test(MemList)
>>> kernel = vtero.KernelProc
>>> kvs = kernel.ScanAndLoadModules()
Loading symbols for ntoskrnl.exe...
Found 234 modules

>>> # Now use vtero, kernel, kvs objects for analysis
>>> WalkProcListExample(vtero, kernel)
PID: 4 Name: System
PID: 88 Name: Registry
PID: 384 Name: smss.exe
...
```

## Additional Resources

- **Architecture**: See [ARCHITECTURE.md](ARCHITECTURE.md)
- **API Reference**: See [API_REFERENCE.md](API_REFERENCE.md)
- **Development**: See [DEVELOPMENT.md](DEVELOPMENT.md)
- **Example Scripts**: See [Scripts/](Scripts/) directory
- **GitHub Issues**: https://github.com/K2/inVtero.net/issues

## Getting Help

If you encounter issues:

1. Check [INSTALLATION.md](INSTALLATION.md) troubleshooting section
2. Enable verbose output to diagnose problems
3. Search existing GitHub issues
4. Create new issue with:
   - Dump format and size
   - Source OS details
   - Error messages
   - Steps to reproduce
