# API Reference

## Table of Contents
- [Core Classes](#core-classes)
- [Configuration](#configuration)
- [Memory Access](#memory-access)
- [Process Detection](#process-detection)
- [Symbol Resolution](#symbol-resolution)
- [Hashing and Integrity](#hashing-and-integrity)
- [Python API](#python-api)
- [PowerShell Cmdlets](#powershell-cmdlets)

## Core Classes

### Vtero Class

Main orchestration class for memory analysis.

**Namespace**: `inVtero.net`

**Key Properties**:
```csharp
public class Vtero
{
    // Configuration
    public static bool VerboseOutput { get; set; }
    public static bool DiagOutput { get; set; }
    public static int VerboseLevel { get; set; }
    public static bool DisableProgressBar { get; set; }
    
    // Analysis results
    public List<DetectedProc> Processes { get; }
    public DetectedProc KernelProc { get; set; }
    public MemAccess MemAccess { get; }
    public KVS KVS { get; set; }  // Kernel Virtual Symbols
    
    // State management
    public void CheckpointSaveState();
    public static Vtero LoadStateFile(string fileName);
}
```

**Example**:
```csharp
var vtero = new Vtero("memory.dmp");
vtero.VerboseOutput = true;
var processes = vtero.Processes;
```

### ConfigOptions Class

Configuration for memory analysis.

**Namespace**: `inVtero.net`

```csharp
public class ConfigOptions
{
    // Input file
    public string FileName { get; set; }
    
    // Process type detection
    public PTType VersionsToEnable { get; set; }
    
    // State management
    public bool IgnoreSaveData { get; set; }
    
    // Memory handling
    public bool ForceSingleFlatMemRun { get; set; }
    
    // Output control
    public int VerboseLevel { get; set; }
}
```

**PTType Enum**:
```csharp
[Flags]
public enum PTType
{
    NONE = 0,
    Windows = 1,
    LinuxS = 2,
    FreeBSD = 4,
    OpenBSD = 8,
    NetBSD = 16,
    VMCS = 32,
    HyperV = 64,
    GENERIC = 0x7FFFFFFF
}
```

**Example**:
```csharp
var opts = new ConfigOptions
{
    FileName = "dump.dmp",
    VersionsToEnable = PTType.Windows | PTType.VMCS,
    IgnoreSaveData = false,
    VerboseLevel = 1
};
```

### Scan Class

Static utility class for initiating memory scans.

**Namespace**: `inVtero.net`

```csharp
public static class Scan
{
    public static Vtero Scanit(ConfigOptions opts);
}
```

**Example**:
```csharp
var opts = new ConfigOptions { FileName = "memory.dmp" };
var vtero = Scan.Scanit(opts);
```

### DetectedProc Class

Represents a detected process with its address space.

**Namespace**: `inVtero.net`

```csharp
public class DetectedProc : IComparable, IDisposable
{
    // Process identification
    public long CR3Value { get; set; }
    public long FileOffset { get; set; }
    public PTType PageTableType { get; }
    
    // Page table
    public PageTable PT { get; set; }
    
    // Memory access
    public Mem MemAccess { get; set; }
    
    // Symbols and modules
    public List<CODEVIEW_HEADER> Modules { get; }
    
    // Methods
    public KVS ScanAndLoadModules();
    public void DumpASToFile(string outputFile);
    public byte[] ExtractUserSpace();
    public byte[] ExtractKernelSpace();
    public dynamic GetStructure(long address, TypeInfo type);
}
```

**Example**:
```csharp
foreach (var proc in vtero.Processes)
{
    Console.WriteLine($"CR3: {proc.CR3Value:X16}");
    Console.WriteLine($"Type: {proc.PageTableType}");
    
    // Load symbols
    var kvs = proc.ScanAndLoadModules();
    
    // Dump memory
    proc.DumpASToFile($"proc_{proc.CR3Value:X}.bin");
}
```

### PageTable Class

Represents parsed page table structures.

**Namespace**: `inVtero.net`

```csharp
public class PageTable : IDisposable
{
    // Page table entries
    public List<HARDWARE_ADDRESS_ENTRY> Failed { get; }
    public List<HARDWARE_ADDRESS_ENTRY> PresentInvalid { get; }
    public HARDWARE_ADDRESS_ENTRY HighestFound { get; }
    
    // Metadata
    public PTType RootTableType { get; set; }
    public long CR3Value { get; set; }
    
    // Address translation
    public long VirtualToPhysical(long virtualAddress);
    public bool IsValidAddress(long virtualAddress);
}
```

**HARDWARE_ADDRESS_ENTRY Structure**:
```csharp
[StructLayout(LayoutKind.Explicit)]
public struct HARDWARE_ADDRESS_ENTRY
{
    [FieldOffset(0)]
    public ulong Address;
    
    [FieldOffset(0)]
    public PTE PTE;  // Page Table Entry bits
    
    public bool Valid { get; }
    public long PFN { get; }  // Page Frame Number
}
```

## Memory Access

### Mem Class

Physical memory access and abstraction.

**Namespace**: `inVtero.net`

```csharp
public class Mem : IDisposable
{
    // File access
    public string FileName { get; }
    public long Length { get; }
    
    // Memory runs
    public List<MemoryRun> Runs { get; }
    
    // Reading methods
    public byte[] ReadPhysicalMemory(long physicalAddress, int length);
    public byte[] ReadVirtualMemory(long virtualAddress, int length);
    
    public ulong ReadUInt64(long address);
    public uint ReadUInt32(long address);
    public ushort ReadUInt16(long address);
    public byte ReadByte(long address);
    
    public string ReadString(long address, int maxLength);
    public string ReadUnicodeString(long address, int maxLength);
    
    // Scanning
    public IEnumerable<long> ScanFor(byte[] pattern);
}
```

**MemoryRun Structure**:
```csharp
public struct MemoryRun
{
    public long BasePage { get; set; }
    public long PageCount { get; set; }
    public long StartAddress { get; }
    public long EndAddress { get; }
}
```

**Example**:
```csharp
var mem = new Mem("memory.dmp");

// Read physical memory
byte[] data = mem.ReadPhysicalMemory(0x1000, 4096);

// Read values
ulong value = mem.ReadUInt64(0x12345000);

// Scan for pattern
byte[] pattern = new byte[] { 0x4D, 0x5A }; // MZ header
foreach (long addr in mem.ScanFor(pattern))
{
    Console.WriteLine($"Found at: {addr:X16}");
}
```

### PhysicalMemoryStream Class

Stream-based access to physical memory.

**Namespace**: `inVtero.net`

```csharp
public class PhysicalMemoryStream : Stream
{
    public override bool CanRead { get; }
    public override bool CanSeek { get; }
    public override long Length { get; }
    public override long Position { get; set; }
    
    public override int Read(byte[] buffer, int offset, int count);
    public override long Seek(long offset, SeekOrigin origin);
}
```

**Example**:
```csharp
using (var stream = new PhysicalMemoryStream(mem))
{
    stream.Seek(0x1000, SeekOrigin.Begin);
    byte[] buffer = new byte[4096];
    stream.Read(buffer, 0, buffer.Length);
}
```

## Symbol Resolution

### KVS Class (Kernel Virtual Symbols)

Symbol resolution and type information.

**Namespace**: `inVtero.net`

```csharp
public class KVS
{
    // Kernel symbols
    public long KernelBase { get; }
    public long PsActiveProcessHead { get; }
    public long PsLoadedModuleList { get; }
    
    // Modules
    public List<ModuleInfo> Modules { get; }
    
    // Type resolution
    public TypeInfo GetTypeInfo(string typeName);
    public long GetSymbolAddress(string symbolName);
    
    // Structure helpers
    public T GetStructure<T>(long address) where T : struct;
}
```

**ModuleInfo Class**:
```csharp
public class ModuleInfo
{
    public string Name { get; }
    public long BaseAddress { get; }
    public long Size { get; }
    public string PDBPath { get; }
    public Guid PDBGuid { get; }
    
    public bool VerifyHash();
}
```

**TypeInfo Class**:
```csharp
public class TypeInfo
{
    public string Name { get; }
    public int Size { get; }
    public List<FieldInfo> Fields { get; }
    
    public FieldInfo GetField(string fieldName);
    public int GetFieldOffset(string fieldName);
}
```

**Example**:
```csharp
var kvs = proc.ScanAndLoadModules();

// Get type information
var eprocessType = kvs.GetTypeInfo("_EPROCESS");
Console.WriteLine($"EPROCESS size: {eprocessType.Size}");

// Get symbol address
long psHead = kvs.GetSymbolAddress("PsActiveProcessHead");

// Get structure
var listEntry = kvs.GetStructure<LIST_ENTRY>(psHead);
```

## Hashing and Integrity

### HashDB Class

Hash database for integrity verification.

**Namespace**: `inVtero.net.Hashing`

```csharp
public class HashDB
{
    // Load hash database
    public static HashDB Load(string databasePath);
    
    // Query hashes
    public HashRecord Lookup(byte[] hash);
    public bool Contains(byte[] hash);
    
    // Add hashes
    public void Add(byte[] hash, string fileName, long offset);
}
```

**HashRecord Class**:
```csharp
public class HashRecord
{
    public byte[] Hash { get; }
    public string FileName { get; }
    public long FileOffset { get; }
    public bool IsKnownGood { get; }
}
```

**Example**:
```csharp
var hashDb = HashDB.Load("hashes.db");

// Verify page
byte[] pageData = mem.ReadPhysicalMemory(0x1000, 4096);
byte[] pageHash = SHA256.HashData(pageData);

var record = hashDb.Lookup(pageHash);
if (record != null && record.IsKnownGood)
{
    Console.WriteLine("Page verified: " + record.FileName);
}
```

### DeLocate Integration

**Namespace**: `Reloc`

```csharp
public class DeLocate
{
    // Normalize relocations for hash comparison
    public static byte[] NormalizeRelocations(byte[] data, long baseAddress);
    
    // Compare with hash database
    public static bool VerifyWithReloc(byte[] data, HashDB db);
}
```

## Python API

### Importing inVtero.net

```python
import clr
import System

clr.AddReferenceToFileAndPath("inVtero.net.dll")
from inVtero.net import *
from inVtero.net.Hashing import *
from System.IO import *
from System import Environment
```

### Basic Analysis

```python
# Configure
copts = ConfigOptions()
copts.FileName = "memory.dmp"
copts.VersionsToEnable = PTType.GENERIC

# Scan
vtero = Scan.Scanit(copts)

# Access processes
for proc in vtero.Processes:
    print("CR3: %016X" % proc.CR3Value)
```

### Reading Memory

```python
# Get memory access object
mem = proc.MemAccess

# Read values
value64 = mem.ReadUInt64(0x12345000)
value32 = mem.ReadUInt32(0x12345000)

# Read bytes
data = mem.ReadPhysicalMemory(0x1000, 4096)

# Read string
text = mem.ReadString(0x12345000, 256)
unicode_text = mem.ReadUnicodeString(0x12345000, 256)
```

### Dynamic Type Access

```python
# Load symbols
kvs = proc.ScanAndLoadModules()

# Get type
eproc_type = kvs.GetTypeInfo("_EPROCESS")

# Read structure
eproc = proc.GetStructure(address, eproc_type)

# Access fields dynamically
pid = eproc.UniqueProcessId
image_name = eproc.ImageFileName
```

### Walking Linked Lists

```python
def walk_list(head_addr, list_offset, type_info):
    """Walk a Windows doubly-linked list"""
    current = head_addr
    
    while True:
        # Read list entry
        flink = mem.ReadUInt64(current)
        
        # Calculate structure address
        struct_addr = current - list_offset
        
        # Read structure
        obj = proc.GetStructure(struct_addr, type_info)
        
        yield obj
        
        # Next entry
        current = flink
        if current == head_addr:
            break
```

### Scanning Memory

```python
# Scan for pattern
pattern = System.Array[System.Byte]([0x4D, 0x5A, 0x90, 0x00])
matches = mem.ScanFor(pattern)

for addr in matches:
    print("Found at: %016X" % addr)
```

## PowerShell Cmdlets

### Get-InVteroProcesses

Get detected processes from memory dump.

```powershell
Get-InVteroProcesses -Path "C:\dumps\memory.dmp"
```

**Parameters**:
- `-Path`: Memory dump file path
- `-Type`: Filter by process type (Windows, Linux, etc.)
- `-Save`: Save analysis state

**Output**:
```
CR3          Type      FileOffset
---          ----      ----------
001AB000     Windows   293A12000
016A0000     Windows   2635D0000
```

### Read-InVteroMemory

Read memory from detected process.

```powershell
$proc = Get-InVteroProcesses -Path "dump.dmp" | Select -First 1
Read-InVteroMemory -Process $proc -Address 0x12345000 -Length 4096
```

### Get-InVteroSymbols

Load and query symbols.

```powershell
$kvs = Get-InVteroSymbols -Process $proc
$kvs.Modules | Format-Table Name, BaseAddress, Size
```

### Export-InVteroMemory

Export process memory to file.

```powershell
Export-InVteroMemory -Process $proc -OutputPath "process_dump.bin"
```

## Data Structures

### CODEVIEW_HEADER

Debug information header.

```csharp
[StructLayout(LayoutKind.Sequential)]
public struct CODEVIEW_HEADER
{
    public uint Signature;       // 'RSDS'
    public Guid Guid;           // PDB GUID
    public uint Age;            // PDB Age
    public string PDBPath;      // Path to PDB file
}
```

### PTE (Page Table Entry)

```csharp
[StructLayout(LayoutKind.Explicit)]
public struct PTE
{
    [FieldOffset(0)]
    public ulong Value;
    
    public bool Valid { get; }
    public bool Writable { get; }
    public bool User { get; }
    public bool NoExecute { get; }
    public ulong PFN { get; }
}
```

### VMCS_ENTRY

Virtual Machine Control Structure entry.

```csharp
public class VMCS_ENTRY
{
    public long PhysicalAddress { get; }
    public uint RevisionID { get; }
    public long EPTP { get; }
    public long GuestCR3 { get; }
}
```

## Error Handling

### Exceptions

```csharp
try
{
    var vtero = Scan.Scanit(opts);
}
catch (FileNotFoundException ex)
{
    // Dump file not found
}
catch (InvalidDataException ex)
{
    // Corrupted or invalid dump format
}
catch (OutOfMemoryException ex)
{
    // Insufficient memory for analysis
}
```

### Validation

```csharp
// Check if process is valid
if (proc.PT != null && proc.PT.RootTableType != PTType.NONE)
{
    // Process has valid page table
}

// Check if address is valid
if (proc.PT.IsValidAddress(virtualAddress))
{
    var data = proc.MemAccess.ReadVirtualMemory(virtualAddress, length);
}
```

## Advanced Usage

### Custom Memory Run Detector

```csharp
public class MyRunDetector : AMemoryRunDetector
{
    public override bool IsSupportedFormat(Mem mem)
    {
        // Check if this detector supports the format
        return CheckSignature(mem);
    }
    
    public override MemoryDescriptor ExtractMemory(Mem mem)
    {
        // Extract memory run information
        var runs = new List<MemoryRun>();
        // ... parse format ...
        return new MemoryDescriptor { Runs = runs };
    }
}
```

### Custom Scanner

```csharp
public class CustomScanner : VirtualScanner
{
    public override List<long> Scan(Mem mem, PTType types)
{
        var candidates = new List<long>();
        
        // Scan for custom patterns
        foreach (var addr in mem.ScanFor(pattern))
        {
            if (ValidateCandidate(addr))
            {
                candidates.Add(addr);
            }
        }
        
        return candidates;
    }
}
```

## Performance Tips

### Parallel Processing

```csharp
// Enable parallel page table walking
ParallelOptions opts = new ParallelOptions
{
    MaxDegreeOfParallelism = Environment.ProcessorCount
};

Parallel.ForEach(processes, opts, proc =>
{
    proc.LoadSymbols();
});
```

### Caching

```csharp
// Enable state caching
copts.IgnoreSaveData = false;

// Save state for reuse
vtero.CheckpointSaveState();

// Load saved state
var vtero = Vtero.LoadStateFile("memory.dmp.inVtero");
```

### Memory-Mapped Files

```csharp
// Use memory mapping for large dumps
using (var mmf = MemoryMappedFile.CreateFromFile("dump.dmp"))
{
    // Access mapped memory
}
```

## Additional Resources

- **User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Examples**: See `Scripts/` directory
- **Source Code**: Inline documentation in `.cs` files

## Support

For API questions and issues:
- GitHub Issues: https://github.com/K2/inVtero.net/issues
- Documentation: http://ShaneK2.github.io/inVtero.net
