# Development Guide

## Table of Contents
- [Getting Started](#getting-started)
- [Development Environment Setup](#development-environment-setup)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
- [Testing](#testing)
- [Coding Standards](#coding-standards)
- [Contributing](#contributing)
- [Debugging](#debugging)
- [Adding Features](#adding-features)

## Getting Started

### Prerequisites for Development

**Windows**:
- Visual Studio 2017 or later (2022 recommended)
- .NET Framework 4.6.1 SDK or later
- .NET Core SDK 6.0 or later
- Git with submodules support

**Linux/macOS**:
- .NET Core SDK 6.0 or later
- Visual Studio Code (recommended)
- Git
- Build essentials (`build-essential` on Ubuntu)

### Fork and Clone

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone --recursive https://github.com/YOUR_USERNAME/inVtero.net.git
   cd inVtero.net
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/K2/inVtero.net.git
   ```

4. **Verify submodules**:
   ```bash
   git submodule update --init --recursive
   ```

## Development Environment Setup

### Visual Studio (Windows)

1. **Install Visual Studio 2022** with workloads:
   - .NET desktop development
   - .NET Core cross-platform development
   
2. **Install extensions** (optional but recommended):
   - ReSharper or CodeMaid
   - GitHub Extension for Visual Studio
   - IronPython Tools

3. **Open solution**:
   ```
   File → Open → Project/Solution → inVtero.net.sln
   ```

4. **Restore NuGet packages**:
   - Right-click solution → Restore NuGet Packages
   - Or: Tools → NuGet Package Manager → Restore

### Visual Studio Code (Cross-platform)

1. **Install VS Code extensions**:
   - C# (Microsoft)
   - .NET Core Tools
   - NuGet Package Manager

2. **Open workspace**:
   ```bash
   code inVtero.net
   ```

3. **Configure tasks** (.vscode/tasks.json):
   ```json
   {
     "version": "2.0.0",
     "tasks": [
       {
         "label": "build",
         "command": "dotnet",
         "type": "process",
         "args": [
           "build",
           "${workspaceFolder}/inVtero.core/inVtero.core.sln",
           "/property:GenerateFullPaths=true",
           "/consoleloggerparameters:NoSummary"
         ],
         "problemMatcher": "$msCompile"
       }
     ]
   }
   ```

### Command Line Setup

**Windows**:
```cmd
# Set up Visual Studio build tools in PATH
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
```

**Linux/macOS**:
```bash
# Verify .NET installation
dotnet --version
# Should be 6.0 or higher
```

## Project Structure

### Repository Layout

```
inVtero.net/
├── inVtero.net/              # Main library (.NET Framework)
│   ├── Mem.cs                # Physical memory access
│   ├── PageTable.cs          # Page table parsing
│   ├── DetectedProc.cs       # Process representation
│   ├── Scanner.cs            # Memory scanning
│   ├── Specialties/          # Format-specific handlers
│   ├── Support/              # Utility classes
│   ├── Hashing/              # Integrity verification
│   └── PS/                   # PowerShell support
├── inVtero.core/             # .NET Core version
│   ├── inVteroCore/          # Core library
│   ├── quickcore/            # Core quickdumps tool
│   └── Dia2Sharp/            # Symbol resolution
├── quickdumps/               # Example tool (.NET Framework)
├── Scripts/                  # Python analysis scripts
├── ConsoleUtils/             # Console helpers
├── Dia2Sharp/                # DIA COM interop
├── inVteroUI/                # GUI application
├── inVteroPS/                # PowerShell module
└── Reloc.net/                # Relocation utilities
```

### Key Directories

- **inVtero.net/**: Core library with full features (Windows-focused)
- **inVtero.core/**: Cross-platform version with core features
- **Specialties/**: Memory dump format handlers (VMware, Xen, CrashDump)
- **Support/**: Shared utilities (Capstone, Keystone, etc.)
- **Scripts/**: IronPython analysis examples

## Building the Project

### Full Build (Windows)

**Visual Studio**:
1. Select "Release" or "Debug" configuration
2. Build → Build Solution (Ctrl+Shift+B)
3. Output: `inVtero.net/bin/{Configuration}/`

**Command Line**:
```cmd
# Using MSBuild
msbuild inVtero.net.sln /p:Configuration=Release /m

# Using dotnet
dotnet build inVtero.net.sln -c Release
```

### Core Build (Cross-platform)

```bash
cd inVtero.core
dotnet restore
dotnet build inVtero.core.sln -c Release

# Build specific project
dotnet build inVteroCore/inVteroCore.csproj -c Release
```

### Build Output

**inVtero.net** (Framework):
```
inVtero.net/bin/Release/
├── inVtero.net.dll
├── inVtero.net.pdb
└── dependencies...

quickdumps/bin/Release/
├── quickdumps.exe
├── inVtero.net.dll
└── dependencies...
```

**inVteroCore**:
```
inVtero.core/inVteroCore/bin/Release/netstandard2.0/
├── inVteroCore.dll
├── inVteroCore.pdb
└── dependencies...
```

### Clean Build

```bash
# Visual Studio
Build → Clean Solution

# Command line
dotnet clean
# or
msbuild /t:Clean
```

## Testing

### Unit Tests

Currently, the project uses manual testing with sample dumps. To add unit tests:

1. **Create test project**:
   ```bash
   dotnet new xunit -n inVtero.Tests
   dotnet add inVtero.Tests reference inVtero.net/inVtero.net.csproj
   ```

2. **Write tests**:
   ```csharp
   public class MemTests
   {
       [Fact]
       public void TestMemoryRunDetection()
       {
           var mem = new Mem("test.dmp");
           Assert.NotEmpty(mem.Runs);
       }
   }
   ```

3. **Run tests**:
   ```bash
   dotnet test
   ```

### Integration Testing

Use sample memory dumps for integration testing:

```bash
# Windows
quickdumps.exe -f test_dumps\windows10.dmp

# Linux/macOS
dotnet run --project inVtero.core/quickcore -f test_dumps/linux.raw
```

### Test Data

Place test dumps in a separate directory (not committed):
```
test_dumps/
├── windows10_x64.dmp
├── linux_ubuntu.raw
├── vmware_nested.vmem
└── xen_dump.xendump
```

## Coding Standards

### C# Style Guidelines

Follow Microsoft C# coding conventions:

**Naming**:
```csharp
// PascalCase for public members
public class PageTable { }
public void ScanMemory() { }
public int ProcessCount { get; set; }

// camelCase for private fields
private int processCount;
private List<DetectedProc> detectedProcesses;

// _camelCase for private fields (alternative)
private int _processCount;

// UPPER_CASE for constants
public const int MAX_PROCESSES = 1000;
```

**Formatting**:
```csharp
// Braces on new line
if (condition)
{
    DoSomething();
}

// Spacing
public void Method(int param1, int param2)
{
    var result = param1 + param2;
}

// Using statements at top
using System;
using System.Collections.Generic;
using inVtero.net.Support;
```

### Documentation

**XML Documentation Comments**:
```csharp
/// <summary>
/// Scans physical memory for page table structures.
/// </summary>
/// <param name="memoryDump">The memory dump to scan</param>
/// <param name="options">Scan configuration options</param>
/// <returns>List of detected processes</returns>
/// <exception cref="ArgumentNullException">
/// Thrown when memoryDump is null
/// </exception>
public List<DetectedProc> ScanForProcesses(
    Mem memoryDump, 
    ConfigOptions options)
{
    // Implementation
}
```

**Code Comments**:
```csharp
// Good: Explain WHY, not WHAT
// Use self-pointer detection to avoid OS dependencies
var selfPointer = FindSelfPointerEntry(pml4);

// Bad: Obvious comments
// Increment i
i++;
```

### Error Handling

```csharp
// Validate inputs
public void ProcessMemory(Mem memory)
{
    if (memory == null)
        throw new ArgumentNullException(nameof(memory));
    
    if (memory.Length == 0)
        throw new ArgumentException(
            "Memory dump is empty", nameof(memory));
}

// Use specific exceptions
if (!File.Exists(fileName))
    throw new FileNotFoundException(
        "Dump file not found", fileName);

// Clean up resources
public void Dispose()
{
    memoryStream?.Dispose();
    fileHandle?.Close();
}
```

## Contributing

### Workflow

1. **Create feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make changes**:
   - Write code
   - Add tests
   - Update documentation

3. **Commit changes**:
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

4. **Push to fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

5. **Create pull request** on GitHub

### Commit Messages

Follow conventional commits format:

```
type(scope): subject

body

footer
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Examples**:
```
feat(scanner): Add ARM64 page table support

Implement 4-level page table walking for ARM64 architecture.
Includes detection of ARMv8 page table format.

Closes #123

fix(mem): Handle sparse memory runs correctly

Previously, memory gaps caused incorrect address calculations.
Now properly tracks memory run boundaries.

docs(api): Add examples to API reference

Add code examples for common use cases in API_REFERENCE.md
```

### Pull Request Guidelines

**Before submitting**:
- [ ] Code builds without warnings
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] Commit messages are clear

**PR Description should include**:
- What changes were made
- Why the changes were needed
- How to test the changes
- Any breaking changes
- Related issues

## Debugging

### Visual Studio Debugging

1. **Set breakpoints** in code
2. **Configure startup project**:
   - Right-click `quickdumps` → Set as StartUp Project
3. **Set command line arguments**:
   - Right-click `quickdumps` → Properties → Debug
   - Command line arguments: `-f C:\dumps\test.dmp`
4. **Start debugging** (F5)

### Debugging Tips

**Enable verbose output**:
```csharp
Vtero.VerboseOutput = true;
Vtero.DiagOutput = true;
Vtero.VerboseLevel = 2;
```

**Attach to running process**:
```
Debug → Attach to Process → Select quickdumps.exe
```

**Conditional breakpoints**:
```csharp
// Right-click breakpoint → Conditions
// Example: proc.CR3Value == 0x1AB000
```

### Common Issues

**Symbols not loading**:
- Check `_NT_SYMBOL_PATH` environment variable
- Verify msdia140.dll is registered
- Clear symbol cache

**Memory access violations**:
- Validate addresses before reading
- Check memory run boundaries
- Verify page table entries

**Performance problems**:
- Profile with Visual Studio Profiler
- Check for inefficient loops
- Optimize memory allocations

## Adding Features

### Adding a New Memory Format

1. **Create format detector**:
   ```csharp
   public class MyFormatDetector : AMemoryRunDetector
   {
       public override bool IsSupportedFormat(Mem mem)
       {
           // Check format signature
           return CheckSignature(mem);
       }
       
       public override MemoryDescriptor ExtractMemory(Mem mem)
       {
           // Parse format and extract runs
           return ParseFormat(mem);
       }
   }
   ```

2. **Register detector**:
   ```csharp
   // In Mem.cs constructor
   detectors.Add(new MyFormatDetector());
   ```

3. **Test with sample dump**

### Adding OS Support

1. **Define OS signature**:
   ```csharp
   // In Scanner.cs
   private bool IsMyOS(HARDWARE_ADDRESS_ENTRY[] pageTable)
   {
       // Check for OS-specific patterns
       return CheckOSPattern(pageTable);
   }
   ```

2. **Add to PTType enum**:
   ```csharp
   public enum PTType
   {
       // Existing types...
       MyOS = 128,
   }
   ```

3. **Implement detection logic**

4. **Add page table walker** if needed

### Adding Analysis Features

1. **Create analysis class**:
   ```csharp
   public class NetworkAnalyzer
   {
       public List<Connection> FindConnections(DetectedProc proc)
       {
           // Scan for network structures
       }
   }
   ```

2. **Add to Python API**:
   ```python
   # In Scripts/
   from inVtero.net.Analysis import NetworkAnalyzer
   
   analyzer = NetworkAnalyzer()
   connections = analyzer.FindConnections(proc)
   ```

3. **Document in API reference**

### Adding Python Scripts

1. **Create script in Scripts/**:
   ```python
   # MyAnalysis.py
   import clr
   clr.AddReferenceToFileAndPath("inVtero.net.dll")
   from inVtero.net import *
   
   def analyze(vtero, proc):
       # Your analysis code
       pass
   ```

2. **Import in Main.py**:
   ```python
   import MyAnalysis
   from MyAnalysis import *
   ```

3. **Add documentation**

## Release Process

### Version Numbering

Follow Semantic Versioning (SemVer):
- MAJOR.MINOR.PATCH
- Example: 2.1.3

### Creating a Release

1. **Update version**:
   - `AssemblyInfo.cs` files
   - NuGet package versions

2. **Update changelog**:
   - Add release notes to `Changelog.txt`

3. **Build release**:
   ```bash
   dotnet build -c Release
   ```

4. **Create tag**:
   ```bash
   git tag -a v2.1.3 -m "Release 2.1.3"
   git push origin v2.1.3
   ```

5. **Create GitHub release** with binaries

## Additional Resources

- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **API Reference**: [API_REFERENCE.md](API_REFERENCE.md)
- **User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
- **Code of Conduct**: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)

## Getting Help

- **GitHub Discussions**: Ask questions and share ideas
- **GitHub Issues**: Report bugs and request features
- **Pull Requests**: Contribute code improvements

## License

This project is licensed under the GNU Affero General Public License v3.0.
See [LICENSE](LICENSE) for details.
