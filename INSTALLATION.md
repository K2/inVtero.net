# Installation Guide

## Table of Contents
- [Prerequisites](#prerequisites)
- [Windows Installation](#windows-installation)
- [Linux Installation](#linux-installation)
- [macOS/BSD Installation](#macosbsd-installation)
- [Building from Source](#building-from-source)
- [Symbol Server Configuration](#symbol-server-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Common Requirements
- **Git**: For cloning the repository
- **Memory dump file**: To analyze (supported formats: .vmem, .vmsn, .dmp, .raw, .dd, .xendump)

### Windows-Specific Requirements
- **Windows 7 or later** (64-bit recommended)
- **.NET Framework 4.6.1 or later**
- **Visual Studio 2017 or later** (for building from source)
- **msdia140.dll** (included with Visual Studio)

### Linux/macOS/BSD Requirements
- **.NET Core 2.0 or later** / **.NET 6.0+ recommended**
- **Mono** (optional, for some features)

## Windows Installation

### Option 1: Binary Package (Quickest)

1. **Download the binary package**:
   ```
   https://github.com/K2/inVtero.net/blob/master/quickdumps/publish.zip
   ```

2. **Extract the archive**:
   ```cmd
   mkdir C:\inVtero
   cd C:\inVtero
   unzip publish.zip
   ```

3. **Register msdia140.dll** (IMPORTANT):
   ```cmd
   # Run as Administrator
   cd C:\inVtero
   regsvr32 msdia140.dll
   ```
   
   Or if msdia140.dll is in System32:
   ```cmd
   regsvr32 C:\Windows\System32\msdia140.dll
   ```

4. **Verify installation**:
   ```cmd
   quickdumps.exe --help
   ```

### Option 2: Build from Source

See [Building from Source](#building-from-source) section below.

### Setting up Symbol Path (Windows)

Configure symbol server for automatic symbol resolution:

```cmd
# Set environment variable (run as Administrator for system-wide)
setx _NT_SYMBOL_PATH "SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols"

# Or for current session only
set _NT_SYMBOL_PATH=SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols
```

Alternative symbol paths:
```
# Local cache + Microsoft symbol server
SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols

# Multiple symbol servers
SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols;SRV*http://chromium-browser-symsrv.commondatastorage.googleapis.com

# Local symbols directory
C:\Symbols
```

## Linux Installation

### Ubuntu/Debian

1. **Install .NET Core/SDK**:
   ```bash
   wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
   sudo dpkg -i packages-microsoft-prod.deb
   rm packages-microsoft-prod.deb
   
   sudo apt-get update
   sudo apt-get install -y dotnet-sdk-8.0
   ```

2. **Clone the repository**:
   ```bash
   git clone --recursive https://github.com/K2/inVtero.net.git
   cd inVtero.net
   ```

3. **Build inVteroCore**:
   ```bash
   cd inVtero.core
   dotnet restore
   dotnet build inVtero.core.sln -c Release
   ```

4. **Set up symbol path** (uses symbol servers automatically on Linux):
   ```bash
   export _NT_SYMBOL_PATH="SRV*$HOME/.symbols*http://msdl.microsoft.com/download/symbols"
   
   # Add to ~/.bashrc for persistence
   echo 'export _NT_SYMBOL_PATH="SRV*$HOME/.symbols*http://msdl.microsoft.com/download/symbols"' >> ~/.bashrc
   ```

### Fedora/RHEL/CentOS

1. **Install .NET Core**:
   ```bash
   sudo dnf install dotnet-sdk-8.0
   ```

2. **Follow Ubuntu steps 2-4** above.

### Arch Linux

1. **Install .NET Core**:
   ```bash
   sudo pacman -S dotnet-sdk
   ```

2. **Follow Ubuntu steps 2-4** above.

## macOS/BSD Installation

### macOS

1. **Install .NET Core**:
   ```bash
   brew install --cask dotnet-sdk
   ```

2. **Clone and build**:
   ```bash
   git clone --recursive https://github.com/K2/inVtero.net.git
   cd inVtero.net/inVtero.core
   dotnet restore
   dotnet build inVtero.core.sln -c Release
   ```

### FreeBSD

1. **Install .NET Core** (if available):
   ```bash
   pkg install dotnet
   ```

2. **Clone and build**:
   ```bash
   git clone --recursive https://github.com/K2/inVtero.net.git
   cd inVtero.net/inVtero.core
   dotnet restore
   dotnet build inVtero.core.sln -c Release
   ```

## Building from Source

### Windows

1. **Clone the repository**:
   ```cmd
   git clone --recursive https://github.com/K2/inVtero.net.git
   cd inVtero.net
   ```

2. **Open in Visual Studio**:
   ```
   Open inVtero.net.sln in Visual Studio 2017 or later
   ```

3. **Restore NuGet packages**:
   - Right-click solution → "Restore NuGet Packages"
   - Or: Tools → NuGet Package Manager → Package Manager Console
   ```
   Update-Package -reinstall
   ```

4. **Build the solution**:
   - Build → Build Solution (Ctrl+Shift+B)
   - Or select Release configuration and build

5. **Output location**:
   ```
   inVtero.net/bin/Release/
   quickdumps/bin/Release/
   ```

### Command Line Build (Windows)

```cmd
# Using MSBuild
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" inVtero.net.sln /p:Configuration=Release

# Or using dotnet (if .NET Core SDK installed)
dotnet build inVtero.net.sln -c Release
```

### Linux/macOS

```bash
git clone --recursive https://github.com/K2/inVtero.net.git
cd inVtero.net

# Build .NET Core version
cd inVtero.core
dotnet restore
dotnet build inVtero.core.sln -c Release

# Build quickcore utility
cd quickcore
dotnet build -c Release

# Run quickcore
dotnet run -- --help
```

## Symbol Server Configuration

### Automatic Configuration (Recommended)

inVtero.net will automatically use the Microsoft symbol server if `_NT_SYMBOL_PATH` is not set.

### Manual Configuration

**Windows**:
```cmd
# Persistent (all users)
setx _NT_SYMBOL_PATH "SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols" /M

# Persistent (current user)
setx _NT_SYMBOL_PATH "SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols"

# Current session only
set _NT_SYMBOL_PATH=SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols
```

**Linux/macOS**:
```bash
# Add to ~/.bashrc or ~/.zshrc
export _NT_SYMBOL_PATH="SRV*$HOME/.symbols*http://msdl.microsoft.com/download/symbols"

# Apply immediately
source ~/.bashrc
```

### Verifying Symbol Configuration

```bash
# Windows (cmd)
echo %_NT_SYMBOL_PATH%

# Windows (PowerShell)
$env:_NT_SYMBOL_PATH

# Linux/macOS
echo $_NT_SYMBOL_PATH
```

### Using Local Symbols

If you have PDB files locally:

```cmd
# Windows
set _NT_SYMBOL_PATH=C:\MySymbols;C:\Windows\Symbols;SRV*C:\Symbols*http://msdl.microsoft.com/download/symbols

# Linux/macOS
export _NT_SYMBOL_PATH="/path/to/symbols:SRV*$HOME/.symbols*http://msdl.microsoft.com/download/symbols"
```

## Dependencies

### Runtime Dependencies

**Windows (.NET Framework)**:
- msdia140.dll (Microsoft Debug Interface Access)
- dbghelp.dll (included in package)
- symsrv.dll (included in package)

**All Platforms**:
- Optional: Capstone engine (for disassembly)
- Optional: Keystone engine (for assembly)
- Optional: IronPython (for scripting)

### Installing Optional Dependencies

**Capstone** (disassembly):
```bash
# Ubuntu/Debian
sudo apt-get install libcapstone-dev

# macOS
brew install capstone

# Windows
# Download from: https://www.capstone-engine.org/
```

**Keystone** (assembly):
```bash
# Ubuntu/Debian
sudo apt-get install cmake
git clone https://github.com/keystone-engine/keystone.git
cd keystone && mkdir build && cd build
cmake .. && make && sudo make install

# macOS
brew install keystone

# Windows
# Download from: https://www.keystone-engine.org/
```

## Verification

### Test Basic Functionality

**Windows**:
```cmd
# Using quickdumps
cd quickdumps\bin\Release
quickdumps.exe --help

# Should display help information
```

**Linux/macOS**:
```bash
cd inVtero.core/quickcore/bin/Release/net6.0
dotnet quickcore.dll --help
```

### Test with Sample Memory Dump

```cmd
# Windows
quickdumps.exe -f "C:\dumps\memory.dmp"

# Linux/macOS
dotnet quickcore.dll -f "/path/to/memory.dmp"
```

Expected output:
- Detection of memory format
- Scanning progress
- List of detected processes
- Process CR3 values
- Hypervisor information (if applicable)

## Troubleshooting

### Common Issues

#### "msdia140.dll not registered" (Windows)

**Solution**:
```cmd
# Run as Administrator
regsvr32 C:\path\to\msdia140.dll

# Or from Visual Studio directory
regsvr32 "C:\Program Files\Microsoft Visual Studio\2022\Community\DIA SDK\bin\amd64\msdia140.dll"
```

#### "Unable to load DLL 'msdia140.dll'" (Windows)

**Solution**:
1. Ensure msdia140.dll is in the same directory as the executable
2. Register the DLL (see above)
3. Install Visual Studio C++ redistributables:
   ```
   https://aka.ms/vs/17/release/vc_redist.x64.exe
   ```

#### "Failed to download symbols"

**Solution**:
1. Check internet connection
2. Verify symbol path configuration
3. Try alternative symbol server
4. Check firewall/proxy settings:
   ```cmd
   # Windows - bypass proxy for symbol server
   set HTTP_PROXY=
   set HTTPS_PROXY=
   ```

#### Build errors on Linux

**Solution**:
1. Ensure all git submodules are initialized:
   ```bash
   git submodule update --init --recursive
   ```

2. Install missing dependencies:
   ```bash
   sudo apt-get install build-essential
   ```

3. Use correct .NET Core version:
   ```bash
   dotnet --version  # Should be 6.0 or higher
   ```

#### "Assembly not found" errors

**Solution**:
```bash
# Restore NuGet packages
dotnet restore

# Clean and rebuild
dotnet clean
dotnet build
```

#### Memory dump not detected

**Solution**:
1. Verify dump file format is supported
2. Check if file is corrupted:
   ```bash
   file memory.dump  # Linux/macOS
   ```
3. Try different run detection mode
4. Convert dump to RAW format using volatility/rekall

#### Performance issues

**Solution**:
1. Use SSD for memory dumps
2. Increase available RAM
3. Enable page caching
4. Use appropriate verbosity level
5. Disable progress bar for batch processing

### Getting Help

- **GitHub Issues**: https://github.com/K2/inVtero.net/issues
- **Documentation**: http://ShaneK2.github.io/inVtero.net
- **Security Issues**: See SECURITY.md

### Debug Mode

Enable verbose output for troubleshooting:

**Python Scripts**:
```python
Vtero.VerboseOutput = True
Vtero.DiagOutput = True
Vtero.VerboseLevel = 2
```

**Command Line**:
```bash
# Add verbose flags (implementation specific)
quickdumps.exe -f dump.dmp --verbose
```

## Next Steps

After installation:
1. Read [USER_GUIDE.md](USER_GUIDE.md) for usage instructions
2. Review [ARCHITECTURE.md](ARCHITECTURE.md) to understand the design
3. Check [Scripts/](Scripts/) directory for example Python scripts
4. See [API_REFERENCE.md](API_REFERENCE.md) for programming interface

## Post-Installation Configuration

### Performance Tuning

1. **Disable Windows Defender scanning** for dump directories (performance)
2. **Use local cache** for symbols:
   ```cmd
   mkdir C:\Symbols
   set _NT_SYMBOL_PATH=C:\Symbols*http://msdl.microsoft.com/download/symbols
   ```
3. **Allocate more memory** for large dumps (16GB+ recommended)

### Security Considerations

1. **Analyze dumps in isolated environment**
2. **Use read-only mounts** for dump files
3. **Restrict network access** if analyzing potentially compromised systems
4. **Verify dump integrity** before analysis

## Updating

### Git Repository

```bash
cd inVtero.net
git pull origin master
git submodule update --init --recursive

# Rebuild
dotnet build -c Release
```

### Binary Package

Download latest publish.zip and extract over existing installation.

## Uninstallation

### Windows
1. Delete installation directory
2. Unregister msdia140.dll (optional):
   ```cmd
   regsvr32 /u msdia140.dll
   ```
3. Remove environment variables

### Linux/macOS
```bash
rm -rf inVtero.net
# Remove from ~/.bashrc if added
```
