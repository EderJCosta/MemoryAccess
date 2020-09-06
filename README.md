# MemoryAccess
It is a Memory Access API written in C# using pinvoke.

### How to use
Import this project as a local NuGet.

In your Code Import the MemoryAccess and use the functions.
```C#
//Import
using MemoryAccess;

// Functions
//Open Process
MemoryAccessAPI.OpenProcess(MemoryAccessAPI.ProcessAccessFlags.All, false, theProcess.Id);
// Scan AOB
MemoryAccessAPI.ScanArrayOfBytes(theProcess, "48 8B 05 ?? ?? ?? ?? 48 39 48 68 0F 94 C0 C3");
// Get address from a pointer
MemoryAccessAPI.GetMemoryAddress(procHeader, baseAddr, attributeOffsets);
// get an integer value from a Address 
MemoryAccessAPI.GetAddressIntegerValue(procHeader, entityAddress, 4);
// Write Value into an Address
MemoryAccessAPI.WriteProcessMemory(procHeader, entityAddress, 150, 4, out _);
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details