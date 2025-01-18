# wow64pp-x64-arm64

An easy to use header-only Heaven's Gate implementation which allows calling
native x64 and ARM64 functions from a 32-bit x86 process.

## Quick reference

wow64pp exposes 3 main functions which have exception-based and
`error_code`-based counterparts.

```cpp
#include "wow64pp.hpp"
// ...

// Equivalent of GetModuleHandle.
auto x64_ntdll_handle = wow64pp::module_handle("ntdll.dll");
// or wow64pp::module_handle("ntdll.dll", error_code);

// Equivalent of GetProcAddress.
auto x64_NtQueryVirtualMemory = wow64pp::import(x64_ntdll_handle, "NtQueryVirtualMemory");
// or wow64pp::import(x64_ntdll_handle, "NtQueryVirtualMemory", error_code);

// After getting the function address you can call it using
// wow64pp::call_function by passing its address as the first argument, with the
// function arguments following. Use wow64pp::handle_to_uint64 and
// wow64pp::ptr_to_uint64 to convert handles and pointers to 64-bit integers
// correctly.
std::uint64_t address = /* ... */;
MEMORY_BASIC_INFORMATION64 memory_info;
std::uint64_t result_len;
auto status = wow64pp::call_function(x64_NtQueryVirtualMemory,
                                     wow64pp::handle_to_uint64(process_handle),
                                     address,
                                     MemoryBasicInformation,
                                     wow64pp::ptr_to_uint64(&memory_info),
                                     sizeof(memory_info),
                                     wow64pp::ptr_to_uint64(&result_len));
```

## References

### Code

* [wow64pp](https://github.com/JustasMasiulis/wow64pp) - The original wow64pp
  project. This version started as its fork.
* [wow64ext](https://github.com/sonyps5201314/wow64ext) - An implementation
  which tries to be compatible with all architectures. Was used as a reference
  for ARM64 support.
* [rewolf-wow64ext](https://github.com/rwfpl/rewolf-wow64ext) - Probably the
  most popular Heaven's Gate implementation.

### Blog posts

* [WoW64
  internals](https://wbenny.github.io/2018/11/04/wow64-internals.html#wow64wow64systemserviceex)
  by Petr Beneš.
* [WOW64!Hooks: WOW64 Subsystem Internals and Hooking
  Techniques](https://cloud.google.com/blog/topics/threat-intelligence/wow64-subsystem-internals-and-hooking-techniques/)
  by Stephen Eckels.
