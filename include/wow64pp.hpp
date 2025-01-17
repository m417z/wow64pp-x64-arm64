/*
 * Copyright 2017 - 2018 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstring>  // memcpy
#include <expected>
#include <memory>
#include <string_view>
#include <system_error>

// The following macros are used to initialize static variables once in a
// thread-safe manner while avoiding TLS, which is what MSVC uses for static
// variables.
#ifdef WOW64PP_AVOID_TLS
//  Similar to:
//  static T var_name = initializer;
#define WOW64PP_STATIC_INIT_ONCE_TRIVIAL(T, var_name, initializer) \
    static T var_name;                                             \
    do {                                                           \
        static_assert(std::is_trivially_destructible_v<T>);        \
        static std::once_flag static_init_once_flag_;              \
        std::call_once(static_init_once_flag_,                     \
                       []() { var_name = initializer; });          \
    } while (0)
#else
#define WOW64PP_STATIC_INIT_ONCE_TRIVIAL(T, var_name, initializer) \
    static T var_name = initializer;
#endif

namespace wow64pp {

namespace defs {

using NtQueryInformationProcessT =
    long(__stdcall*)(void* ProcessHandle,
                     unsigned long ProcessInformationClass,
                     void* ProcessInformation,
                     unsigned long ProcessInformationLength,
                     unsigned long* ReturnLength);

using NtWow64ReadVirtualMemory64T =
    long(__stdcall*)(void* ProcessHandle,
                     unsigned __int64 BaseAddress,
                     void* Buffer,
                     unsigned __int64 Size,
                     unsigned __int64* NumberOfBytesRead);

struct LIST_ENTRY_64 {
    std::uint64_t Flink;
    std::uint64_t Blink;
};

struct UNICODE_STRING_64 {
    unsigned short Length;
    unsigned short MaximumLength;
    std::uint64_t Buffer;
};

struct PROCESS_BASIC_INFORMATION_64 {
    std::uint64_t _unused_1;
    std::uint64_t PebBaseAddress;
    std::uint64_t _unused_2[4];
};

struct PEB_64 {
    unsigned char _unused_1[4];
    std::uint64_t _unused_2[2];
    std::uint64_t Ldr;
};

struct PEB_LDR_DATA_64 {
    unsigned long Length;
    unsigned long Initialized;
    std::uint64_t SsHandle;
    LIST_ENTRY_64 InLoadOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY_64 {
    LIST_ENTRY_64 InLoadOrderLinks;
    LIST_ENTRY_64 InMemoryOrderLinks;
    LIST_ENTRY_64 InInitializationOrderLinks;
    std::uint64_t DllBase;
    std::uint64_t EntryPoint;
    union {
        unsigned long SizeOfImage;
        std::uint64_t _dummy;
    };
    UNICODE_STRING_64 FullDllName;
    UNICODE_STRING_64 BaseDllName;
};

}  // namespace defs

namespace detail {

constexpr static auto image_directory_entry_export = 0;
constexpr static auto ordinal_not_found = 0xC0000138;

inline std::error_code get_last_error() noexcept {
    return std::error_code(static_cast<int>(GetLastError()),
                           std::system_category());
}

inline void throw_last_error(const char* message) {
    throw std::system_error(get_last_error(), message);
}

inline void throw_if_failed(const char* message, int hr) {
    if (hr < 0)
        throw std::system_error(std::error_code(hr, std::system_category()),
                                message);
}

inline HANDLE self_handle() {
    HANDLE h;

    if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                        GetCurrentProcess(), &h, 0, 0,
                        0x00000002) == 0)  // DUPLICATE_SAME_ACCESS
        throw_last_error("failed to duplicate current process handle");

    return h;
}

inline HANDLE self_handle(std::error_code& ec) noexcept {
    HANDLE h;

    if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                        GetCurrentProcess(), &h, 0, 0,
                        0x00000002) == 0)  // DUPLICATE_SAME_ACCESS
        ec = get_last_error();
    else
        ec.clear();

    return h;
}

inline HMODULE native_module_handle(const char* name) {
    const auto addr = GetModuleHandleA(name);
    if (addr == nullptr)
        throw_last_error("GetModuleHandleA() failed");

    return addr;
}

inline HMODULE native_module_handle(const char* name,
                                    std::error_code& ec) noexcept {
    const auto addr = GetModuleHandleA(name);
    if (addr == nullptr)
        ec = get_last_error();
    else
        ec.clear();

    return addr;
}

template <typename F>
inline F native_ntdll_function(const char* name) {
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(HMODULE, ntdll_addr,
                                     native_module_handle("ntdll.dll"));
    auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

    if (f == nullptr)
        throw_last_error("failed to get address of ntdll function");

    return f;
}

template <typename F>
inline F native_ntdll_function(const char* name, std::error_code& ec) noexcept {
    using ntdll_result_t = std::expected<HMODULE, std::error_code>;
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        ntdll_result_t, ntdll_result, ([]() -> ntdll_result_t {
            std::error_code ec;
            const auto ntdll_addr = native_module_handle("ntdll.dll", ec);
            if (ec)
                return std::unexpected(ec);
            return ntdll_addr;
        }()));

    if (!ntdll_result.has_value()) {
        ec = ntdll_result.error();
        return nullptr;
    }

    const auto ntdll_addr = *ntdll_result;

    const auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

    if (f == nullptr)
        ec = detail::get_last_error();
    else
        ec.clear();

    return f;
}

inline std::uint64_t peb_address() {
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        defs::NtQueryInformationProcessT, NtWow64QueryInformationProcess64,
        native_ntdll_function<defs::NtQueryInformationProcessT>(
            "NtWow64QueryInformationProcess64"));

    defs::PROCESS_BASIC_INFORMATION_64 pbi;
    const auto hres =
        NtWow64QueryInformationProcess64(GetCurrentProcess(),
                                         0,  // ProcessBasicInformation
                                         &pbi, sizeof(pbi), nullptr);
    throw_if_failed("NtWow64QueryInformationProcess64() failed", hres);

    return pbi.PebBaseAddress;
}

inline std::uint64_t peb_address(std::error_code& ec) noexcept {
    using function_result_t =
        std::expected<defs::NtQueryInformationProcessT, std::error_code>;
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        function_result_t, function_result, ([]() -> function_result_t {
            std::error_code ec;
            const auto NtWow64QueryInformationProcess64 =
                native_ntdll_function<defs::NtQueryInformationProcessT>(
                    "NtWow64QueryInformationProcess64", ec);
            if (ec)
                return std::unexpected(ec);
            return NtWow64QueryInformationProcess64;
        }()));

    if (!function_result.has_value()) {
        ec = function_result.error();
        return 0;
    }

    const auto NtWow64QueryInformationProcess64 = *function_result;

    defs::PROCESS_BASIC_INFORMATION_64 pbi;
    const auto hres =
        NtWow64QueryInformationProcess64(GetCurrentProcess(),
                                         0,  // ProcessBasicInformation
                                         &pbi, sizeof(pbi), nullptr);
    if (hres < 0)
        ec = detail::get_last_error();
    else
        ec.clear();

    return pbi.PebBaseAddress;
}

template <typename P>
inline void read_memory(std::uint64_t address,
                        P* buffer,
                        std::size_t size = sizeof(P)) {
    if (address + size - 1 <= std::numeric_limits<std::uint32_t>::max()) {
        std::memcpy(
            buffer,
            reinterpret_cast<const void*>(static_cast<std::uint32_t>(address)),
            size);
        return;
    }

    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        defs::NtWow64ReadVirtualMemory64T, NtWow64ReadVirtualMemory64,
        native_ntdll_function<defs::NtWow64ReadVirtualMemory64T>(
            "NtWow64ReadVirtualMemory64"));

    HANDLE h_self = self_handle();
    auto hres =
        NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
    CloseHandle(h_self);
    throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
}

template <typename P>
inline void read_memory(std::uint64_t address,
                        P* buffer,
                        std::size_t size,
                        std::error_code& ec) noexcept {
    if (address + size - 1 <= std::numeric_limits<std::uint32_t>::max()) {
        std::memcpy(
            buffer,
            reinterpret_cast<const void*>(static_cast<std::uint32_t>(address)),
            size);
        return;
    }

    using function_result_t =
        std::expected<defs::NtWow64ReadVirtualMemory64T, std::error_code>;
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        function_result_t, function_result, ([]() -> function_result_t {
            std::error_code ec;
            const auto NtWow64ReadVirtualMemory64 =
                native_ntdll_function<defs::NtWow64ReadVirtualMemory64T>(
                    "NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return std::unexpected(ec);
            return NtWow64ReadVirtualMemory64;
        }()));

    if (!function_result.has_value()) {
        ec = function_result.error();
        return;
    }

    const auto NtWow64ReadVirtualMemory64 = *function_result;

    HANDLE h_self = self_handle(ec);
    if (ec)
        return;
    auto hres =
        NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
    CloseHandle(h_self);
    if (hres < 0)
        ec = get_last_error();
    else
        ec.clear();

    return;
}

template <typename T>
inline T read_memory(std::uint64_t address) {
    alignas(T) std::byte buffer[sizeof(T)];
    read_memory(address, &buffer, sizeof(T));
    return *static_cast<T*>(static_cast<void*>(&buffer));
}

template <typename T>
inline T read_memory(std::uint64_t address, std::error_code& ec) noexcept {
    alignas(T) std::byte buffer[sizeof(T)];
    read_memory(address, &buffer, sizeof(T), ec);
    return *static_cast<T*>(static_cast<void*>(&buffer));
}

}  // namespace detail

/** \brief An equivalent of winapi GetModuleHandle function.
 *   \param[in] module_name The name of the module to get the handle of.
 *   \return    The handle to the module as a 64 bit integer.
 *   \exception Throws std::system_error on failure.
 */
inline std::uint64_t module_handle(std::string_view module_name) {
    const auto ldr_base =
        detail::read_memory<defs::PEB_64>(detail::peb_address()).Ldr;

    const auto last_entry =
        ldr_base + offsetof(defs::PEB_LDR_DATA_64, InLoadOrderModuleList);

    defs::LDR_DATA_TABLE_ENTRY_64 head;
    head.InLoadOrderLinks.Flink =
        detail::read_memory<defs::PEB_LDR_DATA_64>(ldr_base)
            .InLoadOrderModuleList.Flink;

    do {
        try {
            detail::read_memory(head.InLoadOrderLinks.Flink, &head);
        } catch (std::system_error&) {
            continue;
        }

        const auto other_module_name_len =
            head.BaseDllName.Length / sizeof(wchar_t);
        if (other_module_name_len != module_name.length())
            continue;

        auto other_module_name =
            std::make_unique<wchar_t[]>(other_module_name_len);
        detail::read_memory(head.BaseDllName.Buffer, other_module_name.get(),
                            head.BaseDllName.Length);

        if (std::equal(begin(module_name), end(module_name),
                       other_module_name.get()))
            return head.DllBase;
    } while (head.InLoadOrderLinks.Flink != last_entry);

    throw std::system_error(
        std::error_code(detail::ordinal_not_found, std::system_category()),
        "Could not get x64 module handle");
}

/** \brief An equivalent of winapi GetModuleHandle function.
 *   \param[in] module_name The name of the module to get the handle of.
 *   \param[out] ec An error code that will be set in case of failure
 *   \return    The handle to the module as a 64 bit integer.
 *   \exception Does not throw.
 */
inline std::uint64_t module_handle(std::string_view module_name,
                                   std::error_code& ec) {
    const auto ldr_base =
        detail::read_memory<defs::PEB_64>(detail::peb_address(ec), ec).Ldr;
    if (ec)
        return 0;

    const auto last_entry =
        ldr_base + offsetof(defs::PEB_LDR_DATA_64, InLoadOrderModuleList);

    defs::LDR_DATA_TABLE_ENTRY_64 head;
    head.InLoadOrderLinks.Flink =
        detail::read_memory<defs::PEB_LDR_DATA_64>(ldr_base, ec)
            .InLoadOrderModuleList.Flink;
    if (ec)
        return 0;

    do {
        detail::read_memory(head.InLoadOrderLinks.Flink, &head, sizeof(head),
                            ec);
        if (ec)
            continue;

        const auto other_module_name_len =
            head.BaseDllName.Length / sizeof(wchar_t);
        if (other_module_name_len != module_name.length())
            continue;

        auto other_module_name =
            std::make_unique<wchar_t[]>(other_module_name_len);
        detail::read_memory(head.BaseDllName.Buffer, other_module_name.get(),
                            head.BaseDllName.Length, ec);
        if (ec)
            continue;

        if (std::equal(begin(module_name), end(module_name),
                       other_module_name.get()))
            return head.DllBase;

    } while (head.InLoadOrderLinks.Flink != last_entry);

    if (!ec)
        ec = std::error_code(detail::ordinal_not_found, std::system_category());

    return 0;
}

namespace detail {

inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base) {
    const auto e_lfanew = read_memory<IMAGE_DOS_HEADER>(ntdll_base).e_lfanew;

    const auto idd_virtual_addr =
        read_memory<IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew)
            .OptionalHeader.DataDirectory[image_directory_entry_export]
            .VirtualAddress;

    if (idd_virtual_addr == 0)
        throw std::runtime_error(
            "IMAGE_EXPORT_DIRECTORY::VirtualAddress was 0");

    return read_memory<IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr);
}

inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base,
                                               std::error_code& ec) noexcept {
    const auto e_lfanew =
        read_memory<IMAGE_DOS_HEADER>(ntdll_base, ec).e_lfanew;
    if (ec)
        return {};

    const auto idd_virtual_addr =
        read_memory<IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew, ec)
            .OptionalHeader.DataDirectory[image_directory_entry_export]
            .VirtualAddress;
    if (ec)
        return {};

    if (idd_virtual_addr == 0) {
        ec = std::error_code(ordinal_not_found, std::system_category());
        return {};
    }

    return read_memory<IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr,
                                               ec);
}

inline std::uint64_t ldr_procedure_address() {
    const auto ntdll_base = module_handle("ntdll.dll");

    const auto ied = image_export_dir(ntdll_base);

    auto rva_table = std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
    read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.get(),
                sizeof(unsigned long) * ied.NumberOfFunctions);

    auto ord_table = std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
    read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.get(),
                sizeof(unsigned short) * ied.NumberOfFunctions);

    auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
    read_memory(ntdll_base + ied.AddressOfNames, name_table.get(),
                sizeof(unsigned long) * ied.NumberOfNames);

    const char to_find[] = "LdrGetProcedureAddress";
    char buffer[std::size(to_find)] = "";

    const std::size_t n =
        (ied.NumberOfFunctions > ied.NumberOfNames ? ied.NumberOfNames
                                                   : ied.NumberOfFunctions);
    for (std::size_t i = 0; i < n; ++i) {
        read_memory(ntdll_base + name_table[i], &buffer);

        if (std::equal(std::begin(to_find), std::end(to_find), buffer))
            return ntdll_base + rva_table[ord_table[i]];
    }

    throw std::system_error(
        std::error_code(ordinal_not_found, std::system_category()),
        "could find x64 LdrGetProcedureAddress()");
}

inline std::uint64_t ldr_procedure_address(std::error_code& ec) {
    const auto ntdll_base = module_handle("ntdll.dll", ec);
    if (ec)
        return 0;

    const auto ied = image_export_dir(ntdll_base, ec);
    if (ec)
        return 0;

    auto rva_table = std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
    read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.get(),
                sizeof(unsigned long) * ied.NumberOfFunctions, ec);
    if (ec)
        return 0;

    auto ord_table = std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
    read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.get(),
                sizeof(unsigned short) * ied.NumberOfFunctions, ec);
    if (ec)
        return 0;

    auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
    read_memory(ntdll_base + ied.AddressOfNames, name_table.get(),
                sizeof(unsigned long) * ied.NumberOfNames, ec);
    if (ec)
        return 0;

    const char to_find[] = "LdrGetProcedureAddress";
    char buffer[std::size(to_find)] = "";

    const std::size_t n = ied.NumberOfFunctions > ied.NumberOfNames
                              ? ied.NumberOfNames
                              : ied.NumberOfFunctions;

    for (std::size_t i = 0; i < n; ++i) {
        read_memory(ntdll_base + name_table[i], &buffer, sizeof(buffer), ec);
        if (ec)
            continue;

        if (std::equal(std::begin(to_find), std::end(to_find), buffer))
            return ntdll_base + rva_table[ord_table[i]];
    }

    ec = std::error_code(ordinal_not_found, std::system_category());
    return 0;
}

}  // namespace detail

/** \brief Calls a 64 bit function from 32 bit process
 *   \param[in] func The address of 64 bit function to be called.
 *   \param[in] args... The arguments for the function to be called.
 *   \return    The return value of the called function.
 *   \exception Does not throw.
 */
template <class... Args>
inline std::uint64_t call_function(std::uint64_t func, Args... args) {
    std::uint64_t arr_args[sizeof...(args) > 4 ? sizeof...(args) : 4] = {
        (std::uint64_t)(args)...};

    // clang-format off
    #pragma code_seg(push, stack1, ".text")
    __declspec(allocate(".text"), align(16))
    const static std::uint8_t shellcode[] = {
        0x55,             // push ebp
        0x89, 0xE5,       // mov ebp, esp

        0x83, 0xE4, 0xF0, // and esp, 0xFFFFFFF0

        // enter 64 bit mode
        0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,

        0x67, 0x48, 0x8B, 0x4D, 16, // mov rcx, [ebp + 16]
        0x67, 0x48, 0x8B, 0x55, 24, // mov rdx, [ebp + 24]
        0x67, 0x4C, 0x8B, 0x45, 32, // mov r8,  [ebp + 32]
        0x67, 0x4C, 0x8B, 0x4D, 40, // mov r9,  [ebp + 40]

        0x67, 0x48, 0x8B, 0x45, 48, // mov rax, [ebp + 48] args count

        0xA8, 0x01,             // test al, 1
        0x75, 0x04,             // jne _no_adjust
        0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
    // _no adjust:
            0x57,                                     // push rdi
            0x67, 0x48, 0x8B, 0x7D, 0x38,             // mov rdi, [ebp + 56]
            0x48, 0x85, 0xC0,                         // je _ls_e
            0x74, 0x16, 0x48, 0x8D, 0x7C, 0xC7, 0xF8, // lea rdi, [rdi+rax*8-8]
    // _ls:
            0x48, 0x85, 0xC0,       // test rax, rax
            0x74, 0x0C,             // je _ls_e
            0xFF, 0x37,             // push [rdi]
            0x48, 0x83, 0xEF, 0x08, // sub rdi, 8
            0x48, 0x83, 0xE8, 0x01, // sub rax, 1
            0xEB, 0xEF,             // jmp _ls
    // _ls_e:
        0x67, 0x8B, 0x7D, 0x40,       // mov edi, [ebp + 64]
        0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
        0x67, 0xFF, 0x55, 0x08,       // call [ebp + 0x8]
        0x67, 0x48, 0x89, 0x07,       // mov [edi], rax
        0x67, 0x48, 0x8B, 0x4D, 0x30, // mov rcx, [ebp+48]
        0x48, 0x8D, 0x64, 0xCC, 0x20, // lea rsp, [rsp+rcx*8+0x20]
        0x5F,                         // pop rdi

     // exit 64 bit mode
        0xE8, 0, 0, 0, 0, 0xC7, 0x44, 0x24, 4, 0x23, 0, 0, 0, 0x83, 4, 0x24, 0xD, 0xCB,

        0x66, 0x8C, 0xD8, // mov ax, ds
        0x8E, 0xD0,       // mov ss, eax

        0x89, 0xEC, // mov esp, ebp
        0x5D,       // pop ebp
        0xC3        // ret
    };
    #pragma code_seg(pop, stack1)
    // clang-format on

    using my_fn_sig = void(__cdecl*)(
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
        std::uint64_t, std::uint64_t, std::uint64_t, std::uint32_t);

    std::uint64_t ret;
    reinterpret_cast<my_fn_sig>(&shellcode)(
        func, arr_args[0], arr_args[1], arr_args[2], arr_args[3],
        sizeof...(Args) > 4 ? (sizeof...(Args) - 4) : 0,
        reinterpret_cast<std::uint64_t>(arr_args + 4),
        reinterpret_cast<std::uint32_t>(&ret));

    return ret;
}

/** \brief An equivalent of winapi GetProcAddress function.
 *   \param[in] hmodule The handle to the module in which to search for the
                procedure.
 *   \param[in] procedure_name The name of the procedure to be searched for.
 *   \return    The address of the exported function or variable.
 *   \exception Throws std::system_error on failure.
 */
inline std::uint64_t import(std::uint64_t hmodule,
                            std::string_view procedure_name) {
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(std::uint64_t, ldr_procedure_address_base,
                                     detail::ldr_procedure_address());

    defs::UNICODE_STRING_64 unicode_fun_name = {0};
    unicode_fun_name.Length =
        static_cast<unsigned short>(procedure_name.size());
    unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;
    const auto data = procedure_name.data();
    std::memcpy(&unicode_fun_name.Buffer, &data, 4);

    std::uint64_t ret;
    auto fn_ret = call_function(
        ldr_procedure_address_base, hmodule,
        reinterpret_cast<std::uint64_t>(&unicode_fun_name),
        static_cast<std::uint64_t>(0), reinterpret_cast<std::uint64_t>(&ret));
    if (fn_ret)
        throw std::system_error(
            std::error_code(static_cast<int>(fn_ret), std::system_category()),
            "call_function(ldr_procedure_address_base...) failed");

    return ret;
}

/** \brief An equivalent of winapi GetProcAddress function.
 *   \param[in]  hmodule The handle to the module in which to search for the
                 procedure.
 *   \param[in]  procedure_name The name of the procedure to be searched for.
 *   \param[out] ec An error code that will be set in case of failure
 *   \return     The address of the exported function or variable.
 *   \exception  Does not throw.
 */
inline std::uint64_t import(std::uint64_t hmodule,
                            std::string_view procedure_name,
                            std::error_code& ec) {
    using ldr_result_t = std::expected<std::uint64_t, std::error_code>;
    WOW64PP_STATIC_INIT_ONCE_TRIVIAL(
        ldr_result_t, ldr_result, ([]() -> ldr_result_t {
            std::error_code ec;
            const auto ldr_result = detail::ldr_procedure_address(ec);
            if (ec)
                return std::unexpected(ec);
            return ldr_result;
        }()));

    if (!ldr_result.has_value()) {
        ec = ldr_result.error();
        return 0;
    }

    const auto ldr_procedure_address_base = *ldr_result;

    defs::UNICODE_STRING_64 unicode_fun_name = {0};
    unicode_fun_name.Length =
        static_cast<unsigned short>(procedure_name.size());
    unicode_fun_name.MaximumLength = unicode_fun_name.Length;
    const auto data = procedure_name.data();
    std::memcpy(&unicode_fun_name.Buffer, &data, 4);

    std::uint64_t ret;
    auto fn_ret = call_function(ldr_procedure_address_base, hmodule,
                                &unicode_fun_name, 0, &ret);

    return ret;
}

/** \brief Use to pass pointers as arguments to call_function.
 *   \param[in] ptr The pointer.
 *   \return    The 64 bit integer argument.
 *   \exception Does not throw.
 */
template <typename T>
inline std::uint64_t ptr_to_uint64(T* ptr) {
    static_assert(sizeof(ptr) == sizeof(std::uint32_t),
                  "expecting 32-bit pointers");

    // Without the double casting, the pointer is sign extended, not zero
    // extended, which leads to invalid addresses with /LARGEADDRESSAWARE.
    return static_cast<std::uint64_t>(reinterpret_cast<std::uint32_t>(ptr));
}

/** \brief Use to pass handles as arguments to call_function.
 *   \param[in] ptr The handle.
 *   \return    The 64 bit integer argument.
 *   \exception Does not throw.
 */
inline std::uint64_t handle_to_uint64(HANDLE handle) {
    static_assert(sizeof(handle) == sizeof(std::int32_t),
                  "expecting 32-bit handles");

    // Sign-extension is required for pseudo handles such as the handle returned
    // from GetCurrentProcess().
    // "64-bit versions of Windows use 32-bit handles for interoperability [...]
    // it is safe to [...] sign-extend the handle (when passing it from 32-bit
    // to 64-bit)."
    // https://docs.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
    return static_cast<std::uint64_t>(reinterpret_cast<std::int32_t>(handle));
}

}  // namespace wow64pp

#endif  // WOW64PP_HPP
