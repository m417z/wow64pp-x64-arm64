#define WOW64PP_AVOID_TLS
#include "../include/wow64pp.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#define CATCH_CONFIG_MAIN
#include "Catch/single_include/catch2/catch.hpp"

TEST_CASE("basic") {
    std::error_code ec;
    auto ntdll = wow64pp::module_handle("ntdll.dll", ec);
    REQUIRE(!ec);
    auto fn = wow64pp::import(ntdll, "NtGetTickCount", ec);
    REQUIRE(!ec);
    wow64pp::call_function(fn);
}

TEST_CASE("basic_exceptions") {
    auto ntdll = wow64pp::module_handle("ntdll.dll");
    auto fn = wow64pp::import(ntdll, "NtGetTickCount");
    wow64pp::call_function(fn);
}

TEST_CASE("read_virtual_memory_rand") {
    auto ntdll = wow64pp::module_handle("ntdll.dll");
    std::error_code ec;
    auto fn = wow64pp::import(ntdll, "NtReadVirtualMemory", ec);
    REQUIRE(!ec);
    auto h = wow64pp::detail::self_handle();

    volatile std::int32_t i = 6;
    volatile std::int32_t b = 20;
    std::uint64_t read;

    for (int idx = 0; idx < 20; ++idx) {
        read = 0;
        i = rand();
        b = rand();

        for (int j = 0; j < 200; ++j) {
            auto ret = wow64pp::call_function(
                fn, wow64pp::handle_to_uint64(h), wow64pp::ptr_to_uint64(&i),
                wow64pp::ptr_to_uint64(&b), 4, wow64pp::ptr_to_uint64(&read));
            auto status = static_cast<NTSTATUS>(ret);
            CHECK(SUCCEEDED(status));
            CHECK(i == b);
            REQUIRE(read == 4);
        }
    }
}

TEST_CASE("return_value_64bit") {
    auto ntdll = wow64pp::module_handle("ntdll.dll");
    std::error_code ec;
    auto encode_fn = wow64pp::import(ntdll, "RtlEncodePointer", ec);
    REQUIRE(!ec);
    auto decode_fn = wow64pp::import(ntdll, "RtlDecodePointer", ec);
    REQUIRE(!ec);

    std::uint64_t ptr = 0x1234567812345678;

    auto encoded = wow64pp::call_function(encode_fn, ptr);
    auto decoded = wow64pp::call_function(decode_fn, encoded);
    REQUIRE(decoded == ptr);
}

namespace {

// Based on:
// http://securityxploded.com/ntcreatethreadex.php
// Another reference:
// https://github.com/winsiderss/systeminformer/blob/25846070780183848dc8d8f335a54fa6e636e281/phlib/basesup.c#L217
HANDLE MyCreateRemoteThread(HANDLE hProcess,
                            LPTHREAD_START_ROUTINE lpStartAddress,
                            LPVOID lpParameter,
                            ULONG createFlags) {
    using NtCreateThreadEx_t = NTSTATUS(WINAPI*)(
        _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ LPVOID ObjectAttributes,  // POBJECT_ATTRIBUTES
        _In_ HANDLE ProcessHandle,
        _In_ PVOID StartRoutine,  // PUSER_THREAD_START_ROUTINE
        _In_opt_ PVOID Argument,
        _In_ ULONG CreateFlags,  // THREAD_CREATE_FLAGS_*
        _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize,
        _In_ SIZE_T MaximumStackSize,
        _In_opt_ LPVOID AttributeList  // PPS_ATTRIBUTE_LIST
    );

    static auto pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(
        GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
    if (!pNtCreateThreadEx) {
        return nullptr;
    }

    HANDLE hThread;
    NTSTATUS result = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr,
                                        hProcess, lpStartAddress, lpParameter,
                                        createFlags, 0, 0, 0, nullptr);
    if (result < 0) {
        return nullptr;
    }

    return hThread;
}

void* FindNextFreeRegion(void* pAddress,
                         void* pMaxAddr,
                         DWORD dwAllocationGranularity,
                         DWORD* dwSize) {
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((void*)tryAddr, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        if (mbi.State == MEM_FREE) {
            *dwSize = mbi.RegionSize;
            return (void*)tryAddr;
        }

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }

    return nullptr;
}

void* AllocateLargeAddressAwareBuffer(std::size_t size) {
    DWORD dwFreeSize;
    void* dwFreeAddress = FindNextFreeRegion(
        (void*)0x80000000, (void*)0xFFFFFFFF, 0x1000, &dwFreeSize);

    while (dwFreeAddress) {
        if (dwFreeSize >= size &&
            VirtualAlloc((void*)dwFreeAddress, size, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE)) {
            return (void*)dwFreeAddress;
        }

        dwFreeAddress = FindNextFreeRegion(dwFreeAddress, (void*)0xFFFFFFFF,
                                           0x1000, &dwFreeSize);
    }

    return nullptr;
}

}  // namespace

TEST_CASE("thread_without_tls") {
    constexpr ULONG MY_REMOTE_THREAD_THREAD_ATTACH_EXEMPT = 0x02;

    DWORD createThreadFlags =
#ifdef WOW64PP_AVOID_TLS
        MY_REMOTE_THREAD_THREAD_ATTACH_EXEMPT
#else
        0
#endif
        ;

    HANDLE thread = MyCreateRemoteThread(
        GetCurrentProcess(),
        [](LPVOID pThis) -> DWORD {
            auto ntdll = wow64pp::module_handle("ntdll.dll");
            std::error_code ec;
            auto fn = wow64pp::import(ntdll, "NtGetTickCount", ec);
            REQUIRE(!ec);
            wow64pp::call_function(fn);
            return 0;
        },
        0, createThreadFlags);
    REQUIRE(thread);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

TEST_CASE("large_address_aware_ptr") {
    auto ntdll = wow64pp::module_handle("ntdll.dll");
    std::error_code ec;
    auto fn = wow64pp::import(ntdll, "NtReadVirtualMemory", ec);
    REQUIRE(!ec);
    auto h = wow64pp::detail::self_handle();

    void* large_address_aware_ptr = AllocateLargeAddressAwareBuffer(4);
    REQUIRE(reinterpret_cast<std::size_t>(large_address_aware_ptr) >
            static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()));

    volatile std::int32_t* pi =
        reinterpret_cast<std::int32_t*>(large_address_aware_ptr);
    *pi = rand();

    volatile std::int32_t b = rand();
    std::uint64_t read = 0;

    auto ret = wow64pp::call_function(
        fn, wow64pp::handle_to_uint64(h), wow64pp::ptr_to_uint64(pi),
        wow64pp::ptr_to_uint64(&b), 4, wow64pp::ptr_to_uint64(&read));
    auto status = static_cast<NTSTATUS>(ret);
    CHECK(SUCCEEDED(status));
    CHECK(*pi == b);
    REQUIRE(read == 4);
}
