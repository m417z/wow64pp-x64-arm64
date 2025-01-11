#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#define CATCH_CONFIG_MAIN
#include "Catch/single_include/catch.hpp"
#include "../include/wow64pp.hpp"


TEST_CASE ("basic_test")
{
    auto            ntdll = wow64pp::module_handle ("ntdll.dll");
    std::error_code ec;
    auto            fn = wow64pp::import (ntdll, "NtReadVirtualMemory", ec);
    REQUIRE (!ec);
    auto h = wow64pp::detail::self_handle ();

    volatile std::int32_t i = 6;
    volatile std::int32_t b = 20;
    std::uint64_t         read;

    for (int idx = 0; idx < 20; ++idx) {
        read = 0;
        i    = rand ();
        b    = rand ();

        for (int j = 0; j < 200; ++j) {
            auto ret = wow64pp::call_function (fn,
                                               wow64pp::handle_to_uint64(h),
                                               wow64pp::ptr_to_uint64(&i),
                                               wow64pp::ptr_to_uint64(&b),
                                               4,
                                               wow64pp::ptr_to_uint64(&read));
            auto status = static_cast<NTSTATUS>(ret);
            CHECK (SUCCEEDED (status));
            CHECK (i == b);
            REQUIRE (read == 4);
        }
    }
}

namespace {
    void* FindNextFreeRegion(void* pAddress, void* pMaxAddr, DWORD dwAllocationGranularity, DWORD* dwSize) {
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
        void* dwFreeAddress = FindNextFreeRegion((void*)0x80000000, (void*)0xFFFFFFFF, 0x1000, &dwFreeSize);

        while (dwFreeAddress) {
            if (dwFreeSize >= size && VirtualAlloc((void*)dwFreeAddress, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) {
                return (void*)dwFreeAddress;
            }

            dwFreeAddress = FindNextFreeRegion(dwFreeAddress, (void*)0xFFFFFFFF, 0x1000, &dwFreeSize);
        }

        return nullptr;
    }
}

TEST_CASE ("large_address_aware_ptr_test")
{
    auto            ntdll = wow64pp::module_handle ("ntdll.dll");
    std::error_code ec;
    auto            fn = wow64pp::import (ntdll, "NtReadVirtualMemory", ec);
    REQUIRE (!ec);
    auto h = wow64pp::detail::self_handle ();

    void* large_address_aware_ptr = AllocateLargeAddressAwareBuffer (4);
    REQUIRE (reinterpret_cast<std::size_t>(large_address_aware_ptr) >
             static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()));

    volatile std::int32_t* pi = reinterpret_cast<std::int32_t*>(large_address_aware_ptr);
    *pi  = rand ();

    volatile std::int32_t  b = rand();
    std::uint64_t          read = 0;

    auto ret = wow64pp::call_function (fn,
                                       wow64pp::handle_to_uint64(h),
                                       wow64pp::ptr_to_uint64(pi),
                                       wow64pp::ptr_to_uint64(&b),
                                       4,
                                       wow64pp::ptr_to_uint64(&read));
    auto status = static_cast<NTSTATUS>(ret);
    CHECK (SUCCEEDED (status));
    CHECK (*pi == b);
    REQUIRE (read == 4);
}
