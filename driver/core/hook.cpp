#include "hook.h" //read_process_memory, write_process_memory
#include <process/funcs.h>
#include <system/funcs.h>
#include <intrin.h>

uintptr_t swap_process(uintptr_t new_process)
{
	auto usermodeThread = (uintptr_t)KeGetCurrentThread();
	if (!usermodeThread)
		return STATUS_UNSUCCESSFUL;

	auto apc_state = *(uintptr_t*)(usermodeThread + 0x98);
	auto old_process = *(uintptr_t*)(apc_state + 0x20);
	*(uintptr_t*)(apc_state + 0x20) = new_process;

	auto dir_table_base = *(uintptr_t*)(new_process + 0x28);
	__writecr3(dir_table_base);

	return old_process;
}


//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

ULONG_PTR savedptr;
ULONG savedptr2;

//check normal dirbase if 0 then get from UserDirectoryTableBas
UINT64 get_process_cr3(PEPROCESS pProcess)
{
	PRKAPC_STATE APC{};
	KeStackAttachProcess((PKPROCESS)pProcess, APC);
	savedptr = __readcr3();
	KeUnstackDetachProcess(APC);
	return savedptr;
}

UINT64 get_kernel_dirbase()
{
	PRKAPC_STATE APC{};
	KeStackAttachProcess((PKPROCESS)PsGetCurrentProcess(), APC);
	savedptr2 = __readcr3();
	KeUnstackDetachProcess(APC);
	return savedptr2;
}
uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);


NTSTATUS read_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(paddress, buffer, size, read);
}

NTSTATUS write_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress(paddress, buffer, size, written);
}

NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	if (BytesWritten) *BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

//
NTSTATUS ReadProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = get_process_cr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	*read = CurOffset;
	return NtRet;
}

NTSTATUS WriteProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = get_process_cr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	*written = CurOffset;
	return NtRet;
}



namespace memory
{

	NTSTATUS write_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_written)
	{
		NTSTATUS status = STATUS_SUCCESS;
		size_t btransfer;
		status = WriteProcessMemory(pid, addr, buffer, size, &btransfer);
		if (bytes_written)
			*bytes_written = btransfer;
		return status;
	}

	NTSTATUS read_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t* bytes_read)
	{
		NTSTATUS status = STATUS_SUCCESS;
		size_t btransfer;
		status = ReadProcessMemory(pid, addr, buffer, size, &btransfer);
		if (bytes_read)
			*bytes_read = btransfer;
		return status;
	}
}

NTSTATUS GetModuleBaseAddress(int processId, const char* moduleName, uint64_t* baseAddress)
{
	ANSI_STRING ansiString;
	UNICODE_STRING compareString;
	KAPC_STATE state;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = NULL;
	system::PPEB pPeb = NULL;

	RtlInitAnsiString(&ansiString, moduleName);
	RtlAnsiStringToUnicodeString(&compareString, &ansiString, TRUE);

	printf("Looking for module %d\n", processId);

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &process)))
		return STATUS_UNSUCCESSFUL;

	printf("Found process %d\n", processId);

	auto o_process = swap_process((uintptr_t)process);
	pPeb = process::PsGetProcessPeb(process);

	if (pPeb)
	{
		system::PPEB_LDR_DATA pLdr = (system::PPEB_LDR_DATA)pPeb->Ldr;

		if (pLdr)
		{
			for (PLIST_ENTRY listEntry = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
				listEntry != &pLdr->InLoadOrderModuleList;
				listEntry = (PLIST_ENTRY)listEntry->Flink) {

				system::PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(listEntry, system::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				printf("%wZ\n", pEntry->BaseDllName);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, &compareString, TRUE) == 0)
				{
					*baseAddress = (uint64_t)pEntry->DllBase;
					status = STATUS_SUCCESS;
					break;
				}
			}
		}
	}
	swap_process(o_process);
	RtlFreeUnicodeString(&compareString);
	return status;
}

__int64 __fastcall core_hook::hooked_fptr(void* a1)
{
	if (!a1 || ExGetPreviousMode() != UserMode)
	{
		printf("!a1 || ExGetPreviousMode() != UserMode fail. arguments: %16X\n", a1);
		return core_hook::o_function_qword_1(a1);
	}

	fptr_data::kernel_com *com = (fptr_data::kernel_com *)a1;
	com->error = fptr_data::kernel_err::no_error;
	
	switch (com->opr)
	{
		case fptr_data::kernel_opr::get_process_base:
		{
			NTSTATUS status = STATUS_SUCCESS;

			PEPROCESS proc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status))
			{
				com->error = fptr_data::kernel_err::invalid_process;
				com->success = false;

				printf("get_process_base failed: invalid process.\n");
				return 0;
			}

			com->buffer = (uintptr_t)process::PsGetProcessSectionBaseAddress(proc);
			ObDereferenceObject(proc);
			break;
		}
		case fptr_data::kernel_opr::get_process_module:
		{
			// Inputs
			if (!com->target_pid)
			{
				com->error = fptr_data::kernel_err::invalid_data;
				com->success = false;
				printf("get_process_module failed: no valid process id given.\n");
				break;
			}


			uintptr_t buffer = 0;
			com->buffer = 0;
			if ( NT_SUCCESS( GetModuleBaseAddress( com->target_pid, com->name, &buffer ) ) )
				com->buffer = buffer;
			break;
			
			break;
		}

		case fptr_data::kernel_opr::write:
		{
			if (!NT_SUCCESS(memory::write_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("write failed: invalid data.\n");
				return 0;
			}
			break;
		}
		case fptr_data::kernel_opr::read:
		{
			if (!NT_SUCCESS(memory::read_process_memory(com->target_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("read failed: invalid data.\n");
				return 0;
			}
			break;
		}

		default:
		{
			com->success = false;
			com->error = fptr_data::kernel_err::no_operation;
			printf("(%p) failed: unknown operation.\n", com->opr);
			return 0;
		}
	}

	com->success = true;
	printf("kernel operation completed successfully.\n");
	return 0;
}

