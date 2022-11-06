

PVOID GetSystemModuleBase(const char* ModuleName)
{
	ULONG Bytes = 0;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, Bytes, &Bytes);
	if (!Bytes)
		return NULL;
	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x4e554c4c);
	Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Bytes, &Bytes);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Modules, 0x4e554c4c);
		return NULL;
	}
	PRTL_PROCESS_MODULE_INFORMATION moduleinformation = Modules->Modules;
	PVOID imagebase = 0;
	for (int j = 0; j < Modules->NumberOfModules; j++)
	{
		if (!strcmp((const char*)moduleinformation[j].FullPathName, ModuleName))
		{
			imagebase = moduleinformation[j].ImageBase;
			break;
		}
	}
	ExFreePoolWithTag(Modules, 0x4e554c4c);
	if (!imagebase)
		return NULL;
	return imagebase;
}

PVOID GetExportedRoutine(const char* ModuleName, const char* RoutineName)
{
	PVOID imagebase = GetSystemModuleBase(ModuleName);
	if (!imagebase)
		return NULL;
	return RtlFindExportedRoutineByName(imagebase, RoutineName);
}

BOOLEAN WriteMemory(void* src, void* buffer, size_t size)
{
	if (!RtlCopyMemory(src, buffer, size)) return FALSE;
	return TRUE;
}

BOOLEAN WriteReadOnlyMemory(void* src, void* buffer, size_t size)
{
	PMDL pMdl = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
	if (!pMdl)
		return NULL;
	MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	PVOID mapping = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE);

	if (!WriteMemory(mapping, buffer, size)) return FALSE;
	MmUnmapLockedPages(mapping, pMdl);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

BOOLEAN Hook(void* CustomFunction)
{
	if (!CustomFunction)
		return FALSE;
	PVOID* function = reinterpret_cast<PVOID*>(GetExportedRoutine("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtOpenCompositionSurfaceSwapChainHandleInfo"));
	if (!function)
		return FALSE;
	BYTE orig[] = { 0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x56 };
    // mov    QWORD PTR[rsp + 0x18], r8 [4c 89 44 24 18]
	// mov    QWORD PTR[rsp + 0x8], rcx [48 89 4c 24 08]
	// push   rbx                       [53]
	// push   rsi                       [56]
	BYTE shell_code[] = { 0x48, 0xBA }; // mov rdx
	BYTE shell_code_end[] = { 0xFF, 0xE2 }; // jmp rdx

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook = reinterpret_cast<uintptr_t>(CustomFunction);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook, sizeof(hook));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	if (!WriteReadOnlyMemory(function, &orig, sizeof(orig))) return FALSE;

	return TRUE;
}

extern "C" NTSTATUS HookHandler(PVOID Param)
{
	// Your code here

	//
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS EntryPoint(PDRIVER_OBJECT Object, PUNICODE_STRING nPath)
{
	UNREFERENCED_PARAMETER(Object);
	UNREFERENCED_PARAMETER(nPath) ;

	Hook(&HookHandler);

	return STATUS_SUCCESS;
}
