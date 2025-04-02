#pragma once
#include"controller.h"
#pragma pack(1)
struct NEAC_FILTER_CONNECT {
    DWORD Magic;
    DWORD Version;
    BYTE EncKey[32];
};
#pragma pack()
BYTE Key[33] = "FuckKeenFuckKeenFuckKeenFuckKeen"; 
unsigned char enc_imm[] =
{
    0x7A, 0x54, 0xE5, 0x41, 0x8B, 0xDB, 0xB0, 0x55, 0x7A, 0xBD, 
    0x01, 0xBD, 0x1A, 0x7F, 0x9E, 0x17
};
void encrypt(unsigned int *buffer, unsigned int idx)
{
    __m128i v2; // xmm0
    unsigned int *result; // rax
    int v4; // r9d
    __m128i v5; // xmm0
    __m128i v8; // [rsp+20h] [rbp-18h] BYREF

    __m128i imm = _mm_load_si128((__m128i*)enc_imm);
    __m128i zero;
    memset(&zero, 0 ,sizeof(__m128i));
    v2 = _mm_cvtsi32_si128(idx);
    result = &v8.m128i_u32[3];
    v8 = _mm_xor_si128(
        _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_unpacklo_epi8(v2, v2), 0), 0),
        imm);
    v4 = 0;
    v5 = _mm_cvtsi32_si128(0x4070E1Fu);
    do
    {
        __m128i v6 = _mm_shufflelo_epi16(_mm_unpacklo_epi8(_mm_or_si128(_mm_cvtsi32_si128(*result), v5), zero), 27);
        v6 = _mm_packus_epi16(v6, v6);
        *buffer = (*buffer ^ ~idx) ^ v6.m128i_u32[0] ^ idx;
        ++buffer;
        result = (unsigned int *)((char *)result - 1);
        v4++;
    }
    while ( v4 < 4 );
    return;
}

void encode_payload(PBYTE key, PBYTE buffer, SIZE_T size) {
    for(int i = 0; i < size; i++) {
        buffer[i] ^= key[i & 31]; 
    }
    unsigned int* ptr = (unsigned int*)buffer;
    unsigned int v12 = 0;
    do                                        
    {
        encrypt(ptr, v12++);
        ptr += 4;
    }
    while ( v12 < size >> 4 );
}

HANDLE connect_driver() {
    NEAC_FILTER_CONNECT lpContext;
    lpContext.Magic = 0x4655434B;
    lpContext.Version = 8;
    memcpy(lpContext.EncKey, Key, 32);
    HANDLE hPort;
    HRESULT hResult = FilterConnectCommunicationPort(L"\\OWNeacSafePort", 
        FLT_PORT_FLAG_SYNC_HANDLE,
        &lpContext,
        40,
        NULL,
        &hPort
    );
    if(hResult != S_OK || hPort == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    return hPort;
}

#pragma pack(1)
struct GET_PROC_BASE_PACKET {
    BYTE Opcode;
    DWORD Pid;
};
#pragma pack()
PVOID get_proc_base(HANDLE hPort, DWORD Pid) {
    const int buffersize = (sizeof(GET_PROC_BASE_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    GET_PROC_BASE_PACKET *ptr = (GET_PROC_BASE_PACKET *)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 32;
    encode_payload(Key, buffer, 16);

    BYTE result[16];
    DWORD out;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, result, 16, &out);
    if(hResult == S_OK) {
        PVOID *data = (PVOID*)result;
        return *data;
    }
    return NULL;
}
#pragma pack(1)
struct READ_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};
#pragma pack()
DWORD read_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID Out) {
    const int buffersize = (sizeof(READ_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    READ_MEMORY_PACKET *ptr = (READ_MEMORY_PACKET *)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 9;
    ptr->Addr = Addr;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Out, Size, &out_size);
    if(hResult == S_OK) {
        return out_size;
    }
    return 0;
}

#pragma pack(1)
struct WRITE_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};
#pragma pack()

DWORD write_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID In) {
    const int buffersize = (sizeof(WRITE_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    WRITE_MEMORY_PACKET *ptr = (WRITE_MEMORY_PACKET *)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 61;
    ptr->Addr = Addr;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, In, Size, &out_size);
    if(hResult == S_OK) {
        return out_size;
    }
    return 0;
}

#pragma pack(1)
struct PROTECT_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
    DWORD NewProtect;
};
#pragma pack()

BOOL protect_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, DWORD NewProtect) {
    const int buffersize = (sizeof(PROTECT_MEMORY_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    PROTECT_MEMORY_PACKET *ptr = (PROTECT_MEMORY_PACKET *)buffer;
    ptr->Pid = Pid;
    ptr->Opcode = 60;
    ptr->Addr = Addr;
    ptr->Size = Size;
    ptr->NewProtect = NewProtect;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}
#pragma pack(1)
struct START_WATCH_PACKET {
    BYTE Opcode;
    BYTE FunctionId;
    BYTE State;
};
#pragma pack()

BOOL update_state(HANDLE hPort, BYTE FunctionId, BYTE State) {
    const int buffersize = (sizeof(START_WATCH_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    START_WATCH_PACKET *ptr = (START_WATCH_PACKET *)buffer;
    ptr->Opcode = 1;
    ptr->FunctionId = FunctionId;
    ptr->State = State;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KERNEL_WRITE_PACKET {
    BYTE Opcode;
    PVOID Dst;
    PVOID Src;
    DWORD Size;
};
#pragma pack()

BOOL kernel_write_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size) {
    const int buffersize = (sizeof(KERNEL_WRITE_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KERNEL_WRITE_PACKET *ptr = (KERNEL_WRITE_PACKET *)buffer;
    ptr->Opcode = 70;
    ptr->Dst = Dst;
    ptr->Src = Src;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;

    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KERNEL_READ_PACKET {
    BYTE Opcode;
    PVOID Src;
    DWORD Size;
};
#pragma pack()

BOOL kernel_read_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size) {
    const int buffersize = (sizeof(KERNEL_READ_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KERNEL_READ_PACKET *ptr = (KERNEL_READ_PACKET *)buffer;
    ptr->Opcode = 14;
    ptr->Src = Src;
    ptr->Size = Size;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Dst, Size, &out_size);
    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct KILL_PROCESS_PACKET {
    BYTE Opcode;
    DWORD Pid;
};
#pragma pack()

BOOL kill_process(HANDLE hPort, DWORD Pid) {
    const int buffersize = (sizeof(KILL_PROCESS_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    KILL_PROCESS_PACKET *ptr = (KILL_PROCESS_PACKET *)buffer;
    ptr->Opcode = 20;
    ptr->Pid = Pid;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, NULL, NULL, &out_size);
    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}

#pragma pack(1)
struct GET_SSDT_PACKET {
    BYTE Opcode;
};
#pragma pack()

BOOL get_ssdt_items(HANDLE hPort, PVOID Out, DWORD Size) {
    const int buffersize = (sizeof(GET_SSDT_PACKET) / 16 + 1) * 16;
    BYTE buffer[buffersize];
    GET_SSDT_PACKET *ptr = (GET_SSDT_PACKET *)buffer;
    ptr->Opcode = 12;
    encode_payload(Key, buffer, buffersize);

    DWORD out_size;
    HRESULT hResult = FilterSendMessage(hPort, buffer, buffersize, Out, Size, &out_size);

    if(hResult == S_OK) {
        return TRUE;
    }
    return FALSE;
}



#pragma pack(1)
struct NOTIFY_MESSAGE_BASE {
    FILTER_MESSAGE_HEADER Header;
    BYTE NotifyType;
    DWORD MessageSize;
    DWORD64 Time;
};
struct PROCESS_NOTIFY_MESSAGE : NOTIFY_MESSAGE_BASE {
    DWORD64 Counter;
    BYTE Flag;
    BYTE CreateFlag;
    DWORD CurrentPid;
    DWORD CurrentTid;
    DWORD ParentPid;
    BYTE Padding[13];
    WCHAR ProcName1[512];
    WCHAR ProcName2[512];
    PVOID BackTrace[32];
};
#pragma pack()