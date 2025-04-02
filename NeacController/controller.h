#pragma once
#include<Windows.h>
#include<fltuser.h>
#include<emmintrin.h>
#include<winnt.h>
HANDLE connect_driver();

PVOID get_proc_base(HANDLE hPort, DWORD Pid);

DWORD read_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID Out);

DWORD write_proc_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, PVOID In);

BOOL protect_memory(HANDLE hPort, DWORD Pid, PVOID Addr, DWORD Size, DWORD NewProtect);

BOOL update_state(HANDLE hPort, BYTE FunctionId, BYTE State);

BOOL kernel_write_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size);

BOOL kernel_read_data(HANDLE hPort, PVOID Dst, PVOID Src, DWORD Size);

BOOL kill_process(HANDLE hPort, DWORD Pid);

BOOL get_ssdt_items(HANDLE hPort, PVOID Out, DWORD Size);