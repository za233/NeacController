#include"service.h"
#include<cstdio>
int start_driver() {

    const wchar_t* SERVICE_NAME = L"NeacSafe64";

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        printf("[!] OpenSCManager failed (Error: %d)\n", GetLastError());
        return 1;
    }

    SC_HANDLE service = OpenService(
        scm,
        SERVICE_NAME,
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP
    );

    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("[!] service not exist\n");
        } else {
            printf("[!] OpenService failed (Error: %d)\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&status,
        sizeof(status),
        &bytesNeeded)
        ) {
        printf("[!] QueryServiceStatusEx failed (Error: %d)\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if (status.dwCurrentState != SERVICE_RUNNING) {
        printf("[*] starting...\n");
        if (!StartService(service, 0, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                printf("[+] already started\n");
            } else {
                printf("[!] StartService failed (Error: %d)\n", err);
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return 1;
            }
        } else {
            printf("[+] started.\n");
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

int stop_driver() {

    const wchar_t* SERVICE_NAME = L"NeacSafe64";

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        printf("[!] OpenSCManager failed (Error: %d)\n", GetLastError());
        return 1;
    }

    SC_HANDLE service = OpenService(
        scm,
        SERVICE_NAME,
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP
    );

    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("[!] service not exist\n");
        } else {
            printf("[!] OpenService failed (Error: %d)\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&status,
        sizeof(status),
        &bytesNeeded)
        ) {
        printf("[!] QueryServiceStatusEx failed (Error: %d)\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }
    if (status.dwCurrentState == SERVICE_RUNNING) {
        printf("[*] stopping...\n");
        SERVICE_STATUS stopStatus;
        if (!ControlService(service, SERVICE_CONTROL_STOP, &stopStatus)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return 1;
        }
        DWORD64 startTime = GetTickCount64();
        while (status.dwCurrentState != SERVICE_STOPPED) {
            Sleep(1000);
            if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status,
                sizeof(status),
                &bytesNeeded)
                ) {
                printf("[!] QueryServiceStatusEx failed (Error: %d)\n", GetLastError());
                break;
            }

            if (GetTickCount64() - startTime > 30000) {
                printf("[!] time out\n");
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return 1;
            }
        }
        printf("[+] stopped\n");
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}