#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <conio.h>

using namespace std;

BOOL EnablePriv(LPCSTR lpszPriv)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkprivs;
    ZeroMemory(&tkprivs, sizeof(tkprivs));

    if(!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
        return FALSE;

    if(!LookupPrivilegeValue(NULL, lpszPriv, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tkprivs.PrivilegeCount = 1;
    tkprivs.Privileges[0].Luid = luid;
    tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
    CloseHandle(hToken);

    return bRet;
}


DWORD FindProcessID(LPCTSTR szProcessName)
{
    DWORD dwPID = -1;
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe;

    pe.dwSize = sizeof(PROCESSENTRY32);
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

    Process32First(hSnapShot, &pe);
    do
    {
        if(!_stricmp(szProcessName, pe.szExeFile))
        {
            dwPID = pe.th32ProcessID;
            break;
        }
    }
    while(Process32Next(hSnapShot, &pe));

    CloseHandle(hSnapShot);

    return dwPID;
}

int main()
{
    const char* MomiMember[]= {
        "ovtlowfgu.exe",
        "ospmythug.exe",
        "seyvzwvuu.exe",
        "ProcessHideEXEx64.exe",
        "mwyqwxlzy.exe",
        "PmtStartLoader.exe",
        "resjnt.exe",
        0
        };
    int len;
    for(len = 0;MomiMember[len] != 0;len++); // 맘아이 프로세스 개수 구하기
    HANDLE* hProcess = new HANDLE[len];

    EnablePriv(SE_DEBUG_NAME); // SeDebug 권한 활성화

    int terminate_count = 0;
    while(TRUE)
    {
        for(int i = 0;i < len;i++)
        {
            int dwPID = FindProcessID(MomiMember[i]);
            hProcess[i] = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

            if(!hProcess[i])
                cout << "OpenProcess failed, PID: " << dwPID << " | ";

            switch(GetLastError())
            {
            case 0 : // SUCCESS
                break;

            case 5 : // ACCESS_DENIED
                cout << "Admin Privileges required" << endl;
                break;

            case 87 : // Process ID가 존재하지 않음
                cout << "Process doesn't exist" << endl;
                break;

            default :
                cout << "Undefined Error : " << GetLastError() << endl;
                break;
            }
        }
        for(int i = 0;i < len;i++)
        {
            if(TerminateProcess(hProcess[i], 0))
            {
                terminate_count++;
                cout << "Terminate Success" << endl;
            }
        }
        getch();
    }
    getch();
}
