import ctypes
from ctypes import wintypes

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")

PROCESS_ALL_ACCESS = (0x00100000 | 0xF0000 | 0xFFF)

'''
    Windows API

    HWND FindWindowA(
        LPCSTR lpClassName,
        LPCSTR lpWindowName
    );

    DWORD GetWindowThreadProcessId(
        HWND    hWnd,
           LPDWORD lpdwProcessId
    );

    HANDLE OpenProcess(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );

    BOOL TerminateProcess(
        HANDLE hProcess,
        UINT   uExitCode
    );

'''

# Enter window name
print('[+] Enter window name')
window_name = input().encode('utf-8')

# FindWindowA
print('[+] FindWindowA')
lpClassName = None 
lpWindowName = ctypes.c_char_p(window_name)  #LPCSTR --> Pointer to string.
windows_handle = u_handle.FindWindowA(None, lpWindowName)
if windows_handle == 0:
    print('Error code {0} - This window name is not available.'.format(k_handle.GetLastError()))
    exit(1)
else:
    print('OK')

# GetWindowThreadProcessId
print('[+] GetWindowThreadProcessId')
hWnd = windows_handle
dwProcessId = ctypes.c_ulong()
lpdwProcessId = ctypes.byref(dwProcessId)
thread_id = u_handle.GetWindowThreadProcessId(hWnd, lpdwProcessId)
if thread_id == 0:
    print('Error code {0} - GetWindowThreadProcessId failed.'.format(k_handle.GetLastError()))
    exit(1)
else:
    print('OK')

# OpenProcess
print('[+] OpenProcess')
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
if hProcess == 0:
    print('Error code {0} - OpenProcess failed.'.format(k_handle.GetLastError()))
    exit(1)
else:
    print('OK')

# TerminateProcess
print('[+] TerminateProcess')
uExitCode = 0x1     #1 - program exits for system-specific meaning.
res = k_handle.TerminateProcess(hProcess, uExitCode)
if res is False:
    print('Error code {0} - OpenProcess failed.'.format(k_handle.GetLastError()))
    exit(1)
else:
    print('OK')
    print('All done!!!')

 