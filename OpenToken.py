import ctypes
from ctypes import wintypes

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")
adv_handle = ctypes.WinDLL("advapi32.dll")

PROCESS_ALL_ACCESS = (0x00100000 | 0xF0000 | 0xFFF)

'''
Windows API call
    BOOL OpenProcessToken(
        HANDLE  ProcessHandle,
        DWORD   DesiredAccess,
        PHANDLE TokenHandle
    );
dll: advapi32.dll
'''
# Source token value: https://referencesource.microsoft.com/#System.Workflow.Runtime/DebugEngine/NativeMethods.cs
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)

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

# OpenProcessToken
print('[+] OpenProcessToken')
ProcessHandle = hProcess
DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = ctypes.c_void_p()     # void pointer
response = adv_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

if response == 0:
    print('Error code {0} - OpenProcessToken failed.'.format(k_handle.GetLastError()))
else:
    print('Open acccess token successfully!!')
    




 