import ctypes
from ctypes.wintypes import ULONG, LONG, DWORD, BOOL

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")
adv_handle = ctypes.WinDLL("advapi32.dll")

PROCESS_ALL_ACCESS = (0x00100000 | 0xF0000 | 0xFFF)

# Source https://referencesource.microsoft.com/#System.IdentityModel/System/IdentityModel/Privilege.cs
SE_PRIVILEGE_DISABLED = 0x0000
SE_PRIVILEGE_ENABLED = 0x0002
SE_PRIVILEGE_REMOVED = 0x0004

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

# define LUID structure
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", ULONG),
        ("HighPart", LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD)
    ]

class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privilege", LUID_AND_ATTRIBUTES)
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]

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
    #exit(1)
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
response = adv_handle.OpenProcessToken(
    ProcessHandle, 
    DesiredAccess, 
    ctypes.byref(TokenHandle))

if response == 0:
    print('Error code {0} - OpenProcessToken failed.'.format(k_handle.GetLastError()))
else:
    print('Open acccess token successfully!!')


print('[+] LookupPrivilegeValue')
lpSystemName = None
lpName = "SeBackupPrivilege"
lpLuid = LUID()

response = adv_handle.LookupPrivilegeValueW(
    lpSystemName, 
    lpName, 
    ctypes.byref(lpLuid))

if response == 0:
    print('Error code {0} - LookupPrivilegeValue failed.'.format(k_handle.GetLastError()))
else:
    print('Lookup privilege {0} successfully!!'.format(lpName))

# PrivilegeCheck
print('[+] PrivilegeCheck')
ClientToken = TokenHandle
RequiredPrivileges = PRIVILEGE_SET()
RequiredPrivileges.PrivilegeCount = 1
RequiredPrivileges.Privilege.Luid = lpLuid
RequiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_ENABLED
pfResult = BOOL()

response = adv_handle.PrivilegeCheck(
    ClientToken, 
    ctypes.byref(RequiredPrivileges), 
    ctypes.byref(pfResult))

if response == 0:
    print('Error code {0} - PrivilegeCheck failed.'.format(k_handle.GetLastError()))
else:
    print('PrivilegeCheck successfully!!')


if pfResult.value == 0:
    print('Privilege {0} is DISABLED'.format(lpName))
    RequiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_ENABLED      # flip attribute
else:
    print('Privilege {0} is ENABLED'.format(lpName))
    RequiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_DISABLED     # flip attribute

'''
    BOOL AdjustTokenPrivileges(
        HANDLE            TokenHandle,
        BOOL              DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD             BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD            ReturnLength
);
'''
# AdjustTokenPrivileges
print('[+] AdjustTokenPrivileges')
DisableAllPrivileges = False
NewState = TOKEN_PRIVILEGES()
NewState.PrivilegeCount = 1
NewState.Privileges = RequiredPrivileges.Privilege    
BufferLength = ctypes.sizeof(NewState)
PreviousState = ctypes.c_void_p()
ReturnLength = ctypes.c_void_p()

response = adv_handle.AdjustTokenPrivileges(
    TokenHandle, 
    DisableAllPrivileges, 
    ctypes.byref(NewState), 
    BufferLength, 
    ctypes.byref(PreviousState), 
    ctypes.byref(ReturnLength))

if response == 0:
    print('Privilege {0} is NOT FLIPPED'.format(lpName))
else:
    print('Privilege {0} is FLIPPED'.format(lpName))