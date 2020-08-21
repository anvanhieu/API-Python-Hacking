import ctypes
from ctypes.wintypes import HANDLE, DWORD, LPVOID, BOOL, LPSTR, LPBYTE, WORD

k_handle = ctypes.WinDLL("kernel32.dll")

# PROCESS_INFORMATION structure
class PROCESS_INFORMATION(ctypes.Structure):
    _field_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD)
    ]
        
# STARTUPINFOA structure       
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

'''
    BOOL CreateProcessW(
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
);
 '''

lpApplicationName = "c:\\Windows\\System32\\cmd.exe"  # path to application
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
bInheritHandles = False
dwCreationFlags = 0x0010   # CREATE_NEW_CONSOLE 
lpEnvironment = None
lpCurrentDirectory = None
lpStartupInfo = ctypes.byref(STARTUPINFOA())
lpProcessInformation = ctypes.byref(PROCESS_INFORMATION())

response = k_handle.CreateProcessW(
                            lpApplicationName,
                            lpCommandLine,
                            lpProcessAttributes,
                            lpThreadAttributes,
                            bInheritHandles,
                            dwCreationFlags,
                            lpEnvironment,
                            lpCurrentDirectory,
                            lpStartupInfo,
                            lpProcessInformation)
 
if response != 0:
    print("Process is running!!")
    print(ctypes.cast(lpProcessInformation, ctypes.py_object).value)
else:
    print("Create process failed. Error code {}".format(k_handle.GetLastError()))

    
