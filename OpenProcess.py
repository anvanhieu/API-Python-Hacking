import ctypes

k_handle = ctypes.WinDLL("kernel32.dll")

'''
WinAPI Function
    HANDLE OpenProcess(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
       );
'''

PROCESS_ALL_ACCESS = (0x00100000 | 0xF0000 | 0xFFF)     # All possible access rights for a process object

dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = 0x4   #change ID 

response = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

error = k_handle.GetLastError()
if error != 0:
    print("Error code {0}".format(error))
    exit(0)
if response <=0:
    print("Handle was not created")
else:
    print("Handle was created: {0}".format(response))