import ctypes

'''
Windows API
    int MessageBoxW(
        HWND    hWnd,
        LPCWSTR lpText,
        LPCWSTR lpCaption,
        UINT    uType
    );
'''

user_handle = ctypes.WinDLL("User32.dll")

hWnd = None
lpText = "Fix motorcycle"
lpCaption = "Finished"
uType = 0x0000002


response = user_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)

if response == 1:
    print("User click OK")
elif response == 2:
    print("User click Cancel")
    
    