# This is undocumented API Call
import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPWSTR

k_handkle = ctypes.WinDLL("kernel32.dll")
d_handle = ctypes.WinDLL("DNSAPI.dll")

#DNS_CACHE_ENTRY structure
class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_ = [
            ("pNext", HANDLE),
            ("recName", LPWSTR),
            ("wType", DWORD),
            ("wDataLength", DWORD),
            ("dwFlags", DWORD)
        ]

#Setup a new base Entry
DNS_Entry = DNS_CACHE_ENTRY()

# Size of Entry
DNS_Entry.wDataLength = 1024

#Use DnsGetCacheDataTable API call to grab DNS Entry Cache
response = d_handle.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

#Handle for errors
if response == 0:
    print("Error Code {0}".format(k_handkle.GetLastError()))

# Grabing First pNext
# Convert a Pointer to a Structure to ignore the first entry as its 0
DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))


while True:
       # Handle try catch for when we dont have any more entries
    try:
        print("DNS Entry {0} - Type {1}".format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
        DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))
    except:
        break
        

