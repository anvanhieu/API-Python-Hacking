# API-Python-Hacking

## Course

<https://www.udemy.com/course/hacking-the-windows-api-with-python>

## Files

* [HelloWorld.py](helloworld.py): Show message box use API call with Python.

* [OpenProcess.py](OpenProcess.py): Opens an existing local process object with PID.

* [ProcKiller.py](prockiller.py): Kill the process with window name.

* [SpawnProc.py](SpawnProc.py): Spawn a process.

* [DNSGetCache.py](DNSGetCache.py): Get DNS Cache table with an undocumented function DNSGetCacheDataTable().

* [OpenToken.py](OpenToken.py): Opens the access token associated with a process.

* [CheckTokenPrivs.py](CheckTokenPrivs.py): Check privilege(s) be enabled/disabled in access token.

* [ModifyTokenPrivs.py](ModifyTokenPrivs.py): Modify (enable/disable/remove/...) privilege(s) in access token.

* [Impersonate.py](Impersonate.py): Create a new process (cmd) with same token of a process (Task Manager).

## References

* Process and Thread: <https://techcommunity.microsoft.com/t5/ask-the-performance-team/windows-architecture-the-basics/ba-p/372345>

* Access Token: <https://www.elastic.co/blog/introduction-to-windows-tokens-for-security-practitioners>
