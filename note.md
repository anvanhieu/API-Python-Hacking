# Notes for this course

* Process and Thread:

> Think of a process as a room and a thread as a person in the room. A program is a set of instructions for the person in the room to carry out. Looking at it in this fashion, it is easy to see that the process itself doesn't do any work, but the thread does. A thread lives in a process, and executes the instructions of the program.

* Handle

> A handle is an abstract reference to a resource that is used when application software references blocks of memory or objects that are managed by another system like a database or an operating system.
> A resource handle can be an opaque identifier, in which case it is often an integer number (often an array index in an array or "table" that is used to manage that type of resource), or it can be a pointer that allows access to further information. Common resource handles include file descriptors, network sockets, database connections, process identifiers (PIDs), and job IDs. PIDs and job IDs are explicitly visible integers; while file descriptors and sockets (which are often implemented as a form of file descriptor) are represented as integers, they are typically considered opaque. In traditional implementations, file descriptors are indices into a (per-process) file descriptor table, thence a (system-wide) file table.
