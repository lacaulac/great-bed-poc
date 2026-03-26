# Schema for the Neo4J graph database

## Node types

### Behaviour

- `type`: string, the type of the behaviour (e.g., "process", "FILE_READ", "FILE_WRITE", *etc*.)

### Process

*Note: a Process is always a behaviour as well. The Behaviour property "type" is set to "process".*

- `pid`: number, the process ID of the process (*e.g.*, 1234)
- `ppid`: number, the process ID of the parent process (e.g., 32)
- `procname`: string, the name of the process (*e.g.*, "bash")
- `procargs`: list of strings, the command-line arguments of the process (*e.g.*, ["ls", "-l", "-a"] for the command `ls -l -a`)
- `username`: string, the username of the user that executed the process (*e.g.*, "alice")

### File
- `name`: string, the path to the file (*e.g.*, "./secret.txt")
  - *Note: pipes path are represented as `/?/pipe/{inode}`*
- `inode`: number, the inode of the file (*e.g.*, 12345)

### Information
- `type`: string, indicates the type of value of the argument that is represented by this node
  - Possible values include U16 (unsigned 16-bits integer, meant for ports), Integer, Float, Boolean, String and other string-derived types: IPAddress (both IPv4 and IPv6), RemotePath, LocalPath, URL
- `value`: Any (but probably a string), the value of the aforementioned argument

## Relationship types

### CHILD_OF
- From: Behaviour
- To: Behaviour

### EVENT
- From: Process
- To: File
  - *Note: for now, only read/write events are considered.*

#### Properties
- `type`: string, the type of the event (*e.g.*, "read", "write")

### CreatePipe
*Note: For debug purposes to track down the creation of some seemingly useless pipes. Created when receiving a pipe2 event*
- From: Process
- To: File
