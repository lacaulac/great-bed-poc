# GReAT-BeD PoC implementation

A proof-of-concept implementation of the [GReAT-BeD framework](https://github.com/lacaulac/GReAT-BeD), pre-print paper available *relatively* soon.
The proof-of-concept is released under GPL 3. Please note that this repository includes MIT-licensed `cbor.lua`, from the [LUA CBOR implementation](https://github.com/Zash/lua-cbor) provided by Zash, mkluwe and Kristopher38. A copy of the license is included in `LICENSE-mit`

## Dependencies

### Software

- [`just`](https://github.com/casey/just)
- [`uv`](https://github.com/astral-sh/uv)
- [`sysdig`](https://github.com/draios/sysdig) -> See below
- A [`Neo4J`](https://neo4j.com/) instance running locally with a `sysevents` database. Credentials can be configured using the `URI` and `AUTH` variables at the top of `collectors/cbor_events/main.py`, right after most of the imports. (Yeah, it's a PoC, what did you expect?)
- [`universal-cli-parser`](https://github.com/lacaulac/universal-cli-parser)

### Slight adjustment to libsinsp's threadinfo code
This requires a modification of sysdig's libsinsp library's sinsp_threadinfo::set_args function (threadinfo.cpp, around line 560). Instead of using a space character as a separator, we use a tab character; while this is far from perfect from a security perspective, it provides us with a viable solution for our proof-of-concept. This is what the function looks like after the modification:

```cpp
void sinsp_threadinfo::set_args(const std::vector<std::string>& args) {
	m_args = args;
	m_cmd_line = get_comm();
	if(!m_cmd_line.empty()) {
		for(const auto& arg : m_args) {
			m_cmd_line += "\t";
			m_cmd_line += arg;
		}
	}
}
```

This modification allows us to obtain the command line arguments of a process in a clearer way, as using a space character as a separator yields identical arglist strings for different command-lines such as these:
- `ls Hello world exclamationmark`
- `ls "Hello world" exclamationmark`
- `ls Hello "world exclamationmark "`

## Running the PoC
After having started the [command-line parser](https://github.com/lacaulac/universal-cli-parser), the easiest way to run the PoC is to run the following commands:

```bash
just rc-colsel
```

This will start the PoC, listening for events happening for user 1000. The sysdig process executes the `cbor_events.lua` chisel and writes CBOR-encoded datastructures that represent the events captured by sysdig into a randomly-named pipe, that is then read by the python script.

## Limitations

### PID Limit
The identification of a specific process is done by its process ID, Parent Process ID and program name as well as its command line arguments. This is far from perfect, as theoritically speaking, there could be duplicates of the same process ID and command line arguments, which could lead to confusion when trying to identify a specific process. As this is unlikely, we do not have anything planned to detect such cases.
