# Copyright (C) 2025  Antonin Verdier & Institut de Recherche en Informatique de Toulouse

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import cbor2
import sys
from queue import Queue
import queue
from os import stat
import parser
import hashlib
import logging
logger = logging.getLogger(__name__)
import requests
import uuid

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='[GReAT-BeD][%(levelname)s] %(asctime)s - %(message)s')

setup_logging()

from neo4j import GraphDatabase, RoutingControl, Driver, Session

URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "neo4j!!!")

PARSER_URL = "http://localhost:6880"
cl_parser = parser.Parser(PARSER_URL)

query_queue = Queue()
query_trigger = 1

class PipeFDTableEntry:
    def __init__(self, pid: int, fd: int, ino: int):
        self.pid = pid
        self.fd = fd
        self.ino = ino

    def __repr__(self):
        return f"PipeFDTableEntry(pid={self.pid}, fd={self.fd}, ino={self.ino})"

class PipeFDTable:
    def __init__(self):
        self.innertable = [] # type: list[PipeFDTableEntry]

    def add_entry(self, pid: int, fd: int, ino: int):
        if self.entry_exists(pid, fd):
            print(f"Entry already exists for PID {pid} and FD {fd}.")
            return
        entry = PipeFDTableEntry(pid, fd, ino)
        self.innertable.append(entry)
        print(f"Added pipe entry: {entry}")

    def get_entry(self, pid: int, fd: int):
        for entry in self.innertable:
            if entry.pid == pid and entry.fd == fd:
                return entry
        return None

    def get_entries_by_pid(self, pid: int):
        entries = []
        for entry in self.innertable:
            if entry.pid == pid:
                entries.append(entry)
        return entries

    def clone_pid_into(self, ppid: int, pid: int):
        new_entries = []
        for entry in self.innertable:
            if entry.pid == ppid:
                new_entry = PipeFDTableEntry(pid, entry.fd, entry.ino)
                new_entries.append(new_entry)
        self.innertable.extend(new_entries)
        print(f"Cloned {len(new_entries)} entries from PID {ppid} to PID {pid}")

    def remove_entry(self, pid: int, fd: int):
        entry_to_remove = None
        for entry in self.innertable:
            if entry.pid == pid and entry.fd == fd:
                entry_to_remove = entry
                break
        if entry_to_remove:
            self.innertable.remove(entry_to_remove)
            print(f"Removed pipe entry: {entry_to_remove}")
        else:
            print(f"No entry found for PID {pid} and FD {fd}")

    def remove_entries_by_pid(self, pid: int):
        entries_to_remove = []
        for entry in self.innertable:
            if entry.pid == pid:
                entries_to_remove.append(entry)
        for entry in entries_to_remove:
            self.innertable.remove(entry)
            print(f"Removed pipe entry: {entry}")

    def entry_exists(self, pid: int, fd: int):
        for entry in self.innertable:
            if entry.pid == pid and entry.fd == fd:
                return True
        return False

    def __repr__(self):
        return f"PipeFDTable(entries={self.innertable})"

    def beauty_print(self):
        print("PipeFDTable:")
        pid_header = "PID"
        fd_header = "FD"
        ino_header = "INO"
        pid_strings = [str(entry.pid) for entry in self.innertable]
        fd_strings = [str(entry.fd) for entry in self.innertable]
        ino_strings = [str(entry.ino) for entry in self.innertable]
        max_pid_length = max(len(pid_header), max(len(s) for s in pid_strings))
        max_fd_length = max(len(fd_header), max(len(s) for s in fd_strings))
        max_ino_length = max(len(ino_header), max(len(s) for s in ino_strings))
        print(f"{pid_header:<{max_pid_length}} {fd_header:<{max_fd_length}} {ino_header:<{max_ino_length}}")
        print("-" * (max_pid_length + max_fd_length + max_ino_length + 2))
        for entry in self.innertable:
            print(f"{entry.pid:<{max_pid_length}} {entry.fd:<{max_fd_length}} {entry.ino:<{max_ino_length}}")

class FSEventData:
    def __init__(self, raw_object: dict):
        self.pid = raw_object[b"pid"]
        self.ppid = raw_object[b"ppid"]
        self.type = raw_object[b"type"].decode(encoding="utf-8")
        self.name = raw_object[b"name"].decode(encoding="utf-8")
        self.username = raw_object[b"username"].decode(encoding="utf-8")
        self.procname = raw_object[b"procname"].decode(encoding="utf-8")
        tmp_procargs = raw_object[b"procargs"]
        # Split the procargs into a list of arguments on NULL bytes
        self.procargs = [e.decode('utf-8') for e in tmp_procargs.split(b'\t')][1:]
        self.isfileapipe = raw_object[b"ispipe"]

        # if self.isfileapipe:
        #     pipe_path = self.name
        #     pipe_id = stat(pipe_path).st_ino
        #     self.name = f"pipe://{pipe_id}"

class Pipe2EventData:
    def __init__(self, raw_object: dict):
        self.fd1 = raw_object[b"fd1"]
        self.fd2 = raw_object[b"fd2"]
        self.ino = raw_object[b"ino"]
        self.flags = raw_object[b"flags"]
        self.pid = raw_object[b"pid"]
        self.ppid = raw_object[b"ppid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")
# encoded_table = {
# 			["fd1"] = fd1,
# 			["fd2"] = fd2,
# 			["ino"] = ino,
# 			["flags"] = flags,
# 			["pid"] = evt.field(pid),
# 			["username"] = evt.field(username),
# 		}

    def __repr__(self):
        return f"Pipe2EventData(fd1={self.fd1}, fd2={self.fd2}, ino={self.ino}, flags={self.flags}, pid={self.pid}, ppid={self.ppid}, username={self.username})"

class CloseEventData:
    def __init__(self, raw_object: dict):
        self.fd = raw_object[b"fd"]
        self.pid = raw_object[b"pid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")
        # self.name = raw_object[b"name"].decode(encoding="utf-8")
        # self.procname = raw_object[b"procname"].decode(encoding="utf-8")
        # self.procargs = raw_object[b"procargs"].decode(encoding="utf-8")

    def __repr__(self):
        return f"CloseEventData(fd={self.fd}, pid={self.pid}, username={self.username})"

class CloneEventData:
    def __init__(self, raw_object: dict):
        self.ppid = raw_object[b"ppid"]
        self.pid = raw_object[b"pid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")

    def __repr__(self):
        return f"CloneEventData(ppid={self.ppid}, pid={self.pid}, username={self.username})"


def handle_pipe2_event(data, pipe_table: PipeFDTable):
    if isinstance(data, dict):
        # Decode the CBOR data
        event_data = Pipe2EventData(data)
        print(f"Pipe2 Event: {event_data}")
        pipe_table.add_entry(event_data.pid, event_data.fd1, event_data.ino)
        pipe_table.add_entry(event_data.pid, event_data.fd2, event_data.ino)
    else:
        print("Unknown data format:", data)

def handle_close_event(data, pipe_table: PipeFDTable):
    if isinstance(data, dict):
        # Decode the CBOR data
        event_data = CloseEventData(data)
        print(f"Close Event: {event_data}")
        pipe_table.remove_entry(event_data.pid, event_data.fd)
    else:
        print("Unknown data format:", data)

def handle_clone_event(data, pipe_table: PipeFDTable):
    if isinstance(data, dict):
        # Decode the CBOR data
        event_data = CloneEventData(data)
        print(f"Clone Event: {event_data}")
        pipe_table.clone_pid_into(event_data.ppid, event_data.pid)
    else:
        print("Unknown data format:", data)

def get_process_identifier(pid: int, ppid: int, name: str, arglist: list[str]) -> str:
    return hashlib.sha1(f"{pid}-{ppid}-{name}-{arglist}".encode()).hexdigest()

def is_process_already_tracked(upid: str, session: Session) -> bool:
    res = session.run("MATCH (p:Process {upid: $upid}) RETURN p", upid=upid)
    return len(list(res)) != 0

def get_uuid():
    return str(uuid.uuid4())

def handle_data(data, session: Session):
    already_parsed_upid = set() # Avoid asking Neo4J 10 times in a row
    if isinstance(data, dict):
        # Decode the CBOR data
        event_data = FSEventData(data)
        query_queue.put(event_data)

        if query_queue.qsize() >= query_trigger:
            # Process the queue
            logger.info(f"Processing {query_queue.qsize()} events...")
            process_queue = []
            similar_queue = [] #Must make another queue that won't have behaviour data, or Neo4J is unhappy... There's got to be a better way to do this
            for i in range(query_trigger):
                try:
                    event_data = query_queue.get_nowait()
                    universal_process_identifier = get_process_identifier(event_data.pid, event_data.ppid, event_data.procname, event_data.procargs)
                    # First, check if the process's tracking state is cached
                    is_tracked = universal_process_identifier in already_parsed_upid
                    # If it isn't, check if it's already tracked in the database
                    if not is_tracked:
                        is_tracked = is_process_already_tracked(universal_process_identifier, session)
                    # Only parse the commandline if it hasn't been done yet
                    if is_tracked:
                        parsed_commandline = None
                        # Add the process to the already_parsed_upid set, to speed up future checks
                        already_parsed_upid.add(universal_process_identifier)
                    else:
                        parsed_commandline = cl_parser.parse(parser.ParserRequest(event_data.procname, event_data.procargs))
                    #logger.info(f"\tGot {parsed_commandline.elements}")
                    logger.info(f"Handling event {event_data.pid} {event_data.procname}-{event_data.type}->{event_data.name}")
                    # print(f"\t{event_data.procargs}")
                    # logger.info(f"Got UPID {universal_process_identifier} for {event_data.pid}->{event_data.procname}")
                    process_queue.append({
                        "pid": event_data.pid,
                        "ppid": event_data.ppid,
                        "upid": universal_process_identifier,
                        "type": event_data.type,
                        "name": event_data.name,
                        "username": event_data.username,
                        "procname": event_data.procname,
                        "procargs": event_data.procargs,
                    })
                    if parsed_commandline:
                        similar_queue.append({
                            "pid": event_data.pid,
                            "ppid": event_data.ppid,
                            "upid": universal_process_identifier,
                            "type": event_data.type,
                            "name": event_data.name,
                            "username": event_data.username,
                            "procname": event_data.procname,
                            "procargs": event_data.procargs,
                            "behaviours": parsed_commandline
                        })
                except queue.Empty: #Turns out the queue is empty (thank you queue.qsize())
                    break

            # Let's batch process the data
            session.run(
                """
                UNWIND $events AS event
                MERGE (p:Process {pid: event.pid, upid: event.upid, username: event.username, procname: event.procname, procargs: event.procargs})
                MERGE (f:File {name: event.name})
                MERGE (p)-[:EVENT {type: event.type}]->(f)
                """,
                events=process_queue,
            )
            # We'll collect behaviours and arguments and attach them according to the
            # rules requested by the user:
            # - If there are no inherent behaviours: attach all parser behaviours/args to the Process
            # - If there are >=2 inherent behaviours: attach all inherent (and other) behaviours to the Process
            # - If there is exactly 1 inherent behaviour: attach that inherent behaviour to the Process;
            #   attach all other behaviours and arguments as children of that inherent behaviour
            behaviour_node_list = []                # Process -> Behaviour events
            argument_node_list = []                 # Process -> Argument events
            behaviour_parent_child_list = []        # ParentBehaviour -> ChildBehaviour events
            behaviour_parent_argument_list = []     # ParentBehaviour -> Argument events

            for queue_element in similar_queue:
                if queue_element["behaviours"].has_been_processed:
                    continue


                # collect behaviours and arguments from parsed commandline
                # behaviour_option_map: behaviour string -> set(option_name)
                from collections import defaultdict
                behaviour_option_map = defaultdict(set)
                behaviour_option_arg_map = dict()  # (beh, opt) -> {argument, type}
                arguments = []

                for child_behaviour in queue_element["behaviours"].elements:
                    if child_behaviour["type"] == "Option":
                        opt_name = child_behaviour["value"].get("name", "")
                        # extract option-level argument if present
                        raw_opt_arg = child_behaviour["value"].get("argument", None)
                        def _extract_opt_arg(raw):
                            if raw is None:
                                return None
                            # if it's already in {"type":.., "value":..} form
                            if isinstance(raw, dict) and "type" in raw and "value" in raw:
                                return {"argument": raw["value"], "type": raw["type"]}
                            # if it's a dict with a single key (e.g. {"SOME": val})
                            if isinstance(raw, dict) and len(raw) == 1:
                                k = next(iter(raw.keys()))
                                v = raw[k]
                                # if v is a dict with single value
                                if isinstance(v, dict) and len(v) == 1:
                                    t = next(iter(v.keys()))
                                    return {"argument": v[t], "type": t}
                                return {"argument": v, "type": str(k)}
                            # fallback to string
                            return {"argument": str(raw), "type": "unknown"}

                        opt_arg = _extract_opt_arg(raw_opt_arg)
                        for behaviour in child_behaviour["value"]["behaviours"]:
                            # behaviour may itself be a list (grouped inherent behaviours)
                            if isinstance(behaviour, (list, tuple)):
                                for single in behaviour:
                                    behaviour_option_map[single].add(opt_name)
                                    if opt_arg is not None:
                                        behaviour_option_arg_map[(single, opt_name)] = opt_arg
                            else:
                                behaviour_option_map[behaviour].add(opt_name)
                                if opt_arg is not None:
                                    behaviour_option_arg_map[(behaviour, opt_name)] = opt_arg
                    elif child_behaviour["type"] == "Argument":
                        arguments.append({
                            "argument": child_behaviour["value"]["value"],
                            "type": child_behaviour["value"]["type"],
                        })

                # prepare common metadata
                common = {
                    "pid": queue_element["pid"],
                    "ppid": queue_element["ppid"],
                    "upid": queue_element["upid"],
                    "username": queue_element["username"],
                    "procname": queue_element["procname"],
                    "procargs": queue_element["procargs"],
                }

                # decide inherent behaviours (those that have option name 'inherent')
                inherent_behaviours = {beh for beh, opts in behaviour_option_map.items() if 'inherent' in opts}

                # Apply attachment rules using behaviour+option pairs (so two identical behaviour
                # strings with different option names won't be merged)
                if len(inherent_behaviours) == 0:
                    # attach all behaviour+option pairs to Process
                    for beh in sorted(behaviour_option_map.keys()):
                        for opt in sorted(behaviour_option_map[beh]):
                            evt = dict(common)
                            evt["behaviour"] = beh
                            evt["option"] = opt
                            behaviour_node_list.append(evt)
                            # attach option-level argument (if any) as child of the behaviour node
                            opt_key = (beh, opt)
                            if opt_key in behaviour_option_arg_map:
                                arg = behaviour_option_arg_map[opt_key]
                                behaviour_parent_argument_list.append({
                                    **common,
                                    "parent_behaviour": beh,
                                    "parent_option": opt,
                                    **arg,
                                })
                    # attach all arguments to Process
                    for arg in arguments:
                        evt = dict(common)
                        evt.update(arg)
                        argument_node_list.append(evt)

                elif len(inherent_behaviours) >= 2:
                    # attach all behaviour+option pairs to Process (inherent + others)
                    for beh in sorted(behaviour_option_map.keys()):
                        for opt in sorted(behaviour_option_map[beh]):
                            evt = dict(common)
                            evt["behaviour"] = beh
                            evt["option"] = opt
                            behaviour_node_list.append(evt)
                            # attach option-level argument (if any) as child of the behaviour node
                            opt_key = (beh, opt)
                            if opt_key in behaviour_option_arg_map:
                                arg = behaviour_option_arg_map[opt_key]
                                behaviour_parent_argument_list.append({
                                    **common,
                                    "parent_behaviour": beh,
                                    "parent_option": opt,
                                    **arg,
                                })
                    # arguments remain children of Process
                    for arg in arguments:
                        evt = dict(common)
                        evt.update(arg)
                        argument_node_list.append(evt)

                else:  # exactly one inherent behaviour
                    inherent = next(iter(inherent_behaviours))
                    # attach only the inherent behaviour (with option 'inherent') to the Process
                    evt = dict(common)
                    evt["behaviour"] = inherent
                    evt["option"] = 'inherent'
                    behaviour_node_list.append(evt)

                    # all other behaviour+option pairs become children of the inherent behaviour node
                    for beh in sorted(behaviour_option_map.keys()):
                        for opt in sorted(behaviour_option_map[beh]):
                            # skip the parent inherent pair itself
                            if beh == inherent and opt == 'inherent':
                                continue
                            behaviour_parent_child_list.append({
                                **common,
                                "parent_behaviour": inherent,
                                "parent_option": 'inherent',
                                "child_behaviour": beh,
                                "child_option": opt,
                            })

                    # attach arguments as children of the inherent behaviour node
                    for arg in arguments:
                        behaviour_parent_argument_list.append({
                            **common,
                            "parent_behaviour": inherent,
                            "parent_option": 'inherent',
                            **arg,
                        })
                    # attach option-level arguments: all option args become children of the inherent behaviour
                    for (beh, opt), arg in behaviour_option_arg_map.items():
                        behaviour_parent_argument_list.append({
                            **common,
                            "parent_behaviour": inherent,
                            "parent_option": 'inherent',
                            **arg,
                        })

                queue_element["behaviours"].has_been_processed = True

            # Create/attach Behaviour nodes to Process
            if len(behaviour_node_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (p:Process {pid: event.pid, upid: event.upid, username: event.username, procname: event.procname, procargs: event.procargs})
                    MERGE (b:Behaviour {behaviour: event.behaviour, option: event.option, upid: event.upid})
                    MERGE (p)-[:BHV {}]->(b)
                    """,
                    events=behaviour_node_list,
                )

            # Create Argument nodes attached to Process
            if len(argument_node_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (p:Process {pid: event.pid, upid: event.upid, username: event.username, procname: event.procname, procargs: event.procargs})
                    MERGE (a:Argument {argument: event.argument, type: event.type, upid: event.upid})
                    MERGE (p)-[:BHV {}]->(a)
                    """,
                    events=argument_node_list,
                )

            # Create parent -> child Behaviour relationships (for the single-inherent case)
            if len(behaviour_parent_child_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (parent:Behaviour {behaviour: event.parent_behaviour, option: event.parent_option, upid: event.upid})
                    MERGE (child:Behaviour {behaviour: event.child_behaviour, option: event.child_option, upid: event.upid})
                    MERGE (parent)-[:BHV {}]->(child)
                    """,
                    events=behaviour_parent_child_list,
                )

            # Create parent Behaviour -> Argument relationships (single-inherent case)
            if len(behaviour_parent_argument_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (parent:Behaviour {behaviour: event.parent_behaviour, option: event.parent_option, upid: event.upid})
                    MERGE (a:Argument {argument: event.argument, type: event.type, upid: event.upid})
                    MERGE (parent)-[:BHV {}]->(a)
                    """,
                    events=behaviour_parent_argument_list,
                )

        # print(f"PID: {event_data.pid}, Type: {event_data.type}, Name: {event_data.name}")

        # Create a session and run a Cypher query
        # session.run(
        #     """
        #     MERGE (p:Process {pid: $pid})
        #     MERGE (f:File {name: $name})
        #     MERGE (p)-[:EVENT {type: $type}]->(f)
        #     """,
        #     pid=event_data.pid,
        #     name=event_data.name,
        #     type=event_data.type,
        # )
    else:
        print(f"Unknown data format: {data}")

def main(file_path, driver: Driver):
    logger.info("Starting cbor-events collector")
    # try:

    pipe_table = PipeFDTable()

    with driver.session(database="sysevents") as session:
        with open(file_path, "rb") as f:
            while True:
                try:
                    # Read a single CBOR object from the file
                    data = cbor2.load(f)
                    if data == 0x0a:
                        continue
                    if data[b"kind"] == b"fd_rw":
                        handle_data(data, session)
                    # elif data[b"kind"] == b"pipe2":
                    #     handle_pipe2_event(data, pipe_table)
                    # elif data[b"kind"] == b"close":
                    #     handle_close_event(data, pipe_table)
                    # elif data[b"kind"] == b"clone":
                    #     handle_clone_event(data, pipe_table)
                    else:
                        event_kind = data[b"kind"].decode(encoding="utf-8")
                        logger.debug(f"Unknown event kind: {event_kind}")
                    # handle_data(data, driver)
                except EOFError:
                    break
                except requests.exceptions.ConnectionError as e:
                    logger.error(f"Connection error occurred: {e}")
                except KeyboardInterrupt:
                    print("Exiting...")
                    break
        session.close()
        logger.info("Session closed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <input_fifo>")
        sys.exit(1)
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
       driver.verify_connectivity()
       main(sys.argv[1], driver)
