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

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        print(tmp_procargs)
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

def handle_data(data, session: Session):
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
                    is_tracked = is_process_already_tracked(universal_process_identifier, session)
                    # Only parse the commandline if it hasn't been done yet
                    if is_tracked:
                        parsed_commandline = None
                    else:
                        parsed_commandline = cl_parser.parse(parser.ParserRequest(event_data.procname, event_data.procargs))
                    #logger.info(f"\tGot {parsed_commandline.elements}")
                    logger.info(f"Handling event {event_data.pid} {event_data.procname}-{event_data.type}->{event_data.name}")
                    # print(f"\t{event_data.procargs}")
                    logger.info(f"Got UPID {universal_process_identifier} for {event_data.pid}->{event_data.procname}")
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
            behaviour_node_list = []
            argument_node_list = []
            arguments_of_behaviour_list = []
            for queue_element in similar_queue:
                if not queue_element["behaviours"].has_been_processed:
                    # If this was the first time that the commandline was parsed
                    # Add graph nodes for the child behaviours
                    for child_behaviour in queue_element["behaviours"].elements:
                        if child_behaviour["type"] == "Option":
                            for behaviour in child_behaviour["value"]["behaviours"]:
                                behaviour_node_list.append({
                                    "pid": event_data.pid,
                                    "ppid": event_data.ppid,
                                    "upid": queue_element["upid"],
                                    "username": event_data.username,
                                    "procname": event_data.procname,
                                    "procargs": event_data.procargs,
                                    "behaviour": behaviour
                                })
                            # If the option's got an argument, also add the argument node in the arguments_of_behaviour_list
                            # TODO: Add graph nodes for the argument into the arguments_of_behaviour_list
                        elif child_behaviour["type"] == "Argument":
                            argument_node_list.append({
                                "pid": event_data.pid,
                                "ppid": event_data.ppid,
                                "upid": queue_element["upid"],
                                "username": event_data.username,
                                "procname": event_data.procname,
                                "procargs": event_data.procargs,
                                "argument": child_behaviour["value"]["value"],
                                "type": child_behaviour["value"]["type"]
                                })
                queue_element["behaviours"].has_been_processed = True
            if len(behaviour_node_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (p:Process {pid: event.pid, upid: event.upid, username: event.username, procname: event.procname, procargs: event.procargs})
                    MERGE (b:Behaviour {behaviour: event.behaviour, upid: event.upid})
                    MERGE (p)-[:BHV {}]->(b)
                    """,
                    events=behaviour_node_list,
                )
            if len(argument_node_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (p:Process {pid: event.pid, username: event.username, procname: event.procname, procargs: event.procargs})
                    MERGE (a:Argument {argument: event.argument, type: event.type, upid: event.upid})
                    MERGE (p)-[:BHV {}]->(a)
                    """,
                    events=argument_node_list,
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
                        logger.warning(f"Unknown event kind: {event_kind}")
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
