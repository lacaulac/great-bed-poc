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

import hashlib
import logging
import queue
import sys
from enum import Enum
from os import stat
from queue import Queue

import cbor2

import parser

logger = logging.getLogger(__name__)
import uuid

import requests


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        # level=logging.DEBUG,
        format="[GReAT-BeD][%(levelname)s] %(asctime)s - %(message)s",
    )


setup_logging()

from neo4j import Driver, GraphDatabase, RoutingControl, Session

URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "neo4j!!!")

PARSER_URL = "http://localhost:6880"
cl_parser = parser.Parser(PARSER_URL)

query_queue = Queue()
query_trigger = 1


class ProcessingStep(Enum):
    CLONE = 1
    EXECVE = 2


# pid -> ProcessingStep. Allows us to avoid asking Neo4J to see
# # if the process has already been seen (to avoid processing multiple
# # execve, or detect the apparition of events related to a process
# # we do not know about!)
pidProcessingState = dict()


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
        self.procargs = [e.decode("utf-8") for e in tmp_procargs.split(b"\t")][1:]
        self.isfileapipe = raw_object[b"ispipe"]

    def __repr__(self):
        return f"FSEventData(pid={self.pid}, ppid={self.ppid}, type={self.type}, name={self.name}, username={self.username}, procname={self.procname}, procargs={self.procargs}, isfileapipe={self.isfileapipe})"


class CloneEventData:
    def __init__(self, raw_object: dict):
        self.ppid = raw_object[b"ppid"]
        self.pid = raw_object[b"pid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")
        tmp_procargs = raw_object[b"procargs"]
        # Split the procargs into a list of arguments on NULL bytes
        self.procargs = [e.decode("utf-8") for e in tmp_procargs.split(b"\t")][1:]

    def __repr__(self):
        return f"CloneEventData(pid={self.pid}, ppid={self.ppid}, username={self.username}, procargs={self.procargs})"


class ExecveEventData:
    def __init__(self, raw_object: dict):
        self.pid = raw_object[b"pid"]
        self.ppid = raw_object[b"ppid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")
        self.procname = raw_object[b"procname"].decode(encoding="utf-8")
        tmp_procargs = raw_object[b"procargs"]
        # Split the procargs into a list of arguments on NULL bytes
        self.procargs = [e.decode("utf-8") for e in tmp_procargs.split(b"\t")][1:]

    def __repr__(self):
        return f"ExecveEventData(pid={self.pid}, ppid={self.ppid}, username={self.username}, procname={self.procname}, procargs={self.procargs})"


def get_process_identifier(pid: int, ppid: int, name: str, arglist: list[str]) -> str:
    # return hashlib.sha1(f"{pid}-{ppid}-{name}-{arglist}".encode()).hexdigest()
    return hashlib.sha1(f"{pid}-{ppid}".encode()).hexdigest()


def is_process_already_tracked(upid: str, session: Session) -> bool:
    res = session.run("MATCH (p:Process {upid: $upid}) RETURN p", upid=upid)
    return len(list(res)) != 0


def get_uuid():
    return str(uuid.uuid4())


def handle_clone_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_clone_event: " + str(data))
        return
    # Decode the CBOR data
    event_data = CloneEventData(data)
    logger.info(f"Clone Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        pidProcessingState[event_data.pid] = ProcessingStep.CLONE
    else:
        logger.warning(
            f"Received clone event for pid {event_data.pid} which is already in state {pidProcessingState[event_data.pid]}\n\tPID reuse?"
        )
    # Check if the process's parent is already tracked (if ppid != 0 and
    # # ppid not in pidProcessingState, we might have missed the clone event
    # # of the parent, or the parent might have been created before the
    # # collector started)
    if (event_data.ppid != 0) and (event_data.ppid not in pidProcessingState):
        logger.info(
            f"Received clone event for pid {event_data.pid} with unknown parent ppid {event_data.ppid}"
        )
        logger.info(
            f"Creating placeholder for parent process with ppid {event_data.ppid}"
        )
        # TODO Actually create the placeholder in the DB
    # TODO Create the process node


def handle_execve_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_execve_event: " + str(data))
        return
    # Decode the CBOR data
    event_data = ExecveEventData(data)
    logger.info(f"Execve Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        logger.warning(
            f"Received execve event for pid {event_data.pid} which is not in pidProcessingState\n\tPID reuse? Missed clone event?"
        )
        # TODO Actually create the process in the DB, with a "placeholder" procname
        # # and procargs (e.g. procname="unknown", procargs=[])
        # FIXME The above will result in a crash, but it is quite unlikely to happen
        # # in practice, especially for the testing conditions of the PoC
    else:
        pidProcessingState[event_data.pid] = ProcessingStep.EXECVE

    # TODO Update the process node with the real procname and procargs
    # TODO Parse the cmdline and extract behaviours, and attach them to the process
    # # node according to the rules defined in the paper

    return


def handle_fd_rw_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_fd_rw_event: " + str(data))
        return
    # Decode the CBOR data
    event_data = FSEventData(data)
    logger.info(f"FD RW Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        logger.warning(
            f"Received fd_rw event for pid {event_data.pid} which is not in pidProcessingState\n\tPID reuse? Missed clone event?\n\tThis event will be ignored"
        )
        return

    # TODO Insert the event into the DB, using the MERGE operator.
    # # This allows the creation of the file node if it didn't previously exist
    # # # in the DB, and the linking to the process responsible for the event
    # # # if it did.

    return


def handle_data(data, session: Session):
    already_parsed_pids = set()  # Avoid asking Neo4J 10 times in a row
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_data: " + str(data))
    # Decode the CBOR data
    event_data = FSEventData(data)

    logger.info(
        f"Handling event {event_data.pid} {event_data.procname}-{event_data.type}->{event_data.name} :{event_data.procargs}"
    )

    # Check if the process is already tracked by this instance
    is_tracked = event_data.pid in already_parsed_pids
    # If it isn't, parse the command line and mark the process as tracked
    if not is_tracked:
        parsed_commandline = cl_parser.parse(
            parser.ParserRequest(event_data.procname, event_data.procargs)
        )
        already_parsed_pids.add(event_data.pid)

    # # First, check if the process's tracking state is cached
    # is_tracked = universal_process_identifier in already_parsed_upid
    # # If it isn't, check if it's already tracked in the database
    # if not is_tracked:
    #     is_tracked = is_process_already_tracked(universal_process_identifier, session)
    # # Only parse the commandline if it hasn't been done yet
    # if is_tracked:
    #     parsed_commandline = None
    #     # Add the process to the already_parsed_upid set, to speed up future checks
    #     already_parsed_upid.add(universal_process_identifier)
    # else:
    #     parsed_commandline = cl_parser.parse(
    #         parser.ParserRequest(event_data.procname, event_data.procargs)
    #     )
    # # logger.info(f"\tGot {parsed_commandline.elements}")


def handle_data_old(data, session: Session):
    already_parsed_upid = set()  # Avoid asking Neo4J 10 times in a row
    if isinstance(data, dict):
        # Decode the CBOR data
        event_data = FSEventData(data)
        query_queue.put(event_data)

        if query_queue.qsize() >= query_trigger or True:
            # Process the queue
            logger.info(f"Processing {query_queue.qsize()} events...")
            process_queue = []
            similar_queue = []  # Must make another queue that won't have behaviour data, or Neo4J is unhappy... There's got to be a better way to do this
            for i in range(query_trigger):
                try:
                    event_data = query_queue.get_nowait()
                    universal_process_identifier = get_process_identifier(
                        event_data.pid,
                        event_data.ppid,
                        event_data.procname,
                        event_data.procargs,
                    )
                    # First, check if the process's tracking state is cached
                    is_tracked = universal_process_identifier in already_parsed_upid
                    # If it isn't, check if it's already tracked in the database
                    if not is_tracked:
                        is_tracked = is_process_already_tracked(
                            universal_process_identifier, session
                        )
                    # Only parse the commandline if it hasn't been done yet
                    if is_tracked:
                        parsed_commandline = None
                        # Add the process to the already_parsed_upid set, to speed up future checks
                        already_parsed_upid.add(universal_process_identifier)
                    else:
                        parsed_commandline = cl_parser.parse(
                            parser.ParserRequest(
                                event_data.procname, event_data.procargs
                            )
                        )
                    # logger.info(f"\tGot {parsed_commandline.elements}")
                    logger.info(
                        f"Handling event {event_data.pid} {event_data.procname}-{event_data.type}->{event_data.name}"
                    )
                    # print(f"\t{event_data.procargs}")
                    # logger.info(f"Got UPID {universal_process_identifier} for {event_data.pid}->{event_data.procname}")
                    process_queue.append(
                        {
                            "pid": event_data.pid,
                            "ppid": event_data.ppid,
                            "upid": universal_process_identifier,
                            "type": event_data.type,
                            "name": event_data.name,
                            "username": event_data.username,
                            "procname": event_data.procname,
                            "procargs": event_data.procargs,
                        }
                    )
                    if parsed_commandline:
                        similar_queue.append(
                            {
                                "pid": event_data.pid,
                                "ppid": event_data.ppid,
                                "upid": universal_process_identifier,
                                "type": event_data.type,
                                "name": event_data.name,
                                "username": event_data.username,
                                "procname": event_data.procname,
                                "procargs": event_data.procargs,
                                "behaviours": parsed_commandline,
                            }
                        )
                except (
                    queue.Empty
                ):  # Turns out the queue is empty (thank you queue.qsize())
                    break

            # Let's batch process the data
            session.run(
                """
                UNWIND $events AS event
                MERGE (p:Process {pid: event.pid, upid: event.upid, ppid: event.ppid, username: event.username, procname: event.procname, procargs: event.procargs})
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
            behaviour_node_list = []  # Process -> Behaviour events
            argument_node_list = []  # Process -> Argument events
            behaviour_parent_child_list = []  # ParentBehaviour -> ChildBehaviour events
            behaviour_parent_argument_list = []  # ParentBehaviour -> Argument events

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
                            if (
                                isinstance(raw, dict)
                                and "type" in raw
                                and "value" in raw
                            ):
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
                                        behaviour_option_arg_map[(single, opt_name)] = (
                                            opt_arg
                                        )
                            else:
                                behaviour_option_map[behaviour].add(opt_name)
                                if opt_arg is not None:
                                    behaviour_option_arg_map[(behaviour, opt_name)] = (
                                        opt_arg
                                    )
                    elif child_behaviour["type"] == "Argument":
                        arguments.append(
                            {
                                "argument": child_behaviour["value"]["value"],
                                "type": child_behaviour["value"]["type"],
                            }
                        )

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
                inherent_behaviours = {
                    beh
                    for beh, opts in behaviour_option_map.items()
                    if "inherent" in opts
                }

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
                                behaviour_parent_argument_list.append(
                                    {
                                        **common,
                                        "parent_behaviour": beh,
                                        "parent_option": opt,
                                        **arg,
                                    }
                                )
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
                                behaviour_parent_argument_list.append(
                                    {
                                        **common,
                                        "parent_behaviour": beh,
                                        "parent_option": opt,
                                        **arg,
                                    }
                                )
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
                    evt["option"] = "inherent"
                    behaviour_node_list.append(evt)

                    # all other behaviour+option pairs become children of the inherent behaviour node
                    for beh in sorted(behaviour_option_map.keys()):
                        for opt in sorted(behaviour_option_map[beh]):
                            # skip the parent inherent pair itself
                            if beh == inherent and opt == "inherent":
                                continue
                            behaviour_parent_child_list.append(
                                {
                                    **common,
                                    "parent_behaviour": inherent,
                                    "parent_option": "inherent",
                                    "child_behaviour": beh,
                                    "child_option": opt,
                                }
                            )

                    # attach arguments as children of the inherent behaviour node
                    for arg in arguments:
                        behaviour_parent_argument_list.append(
                            {
                                **common,
                                "parent_behaviour": inherent,
                                "parent_option": "inherent",
                                **arg,
                            }
                        )
                    # attach option-level arguments: all option args become children of the inherent behaviour
                    for (beh, opt), arg in behaviour_option_arg_map.items():
                        behaviour_parent_argument_list.append(
                            {
                                **common,
                                "parent_behaviour": inherent,
                                "parent_option": "inherent",
                                **arg,
                            }
                        )

                queue_element["behaviours"].has_been_processed = True

            # Create/attach Behaviour nodes to Process
            if len(behaviour_node_list) != 0:
                session.run(
                    """
                    UNWIND $events AS event
                    MERGE (p:Process {pid: event.pid, upid: event.upid, ppid: event.ppid, username: event.username, procname: event.procname, procargs: event.procargs})
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
                    MERGE (p:Process {pid: event.pid, upid: event.upid, ppid: event.ppid, username: event.username, procname: event.procname, procargs: event.procargs})
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

    with driver.session(database="sysevents") as session:
        with open(file_path, "rb") as f:
            while True:
                try:
                    # Read a single CBOR object from the file
                    data = cbor2.load(f)
                    if data == 0x0A:
                        continue
                    if data[b"kind"] == b"fd_rw":
                        handle_fd_rw_event(data, session)
                    elif data[b"kind"] == b"clone":
                        handle_clone_event(data, session)
                    elif data[b"kind"] == b"execve":
                        handle_execve_event(data, session)
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
