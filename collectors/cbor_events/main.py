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

import logging
import sys
from enum import Enum

import cbor2
import requests
from neo4j import Driver, GraphDatabase, Session

import parser

logger = logging.getLogger(__name__)


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        # level=logging.DEBUG,
        format="[GReAT-BeD][%(levelname)s] %(asctime)s - %(message)s",
    )


setup_logging()


URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "neo4j!!!")

PARSER_URL = "http://localhost:6880"
cl_parser = parser.Parser(PARSER_URL)


class ProcessingStep(Enum):
    CLONE = 1
    EXECVE = 2


# pid -> ProcessingStep. Allows us to avoid asking Neo4J to see
# # if the process has already been seen (to avoid processing multiple
# # execve, or detect the apparition of events related to a process
# # we do not know about!)
pidProcessingState = {}


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
        self.inode = raw_object[b"inode"]

    def __repr__(self):
        return f"FSEventData(pid={self.pid}, ppid={self.ppid}, type={self.type}, name={self.name}, username={self.username}, procname={self.procname}, procargs={self.procargs}, isfileapipe={self.isfileapipe}, inode={self.inode})"


class CloneEventData:
    def __init__(self, raw_object: dict):
        self.ppid = raw_object[b"ppid"]
        self.pid = raw_object[b"pid"]
        self.username = raw_object[b"username"].decode(encoding="utf-8")
        self.procname = raw_object[b"procname"].decode(encoding="utf-8")
        tmp_procargs = raw_object[b"procargs"]
        # Split the procargs into a list of arguments on NULL bytes
        self.procargs = [e.decode("utf-8") for e in tmp_procargs.split(b"\t")][1:]

    def __repr__(self):
        return f"CloneEventData(pid={self.pid}, ppid={self.ppid}, username={self.username}, procname={self.procname}, procargs={self.procargs})"


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


class Pipe2EventData:
    def __init__(self, raw_object: dict):
        self.pid = raw_object[b"pid"]
        self.inode = int(raw_object[b"ino"].decode(encoding="utf-8"))

    def __repr__(self):
        return f"Pipe2EventData(pid={self.pid}, inode={self.inode})"


def is_process_already_tracked(pid: int, session: Session) -> bool:
    res = session.run("MATCH (p:Process {pid: $pid}) RETURN p", pid=pid)
    return len(list(res)) != 0


def handle_clone_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_clone_event: " + str(data))
        return
    # Decode the CBOR data
    event_data = CloneEventData(data)
    logger.debug(f"Clone Event: {event_data}")
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
        if is_process_already_tracked(event_data.ppid, session):
            logger.debug(
                f"Received clone event for pid {event_data.pid} with parent ppid {event_data.ppid} which is already tracked in the DB, but not in pidProcessingState\n\tThis can happen if the parent process was created before the collector started, or if we missed the clone event of the parent process\n\tThe parent process will be added to pidProcessingState with state CLONE, but no placeholder will be created in the DB (as it already exists)"
            )
            pidProcessingState[event_data.ppid] = ProcessingStep.CLONE
        else:
            logger.debug(
                f"Received clone event for pid {event_data.pid} with unknown parent ppid {event_data.ppid}"
            )
            logger.debug(
                f"Creating placeholder for parent process with ppid {event_data.ppid}"
            )
            # Create the placeholder in the DB
            session.run(
                "CREATE (n:Behaviour:Process {procname: $procname, ppid: 0, pid: $pid, type: 'process', procargs: $procargs, username: 'unknown_user'}) SET n.root=elementId(n)",
                pid=event_data.ppid,
                procname=event_data.procname,
                procargs=event_data.procargs,
            )
            # Add the parent process to the pidProcessingState, to avoid creating multiple placeholders if we receive multiple events related to the parent process
            pidProcessingState[event_data.ppid] = ProcessingStep.CLONE
    # Create the process node
    session.run(
        """
        MATCH (a:Process {pid: $ppid})
        CREATE (a)-[:CHILD_OF]->
        (b:Process:Behaviour {pid: $pid, ppid: $ppid, procname: $procname, procargs: $procargs, username: $username, type: 'process'})
        SET b.root = elementId(b)
        """,
        ppid=event_data.ppid,
        pid=event_data.pid,
        procname=event_data.procname,
        procargs=event_data.procargs,
        username=event_data.username,
    )


def handle_execve_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_execve_event: " + str(data))
        return
    # Decode the CBOR data
    event_data = ExecveEventData(data)
    logger.debug(f"Execve Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        logger.debug(
            f"Received execve event for pid {event_data.pid} which is not in pidProcessingState\n\tPID reuse? Missed clone event?"
        )
        # FIXME Actually create the process in the DB, with a "placeholder" procname
        # # and procargs (e.g. procname="unknown", procargs=[])
        # Running without doing the above will result in a crash, but it is quite unlikely to happen
        # # in practice, especially for the testing conditions of the PoC
    else:
        pidProcessingState[event_data.pid] = ProcessingStep.EXECVE

    # Update the process node with the real procname and procargs
    res = session.run(
        """
        MATCH (n:Process {pid: $pid, ppid: $ppid})
        SET n.procargs = $procargs,
            n.username = $username,
            n.procname = $procname
        RETURN elementId(n) AS node_id""",
        pid=event_data.pid,
        ppid=event_data.ppid,
        procname=event_data.procname,
        procargs=event_data.procargs,
        username=event_data.username,
    )
    res_single = res.single()
    if res_single is None:
        logger.warning(
            f"Could not find process node for pid {event_data.pid} and ppid {event_data.ppid} to update with execve event data. This can happen if we missed the clone event of the process, or if the process was created before the collector started. The execve event will be ignored."
        )
        return
    node_id = res_single["node_id"]  # pyright: ignore[reportOptionalSubscript]
    logger.info(
        f"Updated process node with id {node_id} for pid {event_data.pid} with procname {event_data.procname} and procargs {event_data.procargs}"
    )

    # Parse the cmdline and extract behaviours
    parsed_cmdline = cl_parser.parse(
        parser.ParserRequest(program_name=event_data.procname, args=event_data.procargs)
    )
    if parsed_cmdline:
        subparts = parsed_cmdline.get_subparts()
        logger.info(f"Parsed command line for process {event_data.pid}: {subparts}")
        # TODO Attach them to the process node according to the rules defined in the paper
        # Note : Use the node_id property to know where to insert. Useful to move the root in the case of
        # # a single inherent behaviour.
        root_node_id = node_id

        inherent = subparts["inherent"]
        inherent_amount = len(inherent)
        option_behaviours = subparts["options"]
        arguments = subparts["arguments"]

        if inherent_amount == 1:
            # Insert the inherent behaviour as a node, link the process to it, and make it the new root
            inherent_behaviour = inherent[0]
            res = session.run(
                """MATCH (p:Process {pid: $pid, ppid: $ppid})
                    CREATE (p)-[e:CHILD_OF]->(b:Behaviour {type: $bhv})
                    SET p.root = elementId(b)
                    RETURN elementId(b) AS node_id""",
                pid=event_data.pid,
                ppid=event_data.ppid,
                bhv=inherent_behaviour,
            )
            res = res.single()
            if res is None:
                logger.error(
                    "Couldn't get the ID of the inherent behaviour we just created."
                )
                return
            root_node_id = res["node_id"]
        elif inherent_amount > 1:
            # Insert the inherent behaviours as nodes, link the process to all of them
            for bhv in inherent:
                session.run(
                    """MATCH (p:Process {pid: $pid, ppid: $ppid})
                        CREATE (p)-[e:CHILD_OF]->(b:Behaviour {type: $bhv})""",
                    pid=event_data.pid,
                    ppid=event_data.ppid,
                    bhv=bhv,
                )

        # Insert the behaviours
        for option in option_behaviours:
            # Create the behaviour node with a link from the root to it and get its ID post-creation
            # For every behaviour associated with the option
            for bhv in option["behaviours"]:
                bhv_res = session.run(
                    """
                    MATCH (root) WHERE elementId(root) = $root_id
                    CREATE (root)-[:CHILD_OF]->(b:Behaviour {type: $bhv, option: $option_name})
                    RETURN elementId(b) AS node_id
                    """,
                    root_id=root_node_id,
                    bhv=bhv,
                    option_name=option["name"],
                )
                bhv_res_single = bhv_res.single()
                if bhv_res_single is None:
                    logger.error(
                        "Couldn't get the ID of the behaviour we just created."
                    )
                    continue
                behaviour_node_id = bhv_res_single["node_id"]
                if "argument" in option:
                    # Insert the argument as a children of the behaviour node
                    session.run(
                        """
                        MATCH (b) WHERE elementId(b) = $bhv_id
                        CREATE (b)-[:CHILD_OF]->(a:Argument {type: $argtype, value: $argvalue})
                        """,
                        bhv_id=behaviour_node_id,
                        argtype=option["argument"]["type"],
                        argvalue=option["argument"]["value"],
                    )
        for argument in arguments:
            session.run(
                """
                MATCH (b) WHERE elementId(b) = $bhv_id
                CREATE (b)-[:CHILD_OF]->(a:Argument {type: $argtype, value: $argvalue})
                """,
                bhv_id=root_node_id,
                argtype=argument["type"],
                argvalue=argument["value"],
            )


def handle_fd_rw_event(data, session: Session):
    #
    #
    #
    # FIXME Il faut que ces événements soient ajoutés COMME ENFANT d'un comportement
    # # inhérent unique pour que les règles de réécriture de graphe fonctionnent correctement
    #
    #
    #
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_fd_rw_event: " + str(data))
        return
    # Decode the CBOR data
    try:
        event_data = FSEventData(data)
    except KeyError:
        logger.error("Missing expected keys in fd_rw event data: " + str(data))
        return
    logger.debug(f"FD RW Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        logger.debug(
            f"Received fd_rw event for pid {event_data.pid} which is not in pidProcessingState\n\tPID reuse? Missed clone event?\n\tThis event will be ignored"
        )
        return

    # Insert the event into the DB, using the MERGE operator.
    # # This allows the creation of the file node if it didn't previously exist
    # # # in the DB, and the linking to the process responsible for the event
    # # # if it did.
    session.run(
        """
        MATCH (proc:Process {pid: $pid, ppid: $ppid})
        MATCH (p) WHERE elementId(p) = proc.root
        MERGE (f:File {inode: $inode, name: $filename})
        CREATE (p)-[e:EVENT {type: $eventtype}]->(f)""",
        pid=event_data.pid,
        ppid=event_data.ppid,
        filename=event_data.name,
        inode=event_data.inode,
        eventtype=event_data.type,
    )


def handle_pipe2_event(data, session: Session):
    if not isinstance(data, dict):
        logger.error("Invalid data provided to handle_fd_rw_event: " + str(data))
        return

    # Decode the CBOR data
    event_data = Pipe2EventData(data)
    logger.debug(f"Pipe2 Event: {event_data}")
    if event_data.pid not in pidProcessingState:
        if is_process_already_tracked(event_data.pid, session):
            logger.debug(
                f"Received pipe2 event for pid {event_data.pid} which is already tracked in the DB, but not in pidProcessingState\n\tThis can happen if the process was created before the collector started, or if we missed the clone event of the process\n\tThe process will be added to pidProcessingState with state EXECVE, but no placeholder will be created in the DB (as it already exists)"
            )
            pidProcessingState[event_data.pid] = ProcessingStep.EXECVE
        else:
            logger.debug(
                f"Received pipe2 event for pid {event_data.pid} which is not in pidProcessingState\n\tPID reuse? Missed clone event?\n\tThis event will be ignored"
            )
            return
    session.run(
        """
        MATCH (p:Process {pid: $pid})
        MERGE (f:File {name: $name, inode: $inode})
        CREATE (p)-[e:CREATEPIPE]->(f)""",
        pid=event_data.pid,
        inode=event_data.inode,
        name=f"/?/pipe/{event_data.inode}",
    )


def main(file_path, driver: Driver):
    logger.info("Starting cbor-events collector")
    # try:
    received_events = {"fd_rw": 0, "clone": 0, "execve": 0, "pipe2": 0}
    with driver.session(database="sysevents") as session:
        session.run(
            "MATCH (n) DETACH DELETE n"
        )  # TODO Remove this line. This is for debug purposes
        with open(file_path, "rb") as f:
            while True:
                # Print the stats and overwrite the previous line
                print(
                    f"Received events: fd_rw={received_events['fd_rw']}, clone={received_events['clone']}, execve={received_events['execve']}, pipe2={received_events['pipe2']}",
                    end="\r",
                )
                try:
                    # Read a single CBOR object from the file
                    data = cbor2.load(f)
                    if data == 0x0A:
                        continue
                    if data[b"kind"] == b"fd_rw":
                        handle_fd_rw_event(data, session)
                        received_events["fd_rw"] += 1
                    elif data[b"kind"] == b"clone":
                        handle_clone_event(data, session)
                        received_events["clone"] += 1
                    elif data[b"kind"] == b"execve":
                        handle_execve_event(data, session)
                        received_events["execve"] += 1
                    elif data[b"kind"] == b"pipe2":
                        handle_pipe2_event(data, session)
                        received_events["pipe2"] += 1
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
    # if len(sys.argv) < 2:
    #     print("Usage: python main.py <input_fifo>")
    #     sys.exit(1)
    if len(sys.argv) < 2:
        logger.warning("No input file provided. Using stdin...")
        input_file = "/dev/stdin"
    else:
        input_file = sys.argv[1]
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        main(input_file, driver)
