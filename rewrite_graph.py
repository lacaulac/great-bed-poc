import os
from neo4j import GraphDatabase, Session

# Neo4j connection details
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j!!!")

# Cypher queries from wiprequests.md
deduplication_query = """
MATCH (n1: Behaviour)-[r1: EVENT]->(n2: File)<-[r2:EVENT]-(n1: Behaviour)
WHERE r1 <> r2
AND r1.type = r2.type
AND elementId(r1) < elementId(r2)
DETACH DELETE r2
RETURN n1, n2, r1, r2
"""

rule_a1_query = """
MATCH p=(n1)-[e1]->(neutral: Behaviour {type: "NEUTRAL"})-[e2]->(n2)
DETACH DELETE neutral
CREATE (n1)-[:CHILD_OF]->(n2)
"""

rule_a2_query = """
MATCH p=()-[]->(neutral: Behaviour {type: "NEUTRAL"})
DETACH DELETE neutral
"""

rule_a3_better_method_query = """
MATCH p=(sourceNode:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(targetNode:File)
MERGE (targetNode)-[:SOURCE]->(sourceNode)
DETACH DELETE bhv
"""

#Needs to be run until there are no more results
rule_a3_propagate_chains_query = """
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
MERGE (dst)-[newr:SOURCE]->(src)
return chain, newr
"""

rule_a3_propagate_read_operations_query = """
MATCH chain=(bhv:Behaviour)-[:EVENT {type: "read"}]->(int:File)-[:SOURCE]->(src:File)
MERGE (bhv)-[:EVENT {type: "read"}]->(src)
return chain
"""

rule_a3_delete_intermediary_nodes_query = """
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
DETACH DELETE int
"""

rule_a3_delete_file_nodes_query = """
MATCH chain=(bhv:Behaviour)-[:EVENT {type: "read"}]->(int:File)-[:SOURCE]->(src:File)
DETACH DELETE int
"""

rule_b1_b3_query = """
MATCH chain=(bhv:Behaviour)-[lnk]->(targetNode:Argument)
WHERE bhv.type <> "NET_CFG" AND targetNode.type in ["URL", "IPAddress", "RemotePath"]
MERGE (bhv)-[:CHILD_OF]->(:Behaviour {type: "NET_CFG"})-[:CHILD_OF]->(targetNode)
DETACH DELETE lnk
"""

rule_b4_b5_query = """
MATCH chain=(bhv:Behaviour)-[lnk]->(childBhv:Behaviour)
WHERE bhv.type in ["FILE_READ", "FILE_WRITE"]
AND childBhv.type = "NET_CFG"
SET bhv.type = "NET_COMS"
"""

rule_d1_create_virtual_files_query = """
MATCH (n1: Behaviour)-[r13: EVENT {type: "write"}]->(n3: File)<-[r23:EVENT {type: "read"}]-(n2: Behaviour), (n1: Behaviour)-[r14: EVENT {type: "write"}]->(n4: File)<-[r24:EVENT {type: "read"}]-(n2: Behaviour)
WHERE n3 <> n4
AND elementId(n3)<elementId(n4)
MERGE (n3)-[newr1:VIRTUALFILE]->(virtfile:File {name: "virtual:"+elementId(n3)+elementId(n4)})<-[newr2:VIRTUALFILE]-(n4)
return virtfile, n3, n4
"""

rule_d1_merge_virtual_files_query = """
MATCH (a:File)-[lnk1:VIRTUALFILE]->(virt1:File)<-[lnk2:VIRTUALFILE]-(b:File), (b)-[lnk3:VIRTUALFILE]->(virt2:File)<-[lnk4:VIRTUALFILE]-(c:File)
WHERE elementId(virt1) > elementId(virt2)
MERGE (c)-[lnknew:VIRTUALFILE]->(virt1)
DETACH DELETE virt2
"""

rule_d1_create_new_event_relations_query = """
MATCH (bhv: Behaviour)-[rel:EVENT]->(fl:File)-[rep:VIRTUALFILE]->(virt:File)
MERGE (bhv)-[newrel:EVENT]->(virt)
SET newrel=properties(rel)
DETACH DELETE rel
RETURN bhv, rel, fl, rep, virt, newrel
"""

transform_file_read_write_events_query = """
MATCH (b:Behaviour)-[evt:EVENT]->(f:File)
WHERE NOT b.type IN ["FILE_READ", "FILE_WRITE"]
MERGE (b)-[chld:CHILD_OF]->(b2:Behaviour {type:(CASE WHEN evt.type="read" THEN "FILE_READ" ELSE "FILE_WRITE" END)})-[evt2:EVENT {type: evt.type}]->(f)
DETACH DELETE evt
return b,chld,b2,evt2,f
"""

rule_c1_c4_query = """
MATCH chain=(elem2:Behaviour)<-[]-(elem1:Behaviour)-[]->(elem3:Behaviour)
WHERE elem2.type in ["NET_COMS", "CMD_EXEC"]
AND elem3.type in ["FILE_READ", "FILE_WRITE"]
AND NOT EXISTS ((elem2)-[]->(elem3))
AND elem2.type <> elem1.type
MERGE (elem2)-[newlink:CHILD_OF {confidence: 0.5}]->(elem3)
return chain
"""

rule_d2_create_redirection_edges_query = """
MATCH (n2:Behaviour)<-[e1:CHILD_OF]-(n1:Behaviour)-[e2:CHILD_OF]->(n3:Behaviour), (n3)-[edgetomove:EVENT]->(othernode)
WHERE n2 <> n3
AND n2.type = n3.type
AND n2.type <> "process"
AND elementId(n2)<elementId(n3)
MERGE (n2)-[newedge:EVENT]->(othernode)
SET newedge=properties(edgetomove)
DETACH DELETE edgetomove
return n2, newedge, othernode
"""

rule_d2_clean_up_query = """
MATCH (a:Behaviour)-[lnk1:EVENT]->(fm:File)<-[lnk2:EVENT]-(b:Behaviour),(a)<-[]-(c:Behaviour)-[]
->(b)
WHERE elementId(lnk1) > elementId(lnk2)
AND a.type = b.type
AND a <> b
DETACH DELETE b
"""

rule_e1_query = """
MATCH (n1:Behaviour {type:"CMD_EXEC"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_READ"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)-[:DATA]->(scriptExec:IOA {type:"Script Execution", confidence: confidence})-[:creator]->(n1)
"""

rule_e2_query = """
MATCH (n1:Behaviour {type:"NET_COMS"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_WRITE"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)<-[:DATA]-(scriptExec:IOA {type:"File Download", confidence: confidence})-[:creator]->(n1)
"""

rule_e3_query = """
MATCH (n1:Behaviour {type:"NET_COMS"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_READ"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)-[:DATA]->(scriptExec:IOA {type:"File Upload", confidence: confidence})-[:creator]->(n1)
"""

rule_e4_query = """
MATCH (n1:Behaviour {type:"SYS_INFO"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_WRITE"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)<-[:DATA]-(scriptExec:IOA {type:"Sys Recon", confidence: confidence})-[:creator]->(n1)
"""

rule_e5_query = """
MATCH (n1:Behaviour {type:"FS_INFO"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_WRITE"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)<-[:DATA]-(scriptExec:IOA {type:"FS Recon", confidence: confidence})-[:creator]->(n1)
"""

rule_e6_query = """
MATCH (n1:Behaviour {type:"NET_INFO"})-[ed:CHILD_OF]->(n2:Behaviour {type:"FILE_WRITE"})-[]->(n3:File)
WITH n1 as n1, n2 as n2, n3 as n3, ed as ed, CASE WHEN ed.confidence IS NULL THEN 1.0 ELSE ed.confidence END AS confidence
MERGE (n3)<-[:DATA]-(scriptExec:IOA {type:"Net Recon", confidence: confidence})-[:creator]->(n1)
"""

rule_e7_query = """
MATCH (n1:Process)-[ed:SOURCE]->(n2:File)
MERGE (n2)-[:DATA]->(scriptExec:IOA {type:"Process Execution", confidence: 1.0})-[:creator]->(n1)
"""

rule_e8_e9_query = """
MATCH (n1: File)-[e4:DATA]->(n2:IOA)-[e5:creator]->(n3:Behaviour)
where n2.type in ["Script Execution", "Process Execution"]
SET n2.type = "Generic Execution"
"""

# Function to execute Cypher queries
def execute_query(session: Session, query):
    result = session.run(query)
    result = result.values()
    return result

# Execute all queries in order
def rewrite_graph():
    queries_pt1 = [
        deduplication_query,
        rule_a1_query,
        rule_a2_query,
        rule_a3_better_method_query,
    ]
    query_until_no_more = rule_a3_propagate_chains_query
    queries_pt2 = [
        rule_a3_propagate_read_operations_query,
        rule_a3_delete_intermediary_nodes_query,
        rule_a3_delete_file_nodes_query,
        rule_b1_b3_query,
        rule_b4_b5_query,
        rule_d1_create_virtual_files_query,
        rule_d1_merge_virtual_files_query,
        rule_d1_create_new_event_relations_query,
        transform_file_read_write_events_query,
        rule_c1_c4_query,
        rule_d2_create_redirection_edges_query,
        rule_d2_clean_up_query,
        rule_e1_query,
        rule_e2_query,
        rule_e3_query,
        rule_e4_query,
        rule_e5_query,
        rule_e6_query,
        rule_e7_query,
        rule_e8_e9_query
    ]

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session(database="sysevents") as session:
        for query in queries_pt1:
            try:
                counters = execute_query(session, query)
                print(f"Query executed successfully: {query[:100]}...")
                print(f"Counters: {counters}")
            except Exception as e:
                print(f"Error executing query: {query[:100]}...")
                print(f"Error: {e}")
        should_keep_running = True
        while should_keep_running:
            try:
                counters = execute_query(session, query_until_no_more)
                should_keep_running = len(counters) > 0
            except Exception as e:
                print(f"Error: {e}")

        for query in queries_pt2:
            try:
                counters = execute_query(session, query)
                print(f"Query executed successfully: {query[:100]}...")
                print(f"Counters: {counters}")
            except Exception as e:
                print(f"Error executing query: {query[:100]}...")
                print(f"Error: {e}")

if __name__ == "__main__":
    rewrite_graph()
