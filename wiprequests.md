# Implementation of rules in Cypher

## Rules A

### Rule A1

```
MATCH p=(n1)-[e1]->(neutral: Behaviour {type: "NEUTRAL"})-[e2]->(n2)
DETACH DELETE neutral
CREATE (n1)-[:CHILD_OFCHILD_OF]->(n2)
```

### Rule A2

```
MATCH p=()-[]->(neutral: Behaviour {type: "NEUTRAL"})
DETACH DELETE neutral
```

### Rule A3

#### Better method


1. Create explicit data transmission chains and discard COPYs --- do __once__

```
MATCH p=(sourceNode:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(targetNode:File)
MERGE (targetNode)-[:SOURCE]->(sourceNode)
DETACH DELETE bhv
```

Ensuite on propage les chaînes
TANT QUE CHANGEMENTS

2. Propagate the chains --- do __until no more changes are introduced__

```
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
MERGE (dst)-[newr:SOURCE]->(src)
return chain, newr
```

3. Propagate the chain to read operations --- do __once__

```
MATCH chain=(bhv:Behaviour)-[:EVENT {type: "read"}]->(int:File)-[:SOURCE]->(src:File)
MERGE (bhv)-[:EVENT {type: "read"}]->(src)
return chain
```

4. Delete intermediary nodes --- do __once__

```
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
DETACH DELETE int
```

5. Delete file nodes that have been read *and* are sources --- do __once__

```
MATCH chain=(bhv:Behaviour)-[:EVENT {type: "read"}]->(int:File)-[:SOURCE]->(src:File)
DETACH DELETE int
```

#### Old method

Faire ça jusqu'à plus de changement : 
MATCH (sourceNode:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(targetNode:File)
WITH targetNode, sourceNode, bhv
MATCH (targetNode)<-[r]-(x)
MERGE (sourceNode)<-[newRel:EVENT]-(x)
RETURN sourceNode

Puis ça jusqu'à plus de changement :
MATCH (sourceNode:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(targetNode:File)
WITH targetNode, sourceNode, bhv
MATCH (targetNode)<-[r]-(x)
MERGE (sourceNode)<-[newRel:EVENT]-(x)
DETACH DELETE bhv
RETURN sourceNode

## Rules B

### Rules B1-B3

```
MATCH chain=(bhv:Behaviour)-[lnk]->(targetNode:Argument)
WHERE bhv.type <> "NET_CFG" AND targetNode.type in ["URL", "IPAddress", "RemotePath"]
MERGE (bhv)-[:CHILD_OF]->(:Behaviour {type: "NET_CFG"})-[:CHILD_OF]->(targetNode)
DETACH DELETE lnk
```

### Rules B4-B5

**WARNING : __UNTESTED__** since the development event sequence did not contain any event that would have qualified

```
MATCH chain=(bhv:Behaviour)-[lnk]->(childBhv:Behaviour)
WHERE bhv.type in ["FILE_READ", "FILE_WRITE"]
AND childBhv.type = "NET_CFG"
SET bhv.type = "NET_COMS"
```

#  `\_(''/)_/`

MATCH p=(:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(:File) RETURN p;

MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) SET a.linkuuid=randomUUID(), b.linkuuid = a.linkuuid 


MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) MERGE (f:File {linkuuid: a.linkuuid})

MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) return p


MATCH p=(a:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) SET b.name=a.name, b.inode="composite", a.inode="composite" return p
