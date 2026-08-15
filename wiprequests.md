# Implementation of rules in Cypher

## Newstuff

### Deduplication of events

Events (*i.e.*, read/write operations) from one given process to a given file must be deduplicated so as to simplify processing.

```python
MATCH (n1: Behaviour)-[r1: EVENT]->(n2: File)<-[r2:EVENT]-(n1: Behaviour)
WHERE r1 <> r2
AND r1.type = r2.type
AND elementId(r1) < elementId(r2)
DETACH DELETE r2
RETURN n1, n2, r1, r2
```

## Rules A

### Rule A1

```python
MATCH p=(n1)-[e1]->(neutral: Behaviour {type: "NEUTRAL"})-[e2]->(n2)
DETACH DELETE neutral
CREATE (n1)-[:CHILD_OFCHILD_OF]->(n2)
```

### Rule A2

```python
MATCH p=()-[]->(neutral: Behaviour {type: "NEUTRAL"})
DETACH DELETE neutral
```

### Rule A3

#### Better method


1. Create explicit data transmission chains and discard COPYs --- do __once__

```python
MATCH p=(sourceNode:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(targetNode:File)
MERGE (targetNode)-[:SOURCE]->(sourceNode)
DETACH DELETE bhv
```

Ensuite on propage les chaînes
TANT QUE CHANGEMENTS

2. Propagate the chains --- do __until no more changes are introduced__

```python
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
MERGE (dst)-[newr:SOURCE]->(src)
return chain, newr
```

3. Propagate the chain to read operations --- do __once__

```python
MATCH chain=(bhv:Behaviour)-[:EVENT {type: "read"}]->(int:File)-[:SOURCE]->(src:File)
MERGE (bhv)-[:EVENT {type: "read"}]->(src)
return chain
```

4. Delete intermediary nodes --- do __once__

```python
MATCH chain=(dst:File)-[:SOURCE]->(int:File)-[:SOURCE]->(src:File)
DETACH DELETE int
```

5. Delete file nodes that have been read *and* are sources --- do __once__

```python
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

```python
MATCH chain=(bhv:Behaviour)-[lnk]->(targetNode:Argument)
WHERE bhv.type <> "NET_CFG" AND targetNode.type in ["URL", "IPAddress", "RemotePath"]
MERGE (bhv)-[:CHILD_OF]->(:Behaviour {type: "NET_CFG"})-[:CHILD_OF]->(targetNode)
DETACH DELETE lnk
```

### Rules B4-B5

**WARNING : __UNTESTED__** since the development event sequence did not contain any event that would have qualified

```python
MATCH chain=(bhv:Behaviour)-[lnk]->(childBhv:Behaviour)
WHERE bhv.type in ["FILE_READ", "FILE_WRITE"]
AND childBhv.type = "NET_CFG"
SET bhv.type = "NET_COMS"
```

**The rule D1 shall be run before the transform C1-C4. Indeed, D1 does not disturb the execution of C1-C4, but will allow not rewriting D1 to handle FILE_READ and FILE_WRITE intermediary nodes. This is useful, since D1 never applies to anything that's not observed from system calls, whereas D2 does.**

## Rules D (surprise!)

### Rule D1

**This rule must be run after the B rule group, since it affects file read/write events and not FILE_WRITE and FILE_READ behaviours. Though unintentional at first, this actually should help performance a bit.**

1. Create virtual file nodes with a link to the original file nodes

*Note*: There is bug if there are more than 3 processes implicated? Currently fixed by running D1's sequence until nothing changes. This leaves a bunch of virtual files in its wake though.

```python
MATCH (n1: Behaviour)-[r13: EVENT {type: "write"}]->(n3: File)<-[r23:EVENT {type: "read"}]-(n2: Behaviour), (n1: Behaviour)-[r14: EVENT {type: "write"}]->(n4: File)<-[r24:EVENT {type: "read"}]-(n2: Behaviour)
WHERE n3 <> n4
AND elementId(n3)<elementId(n4)
MERGE (n3)-[newr1:VIRTUALFILE]->(virtfile:File {name: "virtual:"+elementId(n3)+elementId(n4)})<-[newr2:VIRTUALFILE]-(n4)
return virtfile, n3, n4
```

2. Merge virtual files together!

```python
MATCH (a:File)-[lnk1:VIRTUALFILE]->(virt1:File)<-[lnk2:VIRTUALFILE]-(b:File), (b)-[lnk3:VIRTUALFILE]->(virt2:File)<-[lnk4:VIRTUALFILE]-(c:File)
WHERE elementId(virt1) > elementId(virt2)
MERGE (c)-[lnknew:VIRTUALFILE]->(virt1)
DETACH DELETE virt2
```

3. Create new EVENT relations from the original programs to the newly created virtual files, then remove the old ones.

```python
MATCH (bhv: Behaviour)-[rel:EVENT]->(fl:File)-[rep:VIRTUALFILE]->(virt:File)
MERGE (bhv)-[newrel:EVENT]->(virt)
SET newrel=properties(rel)
DETACH DELETE rel
RETURN bhv, rel, fl, rep, virt, newrel
```

## Transform file read/write events into behaviour nodes

```python
MATCH (b:Behaviour)-[evt:EVENT]->(f:File)
WHERE NOT b.type IN ["FILE_READ", "FILE_WRITE"]
MERGE (b)-[chld:CHILD_OF]->(b2:Behaviour {type:(CASE WHEN evt.type="read" THEN "FILE_READ" ELSE "FILE_WRITE" END)})-[evt2:EVENT {type: evt.type}]->(f)
DETACH DELETE evt
return b,chld,b2,evt2,f
```

## Rules C

### Rules C1-C4

*Note*: This has been altered from the paper's specification to not apply if the parent (1. in the paper) is of the same type as (2). The alteration is made by adding the last comparison (`AND elem2.type <> elem1.type`)

```python
MATCH chain=(elem2:Behaviour)<-[]-(elem1:Behaviour)-[]->(elem3:Behaviour)
WHERE elem2.type in ["NET_COMS", "CMD_EXEC"]
AND elem3.type in ["FILE_READ", "FILE_WRITE"]
AND NOT EXISTS ((elem2)-[]->(elem3))
AND elem2.type <> elem1.type
MERGE (elem2)-[newlink:CHILD_OF {confidence: 0.5}]->(elem3)
return chain
```

## Rules D (part 2!)

### Rule D2



#  `\_(''/)_/`

MATCH p=(:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(:File) RETURN p;

MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) SET a.linkuuid=randomUUID(), b.linkuuid = a.linkuuid 


MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) MERGE (f:File {linkuuid: a.linkuuid})

MATCH p=(a:File)<-[:EVENT {type:"read"}]-(:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) return p


MATCH p=(a:File)<-[:EVENT {type:"read"}]-(bhv:Behaviour {type:"COPY"})-[:EVENT {type:"write"}]->(b:File) SET b.name=a.name, b.inode="composite", a.inode="composite" return p
