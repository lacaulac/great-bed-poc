# Cypher reference (kinda) — please don't judge me too hard

## Creating a node on its own

Template: `CREATE (n:Label1:Label2 {astringproperty: "bash", anumberproperty: 0})`

Example: `CREATE (n:Behaviour:Process {procname: "bash", ppid: 0, pid: 1})`

## Creating a relationship between two existing nodes

Template: `MATCH (a:Label1:Label2 {property: "value"}), (b:Label2 {property: "value"}) CREATE (a)-[:RELATIONSHIP_LABEL]->(b)`

Example: `MATCH (a:Process:Behaviour {pid: 1}), (b: Process {ppid:1}) CREATE (a)-[:CHILD_OF]->(b)`

## Creating a new node with a relationship to an existing node

Template: `MATCH (a:Label1:Label2 {property: "value"}) CREATE (a)-[:RELATIONSHIP_LABEL]->(b:Label3:Label4 {astringproperty: "bash", anumberproperty: 0})`

Example: `MATCH (a:Process {pid: 1}) CREATE (a)-[:CHILD_OF]->(b:Process:Behaviour {procname: "bash", ppid: 1, pid: 10})`

## Update a few properties of a node, given a match

Template: `MATCH (n:Label1:Label2 {property1: "value", property2: 12}) SET n.astringproperty = "bash", n.anumberproperty = 0`

Example: `MATCH (n:Process {pid: 1, ppid: 0}) SET n.procargs = ["ls", "-l", "-a"], n.procname = "bash"`

# Application-specific

## Clearing every behaviour node of a process

Template: `MATCH (a:Label1:Label2 {property: "value"})-[r:CHILD_OF]->(b:Label3) DELETE r, b`

Example: `MATCH (a:Process {pid: 1})-[r:CHILD_OF]->(b:Behaviour) DELETE r, b`

## Just nuke it

`MATCH (n) DETACH DELETE n`
