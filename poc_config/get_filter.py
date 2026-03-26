ignored_partial_process_name = ["keyboard_layout", "setxkbmap"]
ignored_partial_path = [
    "/dev/pts",
    "/.config/Neo4j Desktop/Application/relate-data/dbmss/",
    "/lib/x86_64-linux-gnu/",
]

filter = ""

for elem in ignored_partial_process_name:
    filter += f"and not (proc.name contains '{elem}') "

for elem in ignored_partial_path:
    filter += f"and not (fd.name contains '{elem}') "

filter = filter[4:]

print(filter)
