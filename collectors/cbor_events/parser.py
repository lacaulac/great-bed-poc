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

from requests import Session
import json

class ParsedCommandLine:
    def __init__(self, parser_output):
        self.parser_output = parser_output
        self.elements = list()
        for parsed_element in parser_output:
            if len(parsed_element.keys()) != 1:
                raise ValueError("[ParsedCommandLine] Invalid parser output: root elements should have only one key (the element type)")
            elem_type = list(parsed_element.keys())[0]
            value = parsed_element[elem_type]
            if elem_type == "CLBehaviouredOption":
                data = value
                value = dict()
                name = data[0]
                behaviours = data[1]
                argument = data[2]
                value["name"] = name
                value["behaviours"] = behaviours
                if argument != None:
                    value["argument"] = argument
                elem_type = "Option"
            if elem_type == "CLArgument":
                data = value
                value = dict()
                value["type"] = list(data.keys())[0]
                value["value"] = data[value["type"]]
                elem_type = "Argument"
            self.elements.append({
                "type": elem_type,
                "value": value
            })
        self.from_cache = False
        self.has_been_processed = False


class ParserCache:
    #TODO Implement a mechanism to limit the size of the cache (like an eviction policy based on a hit-counter or age-counter/insertion order)
    def __init__(self):
        self.cache = {}

    def has(self, key):
        return key in self.cache

    def get(self, key) -> ParsedCommandLine | None:
        return None #Automatic cache miss
        # In the current state of the cache, if the same command is executed twice, only the first instance will have graph nodes for Behaviour and Arguments. We should not use the cache to determine whether or not to add the nodes to the graph
        if key in self.cache:
            return self.cache[key]
        return None

    def set(self, key, value):
        self.cache[key] = value

class ParserRequest:
    def __init__(self, program_name: str, args: list[str]):
        self.program_name = program_name
        self.args = args

    def _get_dict(self):
        return {"program": self.program_name, "args": self.args}

    def _into_key(self):
        return self.program_name + "::".join(self.args)

class Parser:
    """A link to the CLI & behaviours parser"""
    def __init__(self, url):
        self.session = Session()
        self.url = url
        self.cache = ParserCache()

    def parse(self, data: ParserRequest) -> ParsedCommandLine:
        """Parse the given CLI data and return the parsed CLI with behavioural information"""
        cache_key = data._into_key()
        cached_result = self.cache.get(cache_key)
        if cached_result:
            self.from_cache = True
            return cached_result
        response = self.session.post(self.url + "/behaviours", headers={"Content-Type": "application/json"}, data=json.dumps(data._get_dict()))
        response.raise_for_status()
        result = ParsedCommandLine(response.json())
        self.cache.set(cache_key, result)
        return result

    def close(self):
        self.session.close()

if __name__ == "__main__":
    parser = Parser("http://localhost:6880")
    request = ParserRequest("tar", ["-x", "--file", "archive.tar", "-v", "/tmp/hello.txt"])
    result = parser.parse(request)
    print(result.elements)
    parser.close()
