#!/usr/bin/env python3

import argparse
import collections
import functools
import networkx as nx


class memoize:
    # From https://github.com/S2E/s2e-env/blob/master/s2e_env/utils/memoize.py

    def __init__(self, func):
        self._func = func
        self._cache = {}

    def __call__(self, *args):
        if not isinstance(args, collections.abc.Hashable):
            return self._func(args)

        if args in self._cache:
            return self._cache[args]

        value = self._func(*args)
        self._cache[args] = value
        return value

    def __repr__(self):
        # Return the function's docstring
        return self._func.__doc__

    def __get__(self, obj, objtype):
        # Support instance methods
        return functools.partial(self.__call__, obj)


#################################
# Get graph node name
#################################
def node_name(name):
    return name  # 노드 이름 그대로 반환


#################################
# Find the graph node for a name
#################################
@memoize
def find_nodes(name):
    return [n for n in G.nodes() if name == n]


##################################
# Calculate Distance
##################################
def distance(name):
    distance = -1
    for n in find_nodes(name):
        d = 0.0
        i = 0
        for t in targets:
            try:
                shortest = nx.dijkstra_path_length(G, n, t)
                d += 1.0 / (1.0 + shortest)
                i += 1
            except nx.NetworkXNoPath:
                pass

        if d != 0 and (distance == -1 or distance > i / d):
            distance = i / d

    if distance != -1:
        out.write(name)
        out.write(",")
        out.write(str(distance))
        out.write("\n")


##################################
# Main function
##################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dot', type=str, required=True, help="Path to dot-file representing the call graph.")
    parser.add_argument('-t', '--targets', type=str, required=True, help="Target function name.")
    parser.add_argument('-o', '--out', type=str, required=True, help="Path to output file containing distance for each function.")

    args = parser.parse_args()

    print("\nParsing %s ..." % args.dot)
    G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(args.dot))
    print("Graph loaded with %d nodes and %d edges." % (G.number_of_nodes(), G.number_of_edges()))

    # 노드 이름 추출
    node_names = list(G.nodes())
    with open('names.txt', 'w') as file:
        for name in node_names:
            file.write(name + '\n')
            
    # 타겟 함수 설정
    target_function = args.targets.strip()
    targets = find_nodes(target_function)
    if not targets:
        print("Target function '%s' not found in the graph." % target_function)
        exit(1)

    print("Calculating distances...")
    with open(args.out, "w") as out:
        for func_name in node_names:
            if func_name:
                distance(func_name)

    print("Distance calculation completed. Results saved to %s." % args.out)
