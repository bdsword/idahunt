from idautils import *
from idaapi import *
from idc import *
import os
import networkx as nx


external_symbol_fillcolor = '#ff00ff'

path = os.path.splitext(GetIdbPath())[0]

# Get call graph dot file path
dot_path = path + '.dot'
if not os.path.isfile(dot_path):
    print('Cannot find dot file for {}.'.format(os.path.splitext(GetIdbPath())[0] + '.run'))
    Exit(-1)

internal_functions = []
graph = nx.drawing.nx_pydot.read_dot(dot_path)

for node_name in graph.nodes:
    fillcolor = re.findall(r'"(.*)"', graph.nodes[node_name]['fillcolor'])[0]
    function_name = graph.nodes[node_name]['label']
    if fillcolor != external_symbol_fillcolor:
        function_name = re.findall(r'"(.*)\\+l"', function_name)[0]
        internal_functions.append(function_name)

func_dir_path = path + '_functions'
if not os.path.isdir(func_dir_path):
    os.mkdir(func_dir_path)

f = open(os.path.join(func_dir_path, 'functions_list.txt'), 'w')

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        function_name = GetFunctionName(funcea)
        end_ea = FindFuncEnd(funcea)
        f.write(function_name + '\n')
        if function_name in internal_functions:
            GenFuncGdl(os.path.join(func_dir_path, function_name) + '.gdl', None, funcea, end_ea, CHART_GEN_GDL | CHART_PRINT_NAMES);
        else:
            Message('Skipping {} because it is not a internal function.'.format(function_name))
f.close()
Exit(0)

