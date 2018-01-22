from idautils import *
from idaapi import *
from idc import *
import os


path = GetIdbPath().rsplit('.')[0]

func_dir_path = path + '_functions'
if not os.path.isdir(func_dir_path):
    os.mkdir(func_dir_path)

f = open(os.path.join(func_dir_path, 'functions_list.txt'), 'w')

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        function_name = GetFunctionName(funcea)
        end_ea = FindFuncEnd(funcea)
        GenFuncGdl(os.path.join(func_dir_path, function_name), None, funcea, end_ea, CHART_GEN_GDL | CHART_PRINT_NAMES);
        f.write(function_name + '\n')
f.close()
Exit(0)

