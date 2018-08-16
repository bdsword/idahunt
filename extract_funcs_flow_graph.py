from idautils import *
from idaapi import *
from idc import *
import os
import datetime

print('start: ', datetime.datetime.now())
path = os.path.splitext(GetIdbPath())[0]
func_dir_path = path + '_functions'
if not os.path.isdir(func_dir_path):
    os.mkdir(func_dir_path)

f = open(os.path.join(func_dir_path, 'functions_list.txt'), 'w')

for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        function_name = GetFunctionName(funcea)
        end_ea = FindFuncEnd(funcea)
        f.write(function_name + '\n')
        GenFuncGdl(os.path.join(func_dir_path, function_name) + '.dot', None, funcea, end_ea, 0x2000 | CHART_PRINT_NAMES);
f.close()
print('end: ', datetime.datetime.now())
Exit(0)

