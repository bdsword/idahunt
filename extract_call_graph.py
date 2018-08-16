import idc
import idaapi
import os
import datetime

cur = idc.MinEA()
end = idc.MaxEA()
# path = os.path.splitext(idc.GetIdbPath())[0] + '.gdl'
# idc.GenCallGdl(path, None, idc.CHART_GEN_GDL)
path = os.path.splitext(idc.GetIdbPath())[0] + '.dot'
idc.GenCallGdl(path, None, 0x2000) # 0x2000 -> CHART_GEN_DOT
idc.Message('Gdl file has been saved to {}\n'.format(path))
idc.Exit(0)

