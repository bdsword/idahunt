import idc
import idaapi
import os

cur = idc.MinEA()
end = idc.MaxEA()
path = os.path.splitext(idc.GetIdbPath())[0] + '.gdl'
if os.path.isfile(path):
    idc.Message('Gdl file is existed for {}'.format(path))
    idc.Exit(-1)
idc.GenCallGdl(path, None, idc.CHART_GEN_GDL)
idc.Message('Gdl file has been saved to {}\n'.format(path))
idc.Exit(0)

