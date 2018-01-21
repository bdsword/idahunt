from idaapi import *
from idc import *

def ida_fcn_filter(func_ea):
    if SegName(func_ea) not in ("extern", ".plt"):
        return True


def get_ida_symbols():
    symbols = []

    for f in filter(ida_fcn_filter, Functions()):
        func     = get_func(f)
        seg_name = SegName(f)

        fn_name = GetFunctionName(f)
        symbols.append(fn_name)

    return symbols

print("self-contained-functions: {}\n".format(get_ida_symbols()))

idc.Exit(0)
