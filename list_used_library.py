import idaapi
import idc


target = idc.GetIdbPath().rsplit('.')[0]
target_log = target + '.import.txt'
target_log_f = open(target_log, 'w')

def imp_cb(ea, name, ord):
    if not name:
        target_log_f.write("|---- unknown function at {:08x}\n".format(ea))
    else:
        target_log_f.write("|---- {}\n".format(name))
    # True -> Continue enumeration
    # False -> Stop enumeration
    return True


nimps = idaapi.get_import_module_qty()

# print("Found {} import(s)...".format(nimps))


target_log_f.write(target + '\n')

for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print("Failed to get import module name for #{}".format(i))
        continue
    target_log_f.write('|-- {}\n'.format(name))
    
    # print("Walking-> {}".format(name))
    idaapi.enum_import_names(i, imp_cb)
target_log_f.close()

idc.Exit(0)
