#!/bin/sh

idahunt.py --temp-cleanup --inputdir "Z:\Testbed\bomb" --analyze --filter "filters\automatic_arch.py -v" --scripts "Z:\Testbed\idahunt\list_used_library.py"
idahunt.py --temp-cleanup --inputdir "F:\GoogleCodeJam\2016_Extracted" --analyze --filter "filters\automatic_arch.py -v" --scripts "E:\idahunt\extract_funcs_flow_graph.py"
