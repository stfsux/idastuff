import os
import sys
import idaapi
import idautils
import idc
import imp

idashitness = imp.load_source ('*', 'C:\path\to\shitness\idashitness.py')
idashitness.print_func_args ('GetProcAddress', 2)
idashitness.print_func_args ('CreateFileW', 7)
idashitness.print_func_args ('CreateFileA', 7)
idashitness.print_func_args ('GetModuleHandleW', 1)
idashitness.print_func_args ('LoadLibraryW', 1)
idashitness.print_func_args ('DeviceIoControl', 8)
