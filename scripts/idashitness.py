import os
import sys
import idaapi
import idautils
import idc

def get_next_insn_ea (ea, n):
  current_ea = ea
  for m in range(0, n):
    current_ea = idaapi.get_item_end (current_ea)
  return current_ea

def get_prev_insn_ea (ea, n):
  current_ea = ea
  for m in range (0, n):
    current_ea = idaapi.get_item_head (current_ea-1)
  return current_ea

def get_func_arg_ea (ea, arg_n, MAXDEPTH=50):
  curr_arg_n = 0
  current_ea = 0 
  for n in range (1, MAXDEPTH):
    current_ea = get_prev_insn_ea (ea, n)
    insn_name = idc.GetMnem (current_ea)
    if insn_name.lower() == "push":
      if curr_arg_n == arg_n:
        return current_ea
      curr_arg_n = curr_arg_n + 1
  return 0xFFFFFFFF

def print_func_args (symname, narg, OS="win", MAXDEPTH=50):
  args = list()
  sym_ea = idaapi.get_name_ea (idaapi.NT_NONE, symname)
  str_type = idaapi.ASCSTR_TERMCHR
  if OS == "win":
    if symname[-1] == "W":
      str_type = idaapi.ASCSTR_UNICODE
  refs = idautils.CodeRefsTo (sym_ea, 0)
  for r in refs:
    sys.stdout.write ('0x%08X %s (' % (r, symname))
    for m in range(0, narg):
      current_ea = get_func_arg_ea (r, m)
      if current_ea == 0xFFFFFFFF:
        break
      op_type = idc.GetOpType (current_ea, 0)
      if op_type == idc.o_imm: 
        str_arg = idc.GetString (idc.GetOperandValue (current_ea, 0), strtype = str_type)
        if str_arg != None:
          sys.stdout.write ('(char*)(0x%08X)\"%s\"' % (idc.GetOperandValue (current_ea, 0), str_arg))
        else:
          sys.stdout.write ('0x%08X' % idc.GetOperandValue (current_ea, 0))
      else:
        sys.stdout.write ('%s' % idc.GetOpnd (current_ea, 0))
      if (m+1) != narg:
        sys.stdout.write (', ')
    sys.stdout.write (');\n')

