# PySide, ida 6.6
# movfuscator (04/02/16)
#  identified routines:
#    - arithmetic: add, sub, div, mod, mul.
#    - logic: xor, or, and
#    - branch: jmp_gti, jmp_gtu, jmp_lei, jmp_leu,
#              jmp_lti, jmp_gei, jmp_neu, jmp_geu,
#              jmp_equ, jmp_ltu, jmp_jumpv, call external
#    - transfer: mov Rx, select_data
#    - stack variables
#    - export as txt
#    - customizable hl color
#  todo:
#    - transfer: store_data
#    - parameters and local routines
#  tofix:
#    - stack variables which are not aligned use alu_add() routine
#      instead of successive push/pop. Same shit if the stack variables
#      are located at +/-STACK_EX_THRESH.
import idaapi
import idautils
from PySide import QtGui, QtCore

align = 16

mofo_data_start = 0x0
mofo_code_start = 0x0
mofo_code_end   = 0x0

MDAL_SIZE_BYTE  = 1
MDAL_SIZE_WORD  = 2
MDAL_SIZE_DWORD = 4

# config
STACK_SIZE      = 0x200000
SOFT_I_REGS     = 4
SOFT_F_REGS     = 2
SOFT_D_REGS     = 2
MOV_FLOW        = 1
MOV_OFFSET      = 0x80000000
STACK_EX_THRESH = 128*4
MOFO_HL_BKGD    = 0xFF0000

mofo_funcs      = dict()
mofo_data       = list()

REL_CURR = 0
REL_PREV = 1
REL_NEXT = 2

OP_UNKN   = 0
OP_VAL    = 1
OP_REG    = 2
OP_STR    = 3
OP_XREF   = 4

OP_UNKN   = 0
OP_SRC    = 1
OP_DST    = 2

xref_code_sign = [
  [
    'alu_idiv',
    'alu_n',
    [
      [REL_NEXT, 1, OP_XREF, 0, 'alu_d'],
      [REL_NEXT, 2, OP_REG, 0, 'eax'],
      [REL_NEXT, 2, OP_VAL, 1, 0],
      [REL_NEXT, 4, OP_XREF, 1, 'alu_b7'],
      [REL_NEXT, 5, OP_XREF, 0, 'alu_ns'],
      [REL_NEXT, 5, OP_REG, 1, 'eax'],
      [REL_NEXT, 10, OP_VAL, 1, 0],
      [REL_NEXT, 10, OP_REG, 0, 'eax'],
      [REL_NEXT, 11, OP_VAL, 1, 0],
      [REL_NEXT, 11, OP_REG, 0, 'eax'],
    ],
    [
      [REL_CURR, 0, 1, OP_SRC],
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 3826, 0, OP_DST]
    ],
    0,
    3832
  ],
  [
    'alu_imod',
    'alu_n',
    [
      [REL_NEXT, 1, OP_XREF, 0, 'alu_d'],
      [REL_NEXT, 2, OP_REG, 0, 'eax'],
      [REL_NEXT, 2, OP_VAL, 1, 0],
      [REL_NEXT, 4, OP_XREF, 1, 'alu_b7'],
      [REL_NEXT, 5, OP_XREF, 0, 'alu_ns'],
      [REL_NEXT, 5, OP_REG, 1, 'eax'],
      [REL_NEXT, 10, OP_XREF, 1, 'alu_ns'],
      [REL_NEXT, 10, OP_REG, 0, 'eax'],
      [REL_NEXT, 11, OP_XREF, 0, 'alu_rs'],
      [REL_NEXT, 11, OP_REG, 1, 'eax'],
    ],
    [
      [REL_CURR, 0, 1, OP_SRC],
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 3826, 0, OP_DST]
    ],
    0,
    3827
  ],
  [
    'alu_udiv',
    'alu_q',
    [
      [REL_CURR, 0, OP_XREF, 0, 'alu_q'],
      [REL_CURR, 0, OP_VAL,  1, 0],
      [REL_NEXT, 1, OP_XREF, 0, 'alu_r'],
      [REL_NEXT, 1, OP_VAL, 1, 0],
      [REL_PREV, 1, OP_XREF, 0, 'alu_d'],
      [REL_PREV, 2, OP_XREF, 0, 'alu_n'],
      [REL_NEXT, 3714, OP_XREF, 1, 'alu_q'],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC],
      [REL_PREV, 2, 1, OP_SRC],
      [REL_NEXT, 3714, 0, OP_DST],
    ],
    2,
    3715
  ],
  [
    'alu_umod',
    'alu_q',
    [
      [REL_CURR, 0, OP_XREF, 0, 'alu_q'],
      [REL_CURR, 0, OP_VAL,  1, 0],
      [REL_NEXT, 1, OP_XREF, 0, 'alu_r'],
      [REL_NEXT, 1, OP_VAL, 1, 0],
      [REL_PREV, 1, OP_XREF, 0, 'alu_d'],
      [REL_PREV, 2, OP_XREF, 0, 'alu_n'],
      [REL_NEXT, 3714, OP_XREF, 1, 'alu_r'],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC],
      [REL_PREV, 2, 1, OP_SRC],
      [REL_NEXT, 3714, 0, OP_DST],
    ],
    2,
    3715
  ],
  [
    'alu_mul',
    'alu_mul_mul8l',
    [
      [REL_PREV, 13, OP_XREF, 0, 'alu_x'],
      [REL_PREV, 12, OP_XREF, 0, 'alu_y'],
    ],
    [
      [REL_PREV, 13, 1, OP_SRC],
      [REL_PREV, 12, 1, OP_SRC],
      [REL_NEXT, 248, 0, OP_DST]
    ],
    13,
    249
  ],
  [
    'jmp_gti',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 61, OP_XREF, 1, 'alu_false'],
      [REL_NEXT, 62, OP_XREF, 0, 'b0'],
      [REL_NEXT, 63, OP_XREF, 1, 'mofo_sf'],
      [REL_NEXT, 64, OP_XREF, 1, 'mofo_of'],
      [REL_NEXT, 65, OP_XREF, 1, 'xnor0'],
      [REL_NEXT, 67, OP_XREF, 0, 'b1'],
      [REL_NEXT, 68, OP_XREF, 1, 'b0'],
      [REL_NEXT, 69, OP_XREF, 1, 'b1'],
      [REL_NEXT, 70, OP_XREF, 1, 'and0'],
      [REL_NEXT, 72, OP_XREF, 0, 'b0'],
      [REL_NEXT, 73, OP_XREF, 1, 'b0'],
      [REL_NEXT, 74, OP_XREF, 1, 'on'],
      [REL_NEXT, 75, OP_XREF, 1, 'and0'],
      [REL_NEXT, 77, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    112
  ],
  [
    'jmp_gtu',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_cf'],
      [REL_NEXT, 61, OP_XREF, 1, 'alu_false'],
      [REL_NEXT, 62, OP_XREF, 0, 'b0'],
      [REL_NEXT, 63, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 64, OP_XREF, 1, 'alu_false'],
      [REL_NEXT, 65, OP_XREF, 0, 'b1'],
      [REL_NEXT, 66, OP_XREF, 1, 'b0'],
      [REL_NEXT, 67, OP_XREF, 1, 'b1'],
      [REL_NEXT, 68, OP_XREF, 1, 'and0'],
      [REL_NEXT, 70, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    110
  ],
  [
    'jmp_lei',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_sf'],
      [REL_NEXT, 61, OP_XREF, 1, 'mofo_of'],
      [REL_NEXT, 62, OP_XREF, 1, 'xor0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
      [REL_NEXT, 65, OP_XREF, 1, 'b0'],
      [REL_NEXT, 66, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 67, OP_XREF, 1, 'or0'],
      [REL_NEXT, 69, OP_XREF, 0, 'b0'],
      [REL_NEXT, 70, OP_XREF, 1, 'b0'],
      [REL_NEXT, 71, OP_XREF, 1, 'on'],
      [REL_NEXT, 72, OP_XREF, 1, 'and0'],
      [REL_NEXT, 74, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    109
  ],
  [
    'jmp_leu',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_cf'],
      [REL_NEXT, 61, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 62, OP_XREF, 1, 'or0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
      [REL_NEXT, 65, OP_XREF, 1, 'b0'],
      [REL_NEXT, 66, OP_XREF, 1, 'on'],
      [REL_NEXT, 67, OP_XREF, 1, 'and0'],
      [REL_NEXT, 69, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    104
  ],
  [
    'jmp_lti',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_sf'],
      [REL_NEXT, 61, OP_XREF, 1, 'mofo_of'],
      [REL_NEXT, 62, OP_XREF, 1, 'xor0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
      [REL_NEXT, 65, OP_XREF, 1, 'b0'],
      [REL_NEXT, 66, OP_XREF, 1, 'on'],
      [REL_NEXT, 67, OP_XREF, 1, 'and0'],
      [REL_NEXT, 69, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    104
  ],
  [
    'jmp_gei',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_sf'],
      [REL_NEXT, 61, OP_XREF, 1, 'mofo_of'],
      [REL_NEXT, 62, OP_XREF, 1, 'xnor0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    104
  ],
  [
    'jmp_neu',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 61, OP_XREF, 1, 'alu_false'],
      [REL_NEXT, 62, OP_XREF, 0, 'b0'],
      [REL_NEXT, 63, OP_XREF, 1, 'b0'],
      [REL_NEXT, 64, OP_XREF, 1, 'on'],
      [REL_NEXT, 65, OP_XREF, 1, 'and0'],
      [REL_NEXT, 67, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    102
  ],
  [
    'jmp_geu',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_cf'],
      [REL_NEXT, 61, OP_XREF, 1, 'alu_false'],
      [REL_NEXT, 62, OP_XREF, 0, 'b0'],
      [REL_NEXT, 63, OP_XREF, 1, 'b0'],
      [REL_NEXT, 64, OP_XREF, 1, 'on'],
      [REL_NEXT, 65, OP_XREF, 1, 'and0'],
      [REL_NEXT, 67, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    102
  ],
  [
    'jmp_equ',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_zf'],
      [REL_NEXT, 61, OP_XREF, 1, 'on'],
      [REL_NEXT, 62, OP_XREF, 1, 'and0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    100
  ],
  [
    'jmp_ltu',
    'branch_temp',
    [
      [REL_NEXT, 60, OP_XREF, 1, 'mofo_cf'],
      [REL_NEXT, 61, OP_XREF, 1, 'on'],
      [REL_NEXT, 62, OP_XREF, 1, 'and0'],
      [REL_NEXT, 64, OP_XREF, 0, 'b0'],
    ],
    [
      [REL_NEXT, 1, 1, OP_SRC],
      [REL_NEXT, 2, 1, OP_SRC],
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    99
  ],
  [
    'alu_cmp',
    'alu_true',
    [
      [REL_NEXT, 2, OP_XREF, 1, 'alu_true'],
      [REL_NEXT, 4, OP_XREF, 1, 'alu_true'],
      [REL_NEXT, 6, OP_XREF, 1, 'alu_true'],
    ],
    [
      [REL_PREV, 38, 1, OP_SRC],
      [REL_PREV, 37, 1, OP_SRC],
    ],
    38,
    21
  ],
  [
    'jmp_jumpv',
    'branch_temp',
    [
      [REL_NEXT, 1, OP_XREF, 1, 'on'],
    ],
    [
      [REL_CURR, 0, 1, OP_SRC],
    ],
    0,
    35
  ],
  [
    'alu_eq',
    'alu_eq',
    [
      [REL_NEXT, 5, OP_XREF, 1, 'alu_eq'],
      [REL_NEXT, 10, OP_XREF, 1, 'alu_eq'],
      [REL_NEXT, 15, OP_XREF, 1, 'alu_eq'],
      [REL_NEXT, 19, OP_XREF, 1, 'b0'],
      [REL_NEXT, 20, OP_XREF, 1, 'b1'],
      [REL_NEXT, 21, OP_XREF, 1, 'and0'],
      [REL_NEXT, 23, OP_XREF, 0, 'b0'],
      [REL_NEXT, 24, OP_XREF, 1, 'b0'],
      [REL_NEXT, 25, OP_XREF, 1, 'b2'],
      [REL_NEXT, 26, OP_XREF, 1, 'and0'],
      [REL_NEXT, 28, OP_XREF, 0, 'b0'],
      [REL_NEXT, 29, OP_XREF, 1, 'b0'],
      [REL_NEXT, 30, OP_XREF, 1, 'b3'],
      [REL_NEXT, 31, OP_XREF, 1, 'and0'],
      [REL_NEXT, 33, OP_XREF, 0, 'b0']
    ],
    [
      [REL_PREV, 6, 1, OP_SRC],
      [REL_PREV, 5, 1, OP_SRC],
    ],
    6,
    76
  ],
  [
    'alu_bxor',
    'alu_bxor8',
    [
      [REL_PREV, 6, OP_XREF, 0, 'alu_x'],
      [REL_PREV, 5, OP_XREF, 0, 'alu_y'],
      [REL_PREV, 2, OP_XREF, 1, 'alu_x'],
      [REL_PREV, 1, OP_XREF, 1, 'alu_y'],
    ],
    [
      [REL_PREV, 6, 1, OP_SRC],
      [REL_PREV, 5, 1, OP_SRC],
      [REL_NEXT, 24, 0, OP_DST]
    ],
    6,
    25
  ],
  [
    'alu_bor',
    'alu_bor8',
    [
      [REL_PREV, 4, OP_VAL, 1, 0],
      [REL_PREV, 3, OP_VAL, 1, 0],
      [REL_PREV, 4, OP_REG, 0, 'eax'],
      [REL_PREV, 4, OP_REG, 0, 'edx'],
      [REL_PREV, 6, OP_XREF, 0, 'alu_x'],
      [REL_PREV, 5, OP_XREF, 0, 'alu_y'],
    ],
    [
      [REL_PREV, 6, 1, OP_SRC],
      [REL_PREV, 5, 1, OP_SRC],
      [REL_NEXT, 25, 0, OP_DST]
    ],
    6,
    25,
  ],
  [
    'alu_band',
    'alu_band8',
    [
      [REL_PREV, 4, OP_VAL, 1, 0],
      [REL_PREV, 3, OP_VAL, 1, 0],
      [REL_PREV, 4, OP_REG, 0, 'eax'],
      [REL_PREV, 4, OP_REG, 0, 'edx'],
      [REL_PREV, 6, OP_XREF, 0, 'alu_x'],
      [REL_PREV, 5, OP_XREF, 0, 'alu_y'],
    ],
    [
      [REL_PREV, 6, 1, OP_SRC],
      [REL_PREV, 5, 1, OP_SRC],
      [REL_NEXT, 25, 0, OP_DST]
    ],
    6,
    25,
  ],
  [
    'alu_add',
    'alu_add16',
    [
      [REL_PREV, 1, OP_XREF, 1, 'alu_y'],
      [REL_PREV, 2, OP_XREF, 1, 'alu_x'],
    ],
    [
      [REL_PREV,  7, 1, OP_SRC],
      [REL_PREV,  6, 1, OP_SRC],
      [REL_NEXT, 16, 0, OP_DST],
    ],
    7,
    17
  ],
  [
    'alu_sub',
    'alu_inv16',
    [
      [REL_NEXT, 1, OP_XREF, 1, 'alu_add16'],
      [REL_PREV, 1, OP_XREF, 1, 'alu_y'],
      [REL_PREV, 2, OP_XREF, 1, 'alu_x'],
    ],
    [
      [REL_PREV, 7, 1, OP_SRC],
      [REL_PREV, 6, 1, OP_SRC],
      [REL_NEXT, 18, 0, OP_DST],
    ],
    7,
    19
  ],
  [
    'push',
    'stack_temp',
    [
      [REL_CURR, 0, OP_REG,  1, 'eax'],
      [REL_NEXT, 1, OP_REG,  0, 'eax'],
      [REL_NEXT, 1, OP_XREF, 1, 'stack_ptr'],
      [REL_NEXT, 2, OP_REG,  0, 'edx'],
      [REL_NEXT, 2, OP_XREF, 1, 'on'],
      [REL_NEXT, 5, OP_REG,  0, 'edx'],
      [REL_NEXT, 5, OP_XREF, 1, 'stack_ptr'],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC],
    ],
    1,
    14,
  ],
  [
    'movsx16',
    'alu_sex8',
    [
      [REL_PREV, 1, OP_REG, 0, 'al'],
      [REL_PREV, 1, OP_REG, 1, 'dh'],
      [REL_PREV, 2, OP_REG, 0, 'eax'],
      [REL_PREV, 2, OP_VAL, 1, 0]
    ],
    [
      [REL_PREV, 3, 1, OP_SRC],
      [REL_NEXT, 2, 0, OP_DST]
    ],
    2,
    1,
  ],
  [
    'movsx8',
    'alu_sex8',
    [
      [REL_PREV, 2, OP_REG, 0, 'edx'],
      [REL_PREV, 2, OP_VAL, 1, 0],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC],
      [REL_NEXT, 1, 0, OP_DST]
    ],
    2,
    1,
  ],

  [
    'select_data',
    'data_p',
    [
      [REL_NEXT, 1, OP_XREF, 1, 'sel_data']
    ],
    [
      [REL_CURR, 0, 1, OP_SRC]
    ],
    0,
    2
  ],
  [
    'execution_off',
    'sel_on',
    [
      [REL_PREV, 1, OP_REG, 0, 'eax'],
      [REL_NEXT, 1, OP_STR, 0, 'dword ptr [eax]'],
      [REL_NEXT, 1, OP_VAL, 1, 0],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC]
    ],
    1,
    2,
  ],
  [
    'execution_on',
    'sel_on',
    [
      [REL_PREV, 1, OP_REG, 0, 'eax'],
      [REL_NEXT, 1, OP_STR, 0, 'dword ptr [eax]'],
      [REL_NEXT, 1, OP_VAL, 1, 1],
    ],
    [
      [REL_PREV, 1, 1, OP_SRC]
    ],
    1,
    2,
  ],
]


# -------------------------------------------------------------------
def mofo_get_prev_insn (addr, n):
  m = 0
  ea = addr
  while m < n:
    ea = idaapi.get_item_head (ea-1)
    # skip debug_id()
    if GetOpnd (ea, 0) != "id":
      m = m + 1
  return ea

# -------------------------------------------------------------------
def mofo_get_next_insn (addr, n):
  m = 0
  ea = addr
  while m < n:
    ea = idaapi.get_item_end (ea)
    # skip debug_id()
    if GetOpnd (ea, 0) != "id":
      m = m + 1
  return ea

# -------------------------------------------------------------------
def mofo_is_func (ea):
  for f,v in mofo_funcs.iteritems ():
    for a in v:
      if ea >= a[0] and ea < a[1]:
        return f
  return None

# -------------------------------------------------------------------
def mofo_get_func (ea):
  for f,v in mofo_funcs.iteritems ():
    for a in v:
      if ea >= a[0] and ea < a[1]:
        return a
  return None

# -------------------------------------------------------------------
def mofo_get_reg_value (ea, nopnd):
  if GetOpType (ea, nopnd) == o_imm:
    return '0x%08X' % GetOperandValue (ea, nopnd)
  else:
    return GetOpnd (ea, nopnd)

# -------------------------------------------------------------------
def mofo_detect_extern_mode ():
  addr_fault = get_name_ea (NT_NONE, 'fault')
  refs = DataRefsTo (addr_fault)
  for r in refs:
    return 1
  return 0

# -------------------------------------------------------------------
def mofo_get_reg_wr_ea (ea, regname, MAXDEPTH=50):
  current_ea = ea
  for n in range (1, MAXDEPTH):
    current_ea = mofo_get_prev_insn (current_ea, 1)
    if mofo_is_func (current_ea) != None:
      return 0xFFFFFFFF
    if GetOpType (current_ea, 0) == o_reg:
      if regname.lower() == "eax":
        r = GetOpnd (current_ea, 0).lower ()
        if r == "ax" or r == "al" or r == 'ah' or r == 'eax':
          return current_ea
      elif regname.lower () == "ebx":
        r = GetOpnd (current_ea, 0).lower ()
        if r == "bx" or r == "bl" or r == 'bh' or r == 'ebx':
          return current_ea
      elif regname.lower () == "ecx":
        r = GetOpnd (current_ea, 0).lower ()
        if r == "cx" or r == "cl" or r == 'ch' or r == 'ecx':
          return current_ea
      elif regname.lower () == "edx":
        r = GetOpnd (current_ea, 0).lower ()
        if r == "dx" or r == "dl" or r == 'dh' or r == 'edx':
          return current_ea
      else:
          return 0xFFFFFFFF
      if GetOpnd (current_ea, 0).lower() == regname.lower():
        return current_ea
  return 0xFFFFFFFF

# -------------------------------------------------------------------
def mofo_get_reg_rd_ea (ea, regname, MAXDEPTH=50):
  current_ea = ea
  for n in range (1, MAXDEPTH):
    if GetOpType (current_ea, 1) == o_reg:
      if GetOpnd (current_ea, 1).lower() == regname.lower():
        return current_ea
    current_ea = mofo_get_next_insn (current_ea, 1)
  return 0xFFFFFFFF

# -------------------------------------------------------------------
def mofo_byte_has_xref (addr):
  refs = idautils.DataRefsTo (addr)
  nrefs = sum (1 for r in refs)
  if nrefs == 0:
    return 0
  return 1

# -------------------------------------------------------------------
def mofo_align (addr, align):
  if ((addr-mofo_data_start)%align == 0):
    c = 0
  else:
    c = 16-(addr-mofo_data_start)%align
  return (addr+c)&0xFFFFFFFF

# -------------------------------------------------------------------
def mofo_make_data (addr, name, size, count):
  nbytes = 0
  for n in range (0, size):
    MakeUnkn (addr+n, DOUNK_EXPAND|DOUNK_DELNAMES)

  MakeName (addr, name)
  if size == MDAL_SIZE_BYTE:
    MakeByte (addr)
    nbytes = 1
  elif size == MDAL_SIZE_WORD:
    MakeWord (addr)
    nbytes = 2
  elif size == MDAL_SIZE_DWORD:
    MakeDword (addr)
    nbytes = 4
  MakeArray (addr, count)
  return addr + size*count

# -------------------------------------------------------------------
def mofo_make_list_data (addr, prefix, size, count):
  for n in range(0, count):
    MakeDword (addr + n*size)
    MakeName (addr + n*size, '%s%01d' % (prefix, n))
  return addr + size*count 

# -------------------------------------------------------------------
def mofo_make_1d_table (addr, name, size, count):
  if size == MDAL_SIZE_BYTE:
    MakeByte (addr)
  elif size == MDAL_SIZE_WORD:
    MakeWord (addr)
  elif size == MDAL_SIZE_DWORD:
    MakeDword (addr)
  MakeArray (addr, count)
  MakeName (addr, name)
  return addr + size*count + size

# -------------------------------------------------------------------
def mofo_make_2d_table (addr, name, n, m, size):
  cp = mofo_make_1d_table (addr, name, MDAL_SIZE_DWORD, n)
  for k in range (0, n):
    cp = mofo_make_1d_table (cp, name + '_%02X' % k, size, m)
  return cp

# -------------------------------------------------------------------
def mofo_make_1d_table_index (addr, prefix, size, count):
  cp = mofo_make_1d_table (addr, prefix, size, count)
  for n in range (0, count):
    cp = mofo_make_data (cp, prefix + '_%08X' % (n), size, 1)
  return cp

# -------------------------------------------------------------------
def mofo_data_anal ():
  currpos = mofo_data_start 

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_list_data (currpos, 'R', MDAL_SIZE_DWORD,
      SOFT_I_REGS)
  
  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_list_data (currpos, 'F', MDAL_SIZE_DWORD,
      SOFT_F_REGS)

  currpos = mofo_align (currpos, 16)
  for n in range (0, SOFT_D_REGS):
    currpos = mofo_make_data (currpos, 'D%01d' % n,
        MDAL_SIZE_DWORD, 2)
  
  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['or (used)', currpos])
  else:
    mofo_data.append (['or (unused)', currpos])
  currpos = mofo_make_list_data (currpos, 'or',
      MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'or_0',
      MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'or_1',
      MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['and (used)', currpos])
  else:
    mofo_data.append (['and (unused)', currpos])
  currpos = mofo_make_list_data (currpos, 'and', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'and_0',
      MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'and_1',
      MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['xor (used)', currpos])
  else:
    mofo_data.append (['xor (unused)', currpos])
  currpos = mofo_make_list_data (currpos, 'xor',
      MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'xor_0',
      MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'xor_1',
      MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['xnor (used)', currpos])
  else:
    mofo_data.append (['xnor (unused)', currpos])
  currpos = mofo_make_list_data (currpos, 'xnor', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'xnor_0', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_list_data (currpos, 'xnor_1', MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_true (used)', currpos])
  else:
    mofo_data.append (['alu_true (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_true', MDAL_SIZE_BYTE, 512)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_false (used)', currpos])
  else:
    mofo_data.append (['alu_false (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_false', MDAL_SIZE_BYTE, 512)

  currpos = mofo_align (currpos, 16)
  for n in range (0, 8):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['alu_b%01d (used)' % n, currpos])
    else:
      mofo_data.append (['alu_b%01d (unused)' % n, currpos])
    # remove the .align 200h (which appears on alu_s7)
    MakeUnkn (currpos+4, DOUNK_EXPAND|DOUNK_DELNAMES)
    currpos = mofo_make_1d_table (currpos, 'alu_b%01d' % n, MDAL_SIZE_DWORD, 256)
    currpos = mofo_align (currpos, 16)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_b_s (used)', currpos])
  else:
    mofo_data.append (['alu_b_s (unused)', currpos])

  currpos = mofo_make_2d_table (currpos, 'alu_b_s', 8, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_b_c (used)', currpos])
  else:
    mofo_data.append (['alu_b_c (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_b_c', 8, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_eq (used)', currpos])
  else:
    mofo_data.append (['alu_eq (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_eq', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_add8l (used)', currpos])
  else:
    mofo_data.append (['alu_add8l (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_add8l', MDAL_SIZE_BYTE, 512)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_add8h (used)', currpos])
  else:
    mofo_data.append (['alu_add8h (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_add8h', MDAL_SIZE_BYTE, 512)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_add16 (used)', currpos])
  else:
    mofo_data.append (['alu_add16 (unused)', currpos])
  currpos = mofo_make_1d_table_index (currpos, 'alu_add16', MDAL_SIZE_DWORD, 65536*2)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_inv8 (used)', currpos])
  else:
    mofo_data.append (['alu_inv8 (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_inv8', MDAL_SIZE_BYTE, 256)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_inv16 (used)', currpos])
  else:
    mofo_data.append (['alu_inv16 (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_inv16', MDAL_SIZE_WORD, 65536)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_band8 (used)', currpos])
  else:
    mofo_data.append (['alu_band8 (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_band8', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_bor8 (used)', currpos])
  else:
    mofo_data.append (['alu_bor8 (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_bor8', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_bxor8 (used)', currpos])
  else:
    mofo_data.append (['alu_bxor8 (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_bxor8', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_lshu8 (used)', currpos])
  else:
    mofo_data.append (['alu_lshu8 (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_lshu8', 33, 256, MDAL_SIZE_DWORD)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_rshu8 (used)', currpos])
  else:
    mofo_data.append (['alu_rshu8 (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_rshu8', 33, 256, MDAL_SIZE_DWORD)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_rshi8s (used)', currpos])
  else:
    mofo_data.append (['alu_rshi8s (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_rshi8s', 33, 256, MDAL_SIZE_DWORD)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_camp32 (used)', currpos])
  else:
    mofo_data.append (['alu_camp32 (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_clamp32', MDAL_SIZE_DWORD, 512)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_sum8l (used)', currpos])
  else:
    mofo_data.append (['alu_mul_sum8l (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_mul_sum8l', MDAL_SIZE_BYTE, 256*3)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_sum8h (used)', currpos])
  else:
    mofo_data.append (['alu_mul_sum8h (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_mul_sum8h', MDAL_SIZE_BYTE, 256*3)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_shl2 (used)', currpos])
  else:
    mofo_data.append (['alu_mul_shl2 (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_mul_shl2', MDAL_SIZE_DWORD, 256*16)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_sums (used)', currpos])
  else:
    mofo_data.append (['alu_mul_sums (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_mul_sums', MDAL_SIZE_DWORD, 256*16)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_mul8l (used)', currpos])
  else:
    mofo_data.append (['alu_mul_mul8l (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_mul_mul8l', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_mul_mul8h (used)', currpos])
  else:
    mofo_data.append (['alu_mul_mul8h (unused)', currpos])
  currpos = mofo_make_2d_table (currpos, 'alu_mul_mul8h', 256, 256, MDAL_SIZE_BYTE)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_div_shl1_8_c_d (used)', currpos])
  else:
    mofo_data.append (['alu_div_shl1_8_c_d (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_div_shl1_8_c_d', MDAL_SIZE_DWORD, 512)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_div_shl1_8_d (used)', currpos])
  else:
    mofo_data.append (['alu_div_shl1_8_d (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_div_shl1_8_d', MDAL_SIZE_DWORD, 256)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_div_shl2_8_d (used)', currpos])
  else:
    mofo_data.append (['alu_div_shl2_8_d (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_div_shl2_8_d', MDAL_SIZE_DWORD, 256)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_div_shl3_8_d (used)', currpos])
  else:
    mofo_data.append (['alu_div_shl3_8_d (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_div_shl3_8_d', MDAL_SIZE_DWORD, 256)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_sex8 (used)', currpos])
  else:
    mofo_data.append (['alu_sex8 (unused)', currpos])
  currpos = mofo_make_1d_table (currpos, 'alu_sex8', MDAL_SIZE_DWORD, 256)

  strlist = [
  'alu_cmp_of', 'alu_cmp_of_0',
  'alu_cmp_of_1', 'alu_cmp_of_00',
  'alu_cmp_of_01', 'alu_cmp_of_10',
  'alu_cmp_of_11'
  ]
  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_cmp_of (used)', currpos])
  else:
    mofo_data.append (['alu_cmp_of (unused)', currpos])
  for n in range (0, 7):
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 2)

  strlist = [
  'alu_cmp_of_000', 'alu_cmp_of_001',
  'alu_cmp_of_010', 'alu_cmp_of_011',
  'alu_cmp_of_100', 'alu_cmp_of_101',
  'alu_cmp_of_110', 'alu_cmp_of_111'
  ]
  for n in range (0, len(strlist)):
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  for n in range (0, 4): 
    if mofo_byte_has_xref (currpos + n * 4) == 1:
      mofo_data.append (['b%01d (used)' % n, currpos])
    else:
      mofo_data.append (['b%01d (unused)' % n, currpos])
    currpos = mofo_make_data (currpos, 'b%01d' % n, MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_x (used)', currpos])
  else:
    mofo_data.append (['alu_x (unused)', currpos])
  currpos = mofo_make_data (currpos, 'alu_x', MDAL_SIZE_DWORD, 1)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_y (used)', currpos])
  else:
    mofo_data.append (['alu_y (unused)', currpos])
  currpos = mofo_make_data (currpos, 'alu_y', MDAL_SIZE_DWORD, 1)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_s (used)', currpos])
  else:
    mofo_data.append (['alu_s (unused)', currpos])
  currpos = mofo_make_data (currpos, 'alu_s', MDAL_SIZE_DWORD, 2)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['alu_c (used)', currpos])
  else:
    mofo_data.append (['alu_c (unused)', currpos])
  currpos = mofo_make_data (currpos, 'alu_c', MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  for n in range (0, 4):
    currpos = mofo_make_data (currpos, 'nalu_s%01ds' % n, MDAL_SIZE_DWORD, 1)
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['nalu_s%01d (used)' % n, currpos])
    else:
      mofo_data.append (['nalu_s%01d (unused)' % n, currpos])
    currpos = mofo_make_data (currpos, 'nalu_s%01d' % n, MDAL_SIZE_DWORD, 2)
  strlist = ['s', 'c', 'x']
  for n in range (0, 3):
    currpos = mofo_make_data (currpos, 'nalu_s%ss' % (strlist[n]), MDAL_SIZE_DWORD, 1)
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['nalu_s%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['nalu_s%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, 'nalu_s%s' % strlist[n], MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  for n in range (0, 4):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['alu_z%01d (used)' % n, currpos])
    else:
      mofo_data.append (['alu_z%01d (unused)' % n, currpos])
    currpos = mofo_make_data (currpos, 'alu_z%01d' % n, MDAL_SIZE_DWORD, 1)

  strlist = [ 'alu_n', 'alu_d', 'alu_q', 'alu_r',
    'alu_t', 'alu_ns', 'alu_ds', 'alu_qs', 
    'alu_rs' ]
  currpos = mofo_align (currpos, 16)
  for n in range (0, len(strlist)):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 1)

  strlist = [
  'alu_sn', 'alu_sd', 'alu_sq', 'alu_sr',
  ]
  for n in range (0, len(strlist)):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 1)

  strlist = [
  'alu_sel_r', 'alu_sel_d', 'alu_sel_q', 'alu_sel_n'
  ]
  for n in range (0, len(strlist)):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 2)

  strlist = [
  'alu_psel_r', 'alu_psel_d', 'alu_psel_q', 'alu_psel_n'
  ]
  for n in range (0, len(strlist)):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 1)

  strlist = [
  'mofo_zf', 'mofo_sf', 'mofo_of', 'mofo_cf'
  ]
  currpos = mofo_align (currpos, 16)
  for n in range (0, len(strlist)):
    if mofo_byte_has_xref (currpos) == 1:
      mofo_data.append (['%s (used)' % strlist[n], currpos])
    else:
      mofo_data.append (['%s (unused)' % strlist[n], currpos])
    currpos = mofo_make_data (currpos, strlist[n], MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['branch_temp (used)', currpos])
  else:
    mofo_data.append (['branch_temp (unused)', currpos])
  currpos = mofo_make_data (currpos, 'branch_temp', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['stack_temp (used)', currpos])
  else:
    mofo_data.append (['stack_temp (unused)', currpos])
  currpos = mofo_make_data (currpos, 'stack_temp', MDAL_SIZE_DWORD, 2)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['pop_guard (used)', currpos])
  else:
    mofo_data.append (['pop_guard (unused)', currpos])
  currpos = mofo_make_data (currpos, 'pop_guard', MDAL_SIZE_DWORD, 1)

  if mofo_byte_has_xref (currpos) == 1:
    mofo_data.append (['pushpop (used)', currpos])
  else:
    mofo_data.append (['pushpop (unused)', currpos])
  currpos = mofo_make_data (currpos, 'pushpop', MDAL_SIZE_DWORD, 1)
  currpos = currpos + STACK_SIZE
  currpos = mofo_make_data (currpos, 'push_gard', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'stack_ptr', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'frame_ptr', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'sesp', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'sel_on', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_data (currpos, 'on', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'toggle_execution', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'sel_target', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_data (currpos, 'target', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'sel_data', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'data_p', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  for n in range (0, STACK_SIZE/4):
    currpos = mofo_make_data (currpos, 'stack_%08X' % n, MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'id', MDAL_SIZE_DWORD, 1)

  currpos = mofo_align (currpos, 16)
  for n in range (0, SOFT_I_REGS):
    currpos = mofo_make_data (currpos, 'jmp_r%01d' % n, MDAL_SIZE_DWORD, 1)

  for n in range (0, SOFT_F_REGS):
    currpos = mofo_make_data (currpos, 'jmp_f%01d' % n, MDAL_SIZE_DWORD, 1)

  for n in range (0, SOFT_D_REGS):
    currpos = mofo_make_data (currpos, 'jmp_d%01d' % n, MDAL_SIZE_DWORD, 2)

  currpos = mofo_align (currpos, 16)
  currpos = mofo_make_data (currpos, 'ext_ret_val', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'external', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'fault', MDAL_SIZE_DWORD, 2)
  currpos = mofo_make_data (currpos, 'no_fault', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'sa_dispatch', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'disp_sa_mask', MDAL_SIZE_DWORD, 0x20)
  currpos = mofo_make_data (currpos, 'disp_sa_flags', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'disp_sa_restorer', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'sa_loop', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'loop_sa_mask', MDAL_SIZE_DWORD, 0x20)
  currpos = mofo_make_data (currpos, 'loop_sa_flags', MDAL_SIZE_DWORD, 1)
  currpos = mofo_make_data (currpos, 'loop_sa_resterer', MDAL_SIZE_DWORD, 1)

# -------------------------------------------------------------------
def mofo_update_funcs (name, start, end, args):
  if name in mofo_funcs:
    mofo_funcs[name].append(list())
    mofo_funcs[name][-1].append (start)
    mofo_funcs[name][-1].append (end)
    mofo_funcs[name][-1].append (list())
    mofo_funcs[name][-1][2] = args
  else:
    mofo_funcs[name] = list()
    mofo_funcs[name].append (list())
    mofo_funcs[name][0].append (start)
    mofo_funcs[name][0].append (end)
    mofo_funcs[name][0].append (list())
    mofo_funcs[name][0][2] = args

# -------------------------------------------------------------------
def mofo_code_anal ():
  for cs in xref_code_sign:
    xref_ea = get_name_ea (NT_NONE, cs[1])
    xrefs = DataRefsTo (xref_ea)
    for xref in xrefs:
      found = 0
      for refchk in cs[2]:
        refaddr = 0
        if refchk[0] == REL_CURR:
          refaddr = xref
        elif refchk[0] == REL_NEXT:
          refaddr = mofo_get_next_insn (xref, refchk[1])
        elif refchk[0] == REL_PREV:
          refaddr = mofo_get_prev_insn (xref, refchk[1])
        
        if refchk[2] == OP_REG:
          if GetOpType (refaddr, refchk[3]) != o_reg:
            break
        elif refchk[2] == OP_STR:
          if GetOpnd (refaddr, refchk[3]).lower() != refchk[4].lower():
            break
        elif refchk[2] == OP_XREF:
          if GetOperandValue (refaddr, refchk[3]) != get_name_ea (
              NT_NONE, refchk[4]):
            break
        elif refchk[2] == OP_VAL:
          if GetOperandValue (refaddr, refchk[3]) != refchk[4]:
            break
        found = found + 1
      if found == len(cs[2]):
        block_start = mofo_get_prev_insn (xref, cs[4])
        block_end = mofo_get_next_insn (xref, cs[5])
        block_args = list()
        if mofo_is_func (block_start) == None:
          for args in cs[3]:
            arg_ea = 0
            if args[0] == REL_CURR:
              arg_ea = xref
            elif args[0] == REL_NEXT:
              arg_ea = mofo_get_next_insn (xref, args[1])
            elif args[0] == REL_PREV:
              arg_ea = mofo_get_prev_insn (xref, args[1])

            if GetOpType (arg_ea, args[2]) == o_reg:
              regname = GetOpnd (arg_ea, args[2])
              if args[3] == OP_SRC:
                regaxx = mofo_get_reg_wr_ea (block_start, regname)
                if regaxx != 0xFFFFFFFF:
                  block_args.append (GetOpnd (regaxx, 1))
                else:
                  block_args.append (regname)
              elif args[3] == OP_DST:
                regaxx = mofo_get_reg_rd_ea (block_end, regname)
                if regaxx != 0xFFFFFFFF:
                  block_args.append (GetOpnd (regaxx, 0))
                else:
                  block_args.append (regname)
            elif GetOpType (arg_ea, args[2]) == o_imm:
              block_args.append ('0x%08X' % GetOperandValue (arg_ea, args[2]))
            else:
              block_args.append (GetOpnd (arg_ea, args[2]))
          mofo_update_funcs (cs[0], block_start, block_end, block_args)
        
# -------------------------------------------------------------------
def mofo_search_stack ():
  refs = DataRefsTo (get_name_ea (NT_NONE, 'frame_ptr'))
  pushpop_addr = get_name_ea (NT_NONE, 'pushpop')
  stack_addr = get_name_ea (NT_NONE, 'stack_00000000')
  push_val = (pushpop_addr - stack_addr - 4)*(-1)
  pop_val  = (pushpop_addr - stack_addr + 4)*(-1)
  push_str = '%x' % push_val
  pop_str = '%x' % pop_val
  print push_str
  print pop_str
  nbytes = 0
  for r in refs:
    if mofo_is_func (r) != None:
      continue
    current_ea = mofo_get_next_insn (r, 1)
    nbytes = 4
    opnd = GetOpnd (current_ea, 1)
    opnd = opnd.lower ()
    if opnd.find (push_str) != -1:
      while True:
        current_ea = mofo_get_next_insn (current_ea, 1)
        opnd = GetOpnd (current_ea, 1)
        opnd = opnd.lower ()
        if opnd.find (push_str) != -1:
          nbytes = nbytes + 4
        else:
          break
      if GetOpnd (current_ea, 0) == "edx" and GetOpnd (current_ea, 1) == "on":
        end_block = mofo_get_next_insn (current_ea, 4)
        val = GetOpnd (mofo_get_next_insn (current_ea, 3), 1)
        mofo_update_funcs ('mov', r, end_block, ['*(frame_ptr - 0x%08X)' % nbytes, '%s' % val])
      elif GetOpnd (current_ea, 0)[0] == 'R' and GetOpnd (current_ea, 1) == 'eax':
        end_block = mofo_get_next_insn (current_ea, 7)
        val = GetOpnd (mofo_get_next_insn (current_ea, 6), 0)
        mofo_update_funcs ('mov', r, end_block, ['%s' % val, '*(frame_ptr - 0x%08X)' % nbytes])
      else:
        mofo_update_funcs ('alu_sub', r, current_ea, ['frame_ptr', '0x%08X' % nbytes, 'eax'])
    elif opnd.find (pop_str) != -1:
      while True:
        current_ea = mofo_get_next_insn (current_ea, 1)
        opnd = GetOpnd (current_ea, 1)
        opnd = opnd.lower ()
        if opnd.find (pop_str) != -1:
          nbytes = nbytes + 4
        else:
          break
      if GetOpnd (current_ea, 0) == "edx" and GetOpnd (current_ea, 1) == "on":
        end_block = mofo_get_next_insn (current_ea, 4)
        val = GetOpnd (mofo_get_next_insn (current_ea, 3), 1)
        mofo_update_funcs ('mov', r, end_block, ['*(frame_ptr + 0x%08X)' % nbytes, '%s' % val])
      elif GetOpnd (current_ea, 0)[0] == 'R' and GetOpnd (current_ea, 1) == 'eax':
        end_block = mofo_get_next_insn (current_ea, 7)
        val = GetOpnd (mofo_get_next_insn (current_ea, 6), 0)
        mofo_update_funcs ('mov', r, end_block, ['%s' % val, '*(frame_ptr + 0x%08X)' % nbytes])
      else:
        mofo_update_funcs ('alu_add', r, current_ea, ['frame_ptr', '0x%08X' % nbytes, 'eax'])

# -------------------------------------------------------------------
def mofo_search_movreg ():
  for n in range (0, SOFT_I_REGS):
    soft_reg_ea = get_name_ea (NT_NONE, 'R%1d' % n)
    refs = DataRefsTo (soft_reg_ea)
    for r in refs:
      if mofo_is_func (r) != None:
        continue
      start = r
      end = mofo_get_next_insn (r, 1)
      if GetOpType (r, 1) == o_imm:
        op1 = GetOpnd (r, 1)
        mofo_update_funcs ('mov', r, end, ['R%1d' % n, op1])
      elif GetOpType (r, 1) == o_reg:
        op1 = GetOpnd (r, 1)
        opaxx = mofo_get_reg_wr_ea (r, op1)
        if opaxx != 0xFFFFFFFF:
          if GetOpType (opaxx, 1) != o_reg:
            mofo_update_funcs ('mov', opaxx, end, ['R%1d' % n, GetOpnd (opaxx, 1)])
        else:
          mofo_update_funcs ('mov', r, end, ['R%1d' % n, GetOpnd (r, 1)])

# -------------------------------------------------------------------
def mofo_search_call_extern ():
  # MOV_EXTERN = 0
  current_ea = mofo_code_start
  while current_ea < mofo_code_end:
    mnem = GetMnem (current_ea).lower()
    if mnem == "jz" or mnem == "je":
      start = mofo_get_prev_insn (current_ea, 2)
      end = current_ea
      symname = GetOpnd(LocByName(GetOpnd (current_ea, 0)), 0)
      symname = symname.replace ('ds:', '')
      mofo_update_funcs (symname, start, end, ['']) 
    current_ea = mofo_get_next_insn (current_ea, 1)
  # MOV_EXTERN = 1
  current_ea = mofo_code_start
  addr_fault = get_name_ea (NT_NONE, 'fault')
  refs = DataRefsTo (addr_fault)
  for r in refs:
    start = 0
    end = 0
    args = list ()

    start = mofo_get_prev_insn (r, 3)
    end = mofo_get_next_insn (r, 1)
    symname = GetOpnd (GetOperandValue (mofo_get_next_insn (start, 1), 1), 0)
    symname = symname.replace ('ds:', '')
    mofo_update_funcs (symname, start, end, [''])

# -------------------------------------------------------------------
def mofo_code_anal_ex ():
  mofo_search_call_extern ()
  mofo_search_stack ()
  mofo_search_movreg ()

# -------------------------------------------------------------------
def mofo_sel_block (start, end):
  current_ea = start
  while current_ea < end:
    idaapi.set_item_color (current_ea, MOFO_HL_BKGD)
    current_ea = mofo_get_next_insn (current_ea, 1)

# -------------------------------------------------------------------
def mofo_desel_block (start, end):
  current_ea = start
  while current_ea < end:
    idaapi.set_item_color (current_ea, idc.DEFCOLOR)
    current_ea = mofo_get_next_insn (current_ea, 1)

# -------------------------------------------------------------------
class mofoscator_gui (QtGui.QWidget):
  def __init__ (self, parent=None):
    super (mofoscator_gui, self).__init__(parent)
    self.block_sel_begin = 0
    self.block_sel_end = 0
    self.movfuncs = QtGui.QTableWidget (0, 3)
    vheader = QtGui.QHeaderView (QtCore.Qt.Orientation.Vertical)
    hheader = QtGui.QHeaderView (QtCore.Qt.Orientation.Horizontal)
    vheader.setResizeMode (QtGui.QHeaderView.Interactive)
    vheader.hide ()
    self.movfuncs.setVerticalHeader (vheader)
    self.movfuncs.setHorizontalHeader (hheader)
    self.movfuncs.setHorizontalHeaderLabels (['movfuscator functions', 'start', 'end'])
    self.movfuncs.setEditTriggers (QtGui.QAbstractItemView.NoEditTriggers)
    self.movdata = QtGui.QTableWidget (0, 2)
    vheader = QtGui.QHeaderView (QtCore.Qt.Orientation.Vertical)
    hheader = QtGui.QHeaderView (QtCore.Qt.Orientation.Horizontal)
    vheader.setResizeMode (QtGui.QHeaderView.Interactive)
    vheader.hide ()
    self.movdata.setVerticalHeader (vheader)
    self.movdata.setHorizontalHeader (hheader)
    self.movdata.setHorizontalHeaderLabels (['movfuscator data', 'address'])
    self.movdata.setEditTriggers (QtGui.QAbstractItemView.NoEditTriggers)

    movfuncs_sel = self.movfuncs.selectionModel ()
    movfuncs_sel.selectionChanged.connect (self.mofoscator_gui_sel_func_item)

    movdata_sel = self.movdata.selectionModel ()
    movdata_sel.selectionChanged.connect (self.mofoscator_gui_sel_data_item)

    self.codestart_edit = QtGui.QLineEdit ()
    self.codeend_edit = QtGui.QLineEdit ()
    self.datastart_edit = QtGui.QLineEdit ()
    self.labeloffset_edit = QtGui.QLineEdit ()
    self.dataalign_edit = QtGui.QLineEdit ()
    self.nsoftiregs_edit = QtGui.QLineEdit ()
    self.nsoftdregs_edit = QtGui.QLineEdit ()
    self.nsoftfregs_edit = QtGui.QLineEdit ()
    self.stackthres_edit = QtGui.QLineEdit ()
    self.hlcolor_edit    = QtGui.QLineEdit ()
    self.anal_button = QtGui.QPushButton ('ANALize')
    self.exp_button = QtGui.QPushButton ('Export as text')

    self.labeloffset_edit.setText ('0x%08X' % MOV_OFFSET)
    self.dataalign_edit.setText ('%u' % align)
    self.nsoftiregs_edit.setText ('%u' % SOFT_I_REGS)
    self.nsoftdregs_edit.setText ('%u' % SOFT_D_REGS)
    self.nsoftfregs_edit.setText ('%u' % SOFT_F_REGS)
    self.stackthres_edit.setText ('0x%08X' % STACK_EX_THRESH)
    self.hlcolor_edit.setText ('0x%08X' % MOFO_HL_BKGD)

    grid = QtGui.QGridLayout ()
    grid.setSpacing (5)
    grid.addWidget (
        QtGui.QLabel ('code start'),
        1, 0
        )
    grid.addWidget (
        self.codestart_edit, 
        1, 1
    )
    grid.addWidget (
        QtGui.QLabel ('code end'),
        2, 0
        )
    grid.addWidget (
       self.codeend_edit,  
        2, 1
        )
    grid.addWidget (
        QtGui.QLabel ('data start'),
        3, 0 
        )
    grid.addWidget (
       self.datastart_edit,  
        3, 1
        )
    grid.addWidget (
        QtGui.QLabel ('label offset'),
        4, 0
        )
    grid.addWidget (
       self.labeloffset_edit,  
        4, 1
        )
    grid.addWidget (
        QtGui.QLabel ('data align'),
        5, 0
        )
    grid.addWidget (
       self.dataalign_edit,  
        5, 1
        )
    grid.addWidget (
        QtGui.QLabel ('number of soft_i_regs'),
        6, 0
        )
    grid.addWidget (
       self.nsoftiregs_edit,  
        6, 1
        )
    grid.addWidget (
        QtGui.QLabel ('number of soft_f_regs'),
        7, 0
        )
    grid.addWidget (
       self.nsoftdregs_edit,  
        7, 1
        )
    grid.addWidget (
        QtGui.QLabel ('number of soft_d_regs'),
        8, 0
        )
    grid.addWidget (
       self.nsoftfregs_edit,  
        8, 1
        )
    grid.addWidget (
        QtGui.QLabel ('stack thresold'),
        9, 0
        )
    grid.addWidget (
       self.stackthres_edit,  
        9, 1
        )
    grid.addWidget (
        QtGui.QLabel ('highlight color'),
        10, 0
        )
    grid.addWidget (
        self.hlcolor_edit,
        10, 1,
        )
    grid.addWidget (
        self.anal_button,
        11, 0,
        1, 1 
        )
    grid.addWidget (
        self.exp_button,
        11, 1, 
        1, 1
        )
    grid.addWidget (
        self.movfuncs,
        1, 3,
        11, 1
        )
    grid.addWidget (
        self.movdata,
        1, 2,
        11, 1
        )
    grid.setColumnStretch (3, 50)
    self.setLayout (grid)
    self.anal_button.clicked.connect (self.mofoscator_gui_anal)
    self.exp_button.clicked.connect (self.mofoscator_gui_export)
    self.exp_button.setEnabled (False)

  def mofoscator_gui_add_movfuncs (self, name, start, end):
    self.movfuncs.insertRow (self.movfuncs.rowCount())
    self.movfuncs.setItem (self.movfuncs.rowCount()-1, 0, QtGui.QTableWidgetItem (name))
    self.movfuncs.setItem (self.movfuncs.rowCount()-1, 1, QtGui.QTableWidgetItem ('0x%08X' % start))
    self.movfuncs.setItem (self.movfuncs.rowCount()-1, 2, QtGui.QTableWidgetItem ('0x%08X' % end))

  def mofoscator_gui_add_movdata (self, name, start):
    self.movdata.insertRow (self.movdata.rowCount())
    self.movdata.setItem (self.movdata.rowCount()-1, 0, QtGui.QTableWidgetItem (name))
    self.movdata.setItem (self.movdata.rowCount()-1, 1, QtGui.QTableWidgetItem ('0x%08X' % start))

  def mofoscator_gui_anal (self):
    global mofo_code_start
    global mofo_code_end
    global mofo_data_start
    global align
    global MOV_OFFSET
    global SOFT_I_REGS
    global SOFT_F_REGS
    global SOFT_D_REGS
    global MOV_FLOW
    global MOFO_HL_BKGD

    if self.codestart_edit.text () == "":
      print 'please specify the start address of movfuscator\'s code'
      return
    if self.codeend_edit.text () == "":
      print 'please specify the end address of movfuscator\'s code'
      return
    if self.datastart_edit.text () == "":
      print 'please specify the start address of movfuscator\'s data'
      return

    mofo_code_start = int (self.codestart_edit.text(), 16)
    mofo_code_end = int (self.codeend_edit.text(), 16)
    mofo_data_start = int (self.datastart_edit.text(), 16)
    align = int (self.dataalign_edit.text())
    MOV_OFFSET = int (self.labeloffset_edit.text(), 16)
    SOFT_I_REGS = int (self.nsoftiregs_edit.text())
    SOFT_D_REGS = int (self.nsoftdregs_edit.text())
    SOFT_F_REGS = int (self.nsoftfregs_edit.text())
    MOFO_HL_BKGD = int (self.hlcolor_edit.text(), 16)

    self.anal_button.setEnabled (False)
    self.exp_button.setEnabled (True)

    mofo_desel_block (mofo_code_start, mofo_code_end)

    mofo_data_anal ()
    mofo_code_anal ()
    mofo_code_anal_ex ()

    for d in mofo_data:
      self.mofoscator_gui_add_movdata (d[0], d[1])

    current_ea = mofo_code_start
    block_start = current_ea
    block_end = 0
    while current_ea < mofo_code_end:
      f = mofo_is_func (current_ea)
      if f != None:
        a = mofo_get_func (current_ea)
        block_start = current_ea
        block_end = a[1]
        stritem = '%s (' % f
        for n in range (0, len(a[2])):
          if ((n+1) < len(a[2])):
            stritem = stritem + a[2][n] + ', '
          else:
            stritem = stritem + a[2][n]
        stritem = stritem + ');'
        self.mofoscator_gui_add_movfuncs (stritem, block_start, block_end)
        current_ea = a[1]
      else:
        current_ea = mofo_get_next_insn (current_ea, 1)

  def mofoscator_gui_sel_func_item (self, selected, deselected):
    if self.movfuncs.selectionModel().currentIndex().column() > 0:
      row = self.movfuncs.selectionModel().currentIndex().row()
      mofo_desel_block (self.block_sel_begin, self.block_sel_end)
      start = int(self.movfuncs.item(row, 1).data(0), 16)
      end = int(self.movfuncs.item(row, 2).data(0), 16)
      mofo_sel_block (start, end)
      self.block_sel_begin = start
      self.block_sel_end = end
      idaapi.jumpto (start)

  def mofoscator_gui_sel_data_item (self, selected, deselected):
    if self.movfuncs.selectionModel().currentIndex().column() > 0:
      row = self.movdata.selectionModel().currentIndex().row()
      idaapi.jumpto (int(self.movdata.item(row, 1).data(0), 16))

  def mofoscator_gui_export (self):
    filename = QtGui.QFileDialog.getSaveFileName ()
    fdoutput = open (filename[0], 'wb')
    current_ea = mofo_code_start
    block_start = current_ea
    block_end = 0
    while current_ea < mofo_code_end:
      f = mofo_is_func (current_ea)
      if f != None:
        a = mofo_get_func (current_ea)
        block_start = current_ea
        block_end = a[1]
        stritem = '%s (' % f
        for n in range (0, len(a[2])):
          if ((n+1) < len(a[2])):
            stritem = stritem + a[2][n] + ', '
          else:
            stritem = stritem + a[2][n]
        stritem = stritem + ');'
        fdoutput.write ('/* 0x%08X */ %s\n' % (block_start, stritem))
        current_ea = a[1]
      else:
        current_ea = mofo_get_next_insn (current_ea, 1)
    fdoutput.close ()
    print 'The file has been exported'




mofogui = mofoscator_gui ()
mofogui.setWindowTitle ('mofoscator')
mofogui.setWindowFlags (QtCore.Qt.WindowStaysOnTopHint)
mofogui.show ()
