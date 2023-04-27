#! /usr/bin/python3

import re

f = open('include/common/bluetooth.h', 'r')
fout = open('bluetooth.h', 'w')
lines = []
struct_name = ''
for line in f.readlines():
    if line.find('struct') == 0:
        struct_name = line.split()[1]
        lines.append('typedef struct __attribute__((packed)) {\n')
    elif '__attribute__((packed))' in line and 'struct' not in line:
        lines.append('}' + ' {};\n'.format(struct_name))
    else:
        lines.append(line)
        
fout.writelines(lines)