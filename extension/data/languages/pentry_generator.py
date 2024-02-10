#!/usr/bin/env python3

regs = ["RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"]

print('<!-- 8 byte arguments -->')
for r in regs:
    print('<pentry minsize="1" maxsize="8">')
    print(f'  <register name="{r}"/>')
    print('</pentry>')
print()

print('<!-- 16 byte arguments -->')
for (i, r1) in enumerate(regs[:-1]):
    r2 = regs[i+1]
    print('<pentry minsize="9" maxsize="16">')
    print(f'  <addr space="join" piece1="{r2}" piece2="{r1}"/>')
    print('</pentry>')
print()

print('<!-- 24 byte arguments -->')
for (i, r1) in enumerate(regs[:-2]):
    r2 = regs[i+1]
    r3 = regs[i+2]
    print('<pentry minsize="17" maxsize="24">')
    print(f'  <addr space="join" piece1="{r3}" piece2="{r2}" piece3="{r1}"/>')
    print('</pentry>')
print()

print('<!-- 32 byte arguments -->')
for (i, r1) in enumerate(regs[:-3]):
    r2 = regs[i+1]
    r3 = regs[i+2]
    r4 = regs[i+3]
    print('<pentry minsize="25" maxsize="32">')
    print(f'  <addr space="join" piece1="{r4}" piece2="{r3}" piece3="{r2}" piece4="{r1}"/>')
    print('</pentry>')
print()
