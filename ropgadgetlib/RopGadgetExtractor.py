#!/usr/bin/python3

"""
Copyright 2021 Neetx
This file is part of ropgadgetlib.
ropgadgetlib is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
ropgadgetlib is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with ropgadgetlib.  If not, see <http://www.gnu.org/licenses/>.
"""

from capstone import *
import sys

class Gadget:
    address = None
    instructions = None

    def __init__(self, instructions):
        self.address = instructions[0]['address']
        self.instructions = instructions

    def __str__(self):
        return "0x%x" % self.address
    
    def getAddress(self):
        return self.address
    
    def getInstructions(self):
        return self.instructions

class RopGadgetExtractor:
    filename = None
    file_byte_array = None
    indexes = None
    gadgets = None
    arch = None
    mode = None
    depth = 5

    def __init__(self, filename, arch="amd64", mode="64"):
        self.filename = filename
        self.arch = arch
        self.mode = mode
        self.file_byte_array = self.get_bytes_from_file(self.filename)
        self.indexes = self.get_ret_index(self.file_byte_array)

    def get_bytes_from_file(self, filename):  
        return open(filename, "rb").read()  

    def get_ret_index(self, file_array):
        indexes = []
        for i in range(0, len(file_array)):
            if hex(file_array[i]) == "0xc3" or ((hex(file_array[i]) == "0x5") and (hex(file_array[i-1]) == "0xf")) or ((hex(file_array[i]) == "0xd0") and (hex(file_array[i-1]) == "0xff")):
                indexes.append(i)
        return indexes

    def get_gadgets(self, depth=5):
        if self.arch=="amd64" and self.mode=="64":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            exit(0)

        gadgets = []

        for item in self.indexes:
            for j in range(0, depth + 1):
                gadget_array = self.file_byte_array[item-j:item+1]
                gadget = []
                last_o = None        
                for i in md.disasm(gadget_array, 0x400000+item-j): #This starting address fix offsets in oprand
                    address = 0x400000+item-j
                    #print("0x%x %s %s" % (i.address, i.mnemonic, i.op_str))
                    gadget.append({"address": i.address, "mnemonic": i.mnemonic, "op_str":i.op_str})
                    last_o  = i.mnemonic
                    last_op = i.op_str
                    
                if last_o != None and (last_o == "ret" or last_o == "ret" or (last_o == "call" and last_op == "rax" )) and len(gadget)>0:
                    g = Gadget(gadget)
                    gadgets.append(g)

        self.gadgets = gadgets 
        return self.gadgets


def print_gadgets(gadgets):
    for gadget in gadgets:
        print("0x%x : " % gadget.address, end='')
        for instruction in gadget.instructions:
            if instruction == gadget.instructions[-1]:
                print("%s %s" % (instruction['mnemonic'], instruction['op_str']), end='')    
            else:
                print("%s %s ; " % (instruction['mnemonic'], instruction['op_str']), end='')
        print("\n", end='')
    print("\nGadget found : %d" % len(gadgets))

if __name__ == "__main__":

    rop = RopGadgetExtractor(sys.argv[1])
    
    gadgets = rop.get_gadgets(10)

    print_gadgets(gadgets)
