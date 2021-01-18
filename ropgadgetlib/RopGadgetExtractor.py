from capstone import *
import sys

class RopGadgetExtractor:
    filename = None
    file_byte_array = None
    ret_indexes = None
    sys_indexes = None
    ret_gadgets = None
    sys_gadgets = None
    arch = None
    mode = None
    depth = 5

    def __init__(self, filename, arch="amd64", mode="64"):
        self.filename = filename
        self.arch = arch
        self.mode = mode
        self.file_byte_array = self.get_bytes_from_file(self.filename)
        self.ret_indexes, self.sys_indexes = self.get_ret_index(self.file_byte_array)

    def get_bytes_from_file(self, filename):  
        return open(filename, "rb").read()  

    def get_ret_index(self, file_array):
        rets_indexes = []
        sys_indexes = []
        for i in range(0, len(file_array)):
            byte = hex(file_array[i])
            if (byte == "0x5") and (hex(file_array[i-1]) == "0xf"):
                sys_indexes.append(i)
            elif byte == "0xc3":
                rets_indexes.append(i)
        return rets_indexes, sys_indexes

    def get_gadgets(self, depth=5):
        if self.arch=="amd64" and self.mode=="64":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            exit(0)

        gadgets = {}
        
        #print(hex(self.file_byte_array[self.ret_indexes[0]]))

        for item in self.ret_indexes:
            for j in range(0, depth + 1):
                gadget_array = self.file_byte_array[item-j:item+1]
                gadget = []
                last_o = None        
                for i in md.disasm(gadget_array, 0x400000+item-j): #This starting address fix offsets in oprand
                    address = 0x400000+item-j
                    #print("0x%x %s %s" % (i.address, i.mnemonic, i.op_str))
                    gadget.append({"address": i.address, "mnemonic": i.mnemonic, "op_str":i.op_str})
                    last_o = i.mnemonic
                    #print(last_o)
                if last_o != None and last_o == "ret" and len(gadget)>0:
                    """This will remove duplicate, often there are doubled gadget
                    but ending with repz ret: https://repzret.org/p/repzret/  """
                    if address not in gadgets:  
                        gadgets[address] = gadget
        sys_gadgets = {}
        for item in self.sys_indexes:
            for j in range(0, depth + 1):
                gadget_array = self.file_byte_array[item-j:item+1]
                gadget = []
                last_o = None        
                for i in md.disasm(gadget_array, 0x400000+item-j): #This starting address fix offsets in oprand
                    address = 0x400000+item-j
                    #print("%s %s %s" % (i.address, i.mnemonic, i.op_str))
                    gadget.append({"address": i.address, "mnemonic": i.mnemonic, "op_str":i.op_str})
                    last_o = i.mnemonic
                    #print(last_o)             
            
                if last_o != None and last_o == "syscall" and len(gadget)>0:
                    """This will remove duplicate, often there are doubled gadget
                    but ending with repz ret: https://repzret.org/p/repzret/  """
                    if address not in sys_gadgets:  
                        sys_gadgets[address] = gadget


        self.ret_gadgets = gadgets
        self.sys_gadgets = sys_gadgets
        return self.ret_gadgets, self.sys_gadgets

def print_gadgets(gadgets):
    for address in gadgets.keys():
        print("0x%x : " % address, end='')
        for op in gadgets[address]:
            if op['mnemonic'] == "ret" or op['mnemonic'] == "syscall":
                print("%s  %s" % (op['mnemonic'], op['op_str']), end='')
            else:
                print("%s  %s; " % (op['mnemonic'], op['op_str']), end='')
        print('\n', end='')

    print("\nGadget found : %d" % len(gadgets))



if __name__ == "__main__":

    rop = RopGadgetExtractor(sys.argv[1])
    
    ret_gadgets, sys_gadgets = rop.get_gadgets(10)

    print_gadgets(ret_gadgets)
    print_gadgets(sys_gadgets)
