# ropgadgetlib

ropgadgetlib is a python>=3.7 rop gadget extractor, its purpose is to support me into research and experiments as a tool and library.

In the future I will support x86, arm and mips and a setup.py to have the right installation way.

### Context

- x86_64 Linux

### Installation and requirements
```bash
git clone https://github.com/Neetx/ropgadgetlib
cd ropgadgetlib
pip install -r requirements.txt
python setup.py install
```

### Basic usage

For now it gets ret, syscall and call rax gadget.

ropgadgetextractor as a tool

```bash
./RopGadgetExtractor.py <FILE_NAME>
```

**ropgadgetlib**
```python
from ropgadgetlib.RopGadgetExtractor import *

rop = RopGadgetExtractor(sys.argv[1])
gadgets = rop.get_gadgets(10)
print_gadgets(gadgets)
```

"gadgets" is a list of Gadget objects
```python
first_gadget = gadgets[0]
print(hex(first_gadget.address))
print(first_gadget.instructions)
```

Output:
```python
'0x400410'
[{'address': 4195344, 'mnemonic': 'call', 'op_str': 'rax'}]
```

### Output example

```bash
 ./RopGadgetExtractor.py ./vuln 
0x400410 : call rax
0x40040e : je 0x400412 ; call rax
0x40040c : test eax, eax ; je 0x400412 ; call rax
0x40040b : test rax, rax ; je 0x400412 ; call rax
0x400409 : and byte ptr [rax], al ; test rax, rax ; je 0x400412 ; call rax
0x400416 : ret 
0x400413 : add esp, 8 ; ret 
0x400412 : add rsp, 8 ; ret 
0x400410 : call rax ; add rsp, 8 ; ret 
0x40040e : je 0x400412 ; call rax ; add rsp, 8 ; ret 
0x40040d : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret 
0x40040c : test eax, eax ; je 0x400412 ; call rax ; add rsp, 8 ; ret 

   .
   .
   .

0x4005cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret 
0x4005cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret 
0x4005cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret 
0x4005ca : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret 
0x4005e1 : ret 
0x4005e0 : ret 
0x4005df : add bl, dh ; ret 
0x4005de : add byte ptr [rax], al ; ret 
0x4005dd : add byte ptr [rax], al ; add bl, dh ; ret 
0x4005dc : add byte ptr [rax], al ; add byte ptr [rax], al ; ret 
0x4005db : add byte ptr [rax], al ; add byte ptr [rax], al ; add bl, dh ; ret 
0x4005da : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; ret 
0x4005d8 : nop dword ptr [rax + rax] ; ret 
0x4005d7 : nop dword ptr cs:[rax + rax] ; ret 
0x4005ec : ret 
0x4005e9 : add esp, 8 ; ret 
0x4005e8 : add rsp, 8 ; ret 
0x4005e5 : sub esp, 8 ; add rsp, 8 ; ret 
0x4005e4 : sub rsp, 8 ; add rsp, 8 ; ret 
0x4005e2 : add byte ptr [rax], al ; sub rsp, 8 ; add rsp, 8 ; ret 

Gadget found : 84
```
### Contacts

[neetx](neetx@protonmail.com)

### License

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