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