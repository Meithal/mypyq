# Mypyq

Mypypq is a rewrite of https://github.com/TheSil/mpyq.
It is meant to open hostile mpq's such as protected war3 maps.

## Install
```
python -m pip install git+https://github.com/Meithal/mypyq.git
```

## Usage
It can be used as a runpy module, eg `python -m mypyq`.

- `python -m mypyq --help` to see usage.
- `python -m mypyq --bat` to generate a .bat file on which you can drag and drop the mpqs you want to extract.

After creating a .bat file you can drag and drop the mpq files you want to have extracted onto the .bat file you created.

It can also be used as a library, eg 

```python

import pathlib
import mypyq

with pathlib.Path("your mpq path").open('rb') as f:
    ar = MPQArchive(f)
    print(ar.has_listfile)
    ...
```