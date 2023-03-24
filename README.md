# Mypyq

Mypypq is a rewrite of https://github.com/TheSil/mpyq.
It is meant to open hostile mpq's such as protected war3 maps.

## Usage
It can be used as a runpy module, eg `python -m mypyq`.

`python -m mypyq --help` to see usage.
`python -m mypyq --bat` to generate a .bat file on which you can simply drag and drop the mpqs you want to extract.

Then drag and drop the mpq files you want to have extracted onto the .bat file.

On unix you might be able to drag and drop your mpqs directly onto mypyq.py and it might work (not tested).

It can also be used as a library, eg 

```python

import pathlib
import mypyq

with pathlib.Path("your mpq path").open('rb') as f:
    ar = MPQArchive(f)
    print(ar.has_listfile)
    ...
```