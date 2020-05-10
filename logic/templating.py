import pathlib
import string
from typing import Tuple, NewType, Dict
from logic import utils
from logic.utils import trace
import settings
import aiohttp.web as aiow

ProjectName = NewType('ProjectName', str)
CatName = NewType('CatName', str)
TplName = NewType('TplName', str)
TplKey = NewType('TplKey', Tuple[ProjectName, CatName, TplName])

tpls: Dict[TplKey, str] = {}


def gencsslinks(files, req: aiow.Request):
    return '\n'.join(f"    <link href='{req.scheme}://{req.host}/{cssf}' rel='stylesheet' type='text/css'>" for cssf in files)


def load_files(path: pathlib.Path, key: ProjectName):
    for cat in utils.parse_folder(path / 'templates'):
        for tpl in (t for t in cat.iterdir() if t.name.endswith('.html')):
            with open(str(tpl)) as content:
                tpls[key, CatName(cat.name), TplName(tpl.stem)] = content.read()


class _Catcher(dict):
    has_include: bool = False
    include_into: tuple
    include_key: str
    override_project: str = ""

    def __missing__(self, key):
        if key.startswith("export_"):
            self.has_include = True
            __, cat, name, keyv = key.split("_")
            self.include_into = cat, name
            self.include_key = keyv
            return ""

        if key == "_html":
            self.has_include = True
            self.include_into = 'default', 'default'
            # self.include_into = settings.project, settings.maincat
            self.include_key = 'contents'
            self.override_project = 'global'
            return ""

        return f"{{{key}}}"


class _InPlace(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


class _Runtime(dict):

    def __init__(self, seq, req, **kwargs):
        super().__init__(seq, **kwargs)
        self.req = req

    def __missing__(self, key):
        if key.startswith("_fun"):
            __, fun, data = key[1:].split('_')
            return globals()[fun](self[data], self.req)
        return ""


def template_text(project: str, cat: str, tpl: str) -> str:
    """convenient accessor with generic types"""
    return tpls.setdefault((project, cat, tpl), tpls[(settings.project, settings.maincat, settings.default_template)])


def add_project(project: str):
    load_files(pathlib.Path('.') / 'projects' / project, ProjectName(project))

    for key, content in tpls.items():
        catcher = _Catcher()
        text = MyFormatter().format(content).format_map(catcher)
        if catcher.has_include:
            include_into = template_text(
                catcher.override_project or project, catcher.include_into[0], catcher.include_into[1]
            )
            tpls[key] = MyFormatter().format(include_into).format_map(_InPlace({catcher.include_key: text}))


def has_template(site, cat, name):
    return (site, cat, name) in tpls


class MyFormatter(string.Formatter):
    def get_value(self, key, args, kwargs):
        # print("get key", key, args, kwargs)
        if isinstance(key, int):
            if key > len(args):
                args.append(None)
        else:
            if key not in kwargs:
                kwargs[key] = f"{{{key}}}"
        return super().get_value(key, args, kwargs)

    def convert_field(self, value, conversion):
        if conversion == 'm':
            return value.upper()
        else:
            return super().convert_field(value, conversion)

    def format_field(self, value, format_spec):
        if format_spec == 'gen_css_links':
            return super().format_field(str(value)[-2] + format_spec + '}', '')
        else:
            return super().format_field(value, format_spec)


def parse(request, cat=('global', 'default'), name='index', **data):
    inter = MyFormatter().format(template_text(cat[0], cat[1], name))
    rv = inter.format_map(_Runtime(data, request))
    return rv
