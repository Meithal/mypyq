import os
import pathlib
from pprint import pprint as pp
from typing import Tuple
from logic import utils

tpls = {}


def process_templates(path: pathlib.Path, key):
    utils.trace(path, type(path))
    # with path / 'templates' as tpl_path:
    for cat in utils.parse_folder(path / 'templates'):
        # with tpl_path / cat as catpath:
        for tpl in (t for t in os.listdir(cat) if t.endswith('.html')):
            tpls[(key, cat), tpl.split('.')[0]] = open(cat / tpl).read()


def add_project(project):
    process_templates(pathlib.Path('.') / 'projects' / project, project)


def get_template(cat: Tuple[str, str], tpl):
    return tpls.get((cat, tpl), "Didn't find any matching template")


def recurse_replace(kwargs, domain, name):
    recur = RecurReplacementHandler(kwargs, get_template(domain, name), domain)
    return get_template(domain, name).format_map(recur)


class RecurReplacementHandler(dict):

    def __init__(self, initial_values, content, domain):
        super().__init__(initial_values)

        self.initial_values = initial_values
        self.content = self.trunced = content
        if isinstance(domain, tuple):
            self.site, self.area = domain
        else:
            self.site = 'global'
            self.area = domain

    def __missing__(self, item):

        if item.startswith("export_"):
            _, domain, name, key = item.split("_")

            self.trunced = self.content.replace(
                "{{export_{domain}_{name}_{key}}}".format(domain=domain, name=name, key=key), ""
            )
            self.initial_values[key] = self.trunced
            self.initial_values['$to_remove'] += len(self.trunced)

            return recurse_replace(self.initial_values, (self.site, domain), name)
        else:
            return "{{{item}}}".format(item=item)

    def __getitem__(self, item):
        if item not in self:
            return self.__missing__(item)
        return "{{{item}}}".format(item=item)


class FinalReplacerHandler(dict):
    def __missing__(self, key):
        return f"&lt;&lt;&lt;missing {key} >>>"


def parse(domain: Tuple[str, str], name: str, **kwargs):
    kwargs['$to_remove'] = 0
    inter = recurse_replace(kwargs, domain, name)[:-kwargs['$to_remove']]
    final = inter.format_map(FinalReplacerHandler(kwargs)).format_map(FinalReplacerHandler(kwargs))
    return final
