import os
import pathlib


def _get_templates():
    # todo: recompile template if changed

    templates = {}
    with pathlib.Path('.') / 'templates' as tplpath:
        for cat in {*os.listdir(tplpath)} - {'__init__.py', '__pycache__'}:
            with tplpath / cat as catpath:
                for tpl in (t for t in os.listdir(catpath) if t.endswith('.html')):
                    templates[cat, tpl.split('.')[0]] = open(catpath / tpl).read()

    return templates


tpls = _get_templates()


def get_template(cat, tpl):
    return tpls[cat, tpl]


def recurse_replace(kwargs, domain, name):
    recur = RecurReplacementHandler(kwargs, get_template(domain, name))
    return get_template(domain, name).format_map(recur)


class RecurReplacementHandler(dict):

    def __init__(self, initial_values, content):
        super().__init__(initial_values)

        self.initial_values = initial_values
        self.content = self.trunced = content

    def __missing__(self, item):

        if item.startswith("export_"):
            _, domain, name, key = item.split("_")
            self.trunced = self.content.replace(
                "{{export_{domain}_{name}_{key}}}".format(domain=domain, name=name, key=key), ""
            )
            self.initial_values[key] = self.trunced
            self.initial_values['$to_remove'] += len(self.trunced)

            return recurse_replace(self.initial_values, domain, name)
        else:
            return "{{{item}}}".format(item=item)

    def __getitem__(self, item):
        if item not in self:
            return self.__missing__(item)
        return "{{{item}}}".format(item=item)


class FinalReplacerHandler(dict):
    def __missing__(self, key):
        return f"&lt;&lt;&lt;missing {key} >>>"


def parse(domain, name, **kwargs):
    kwargs['$to_remove'] = 0
    inter = recurse_replace(kwargs, domain, name)[:-kwargs['$to_remove']]
    final = inter.format_map(FinalReplacerHandler(kwargs)).format_map(FinalReplacerHandler(kwargs))
    return final
