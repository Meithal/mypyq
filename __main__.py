import os
import logging
import pathlib
import asyncio
import typing
import importlib

import sass
from aiohttp import web as aiow
print("foo")
from logic import utils, templating
import settings
trace = utils.trace


templating.load_files(pathlib.Path('.'), templating.ProjectName('global'))
templating.add_project(settings.project)

rp = pathlib.Path('.')
projectPath = rp / 'projects' / settings.project

print("foo")

async def listen_to_sass_changes(app):
    def _compile():
        try:
            sass.compile(dirname=(projectPath / 'scss', rp / '_css'), output_style='expanded')
            sass.compile(dirname=(rp / 'scss', rp / '_css'), output_style='expanded')
        except Exception as e:
            trace("sass compilation failed", e)

    trace("sass listener started")
    _compile()
    sassfiles: typing.Dict[pathlib.Path, os.stat_result] = {
        f: 0
        for f in (projectPath / 'scss').iterdir()
    }
    for f in sassfiles:
        sassfiles[f] = f.stat()
    trace("scss files", list(sassfiles))
    while True:
        await asyncio.sleep(2.0)
        for f in sassfiles:
            stats = f.stat()
            if sassfiles[f].st_mtime < stats.st_mtime:
                trace(f, "has changed, recompiling...")
                _compile()
                sassfiles[f] = stats


async def start_sass_listener(app):
    app['sass_listener'] = asyncio.create_task(listen_to_sass_changes(app))


def is_static_request(request: aiow.Request):
    """Checks if the route capturing the request is a static file handler"""

    return isinstance(request.match_info.route.resource, aiow.StaticResource)


@aiow.middleware
async def add_custom_css(request, handler):

    if not is_static_request(request) and hasattr(request.match_info.route,
                                                  'resource') and request.match_info.route.resource is not None:
        path = request.match_info.route.resource.get_info().get('path', None)

        if path:
            extracss = path[1:] or "index"
            v = request.get('extra_css_hook', '')
            v += f"    <link href='_css/{extracss}.css' rel='stylesheet' type='text/css'>\n"
            request['extra_css_hook'] = v
    resp = await handler(request)
    return resp


@aiow.middleware
async def add_debug_bar(request, handler):
    v = request.get('extra_css_hook', '')
    v += f"    <link href='_css/debug.css' rel='stylesheet' type='text/css'>\n"
    request['extra_css_hook'] = v
    request['extra_html_hook'] = "<ol id='debug_bar'>{}</ol>\n".format('\n'.join(f"<li><a href='{route.path}'>{route.path}</a></li>" for route in routes if isinstance(route, aiow.RouteDef)))
    return await handler(request)


@aiow.middleware
async def render_html(request, handler):
    # trace("render html hook start", request, handler)
    try:
        resp = await handler(request)
    except Exception as e:
        # trace(e)
        resp = e
    extra_css = request.get('extra_css_hook', '')
    extra_html = request.get('extra_html_hook', '')
    # trace("resp", resp, vars(resp))
    if not is_static_request(request) \
            and hasattr(resp, 'text'):   # no binarycontent (images)
        tplname = request.path[1:]
        trace("tplname", tplname)
        if not tplname:
            if templating.has_template(settings.project, settings.maincat, 'index'):
                folder = (settings.project, settings.maincat)
                tplname = 'index'
            else:
                folder = ('global', 'default')
        else:
            folder = (settings.project, settings.maincat)
        resp.text = templating.parse(
            folder,
            tplname or settings.default_template,
            extra_css=extra_css,
            title=f"{settings.project} - {tplname}",
            extra_html=extra_html,
            defcontent=resp.text
        )

        resp.headers['Content-Type'] = 'text/html'

    # print("resp2", resp.text)
    return resp


routes = aiow.RouteTableDef()


routes.static('/_css', rp / '_css')
routes.static('/assets', projectPath / 'assets')


def main():
    middlewares = [add_debug_bar, add_custom_css, render_html]
    trace("middlewares", middlewares)

    app = aiow.Application(middlewares=middlewares)

    app['projectPath'] = projectPath

    app.on_startup.append(start_sass_listener)
    for file in utils.parse_folder(projectPath / 'startup'):
        app.on_startup.append(
            getattr(importlib.import_module('projects.' + settings.project + '.startup.' + file.stem),
                    'middleware_reg')
        )

        app.on_shutdown.append(
            getattr(importlib.import_module('projects.' + settings.project + '.startup.' + file.stem),
                    'on_shutdown')
        )

    logging.basicConfig(level=logging.DEBUG)

    for filename in utils.parse_folder(projectPath / 'controllers'):
        module = importlib.import_module(f"projects.{settings.project}.controllers.{filename.stem}")
        module.View = routes.view(f"/{filename.stem}")(module.View)

    for project in {folder.name for folder in utils.yield_folders(rp / 'projects')} - {settings.project}:
        for filename in utils.parse_folder(rp / 'projects' / project / 'controllers'):
            module = importlib.import_module(f"projects.{project}.controllers.{filename.stem}")
            module.View = routes.view(f"/{project}/{filename.stem}")(module.View)
            if filename.stem == 'index':
                module.View = routes.view(f"/")(module.View)  # make index point onto /
        templating.add_project(project)

    trace("templates", list(templating.tpls))

    app.add_routes(routes)

    trace("routes", type(routes), list(routes))
    trace("routes dispatch", type(app.router.routes()), list(app.router.routes()))

    aiow.run_app(app)


if __name__ == '__main__':
    main()
