import os
import logging
import pathlib
import asyncio
import typing
import importlib

import sass
from aiohttp import web as aiow, web_urldispatcher as aiowud
from logic import utils, templating
import settings
trace = utils.trace


templating.load_files(pathlib.Path('.'), templating.ProjectName('global'))
templating.add_project(settings.project)

rp = pathlib.Path('.')
projectPath = rp / 'projects' / settings.project

if not (rp / '_css').exists():
    (rp / '_css').mkdir()


async def listen_to_sass_changes(app):
    def _compile():

        for css in (rp / '_css').iterdir():
            css.unlink()
        for project in (rp / 'projects').iterdir():

            if not (project / 'scss').exists():
                continue

            for scss_file in (project / 'scss').iterdir():
                if scss_file.name.startswith('_'):
                    continue
                try:
                    css, sourcemap = sass.compile(
                        filename=str(scss_file),
                        source_map_filename=f"{scss_file.parent / (project.name + '_' + scss_file.stem)}.css.map",
                        source_map_root=f"../{project.name}/scss/",
                        source_comments=True,
                    )
                except Exception as e:
                    trace("sass compilation failed", e)
                    raise

                with open(rp / '_css' / f"{project.name}_{scss_file.stem}.css", 'w') as write_file:
                    write_file.write(css)
                with open(rp / '_css' / f"{project.name}_{scss_file.stem}.css.map", 'w') as write_file:
                    write_file.write(sourcemap)

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


def project_cat_page_from_path(path: str) -> typing.Tuple[str, str, str]:
    if not path:
        if templating.has_template(settings.project, settings.maincat, 'index'):
            return settings.project, settings.maincat, 'index'

        return 'global', 'default', 'default'
    if '/' not in path:
        return settings.project, settings.maincat, path
    if path.count('/') < 2:
        project, page = path.split('/')
        return project, "site", page
    return tuple(path.split('/'))


@aiow.middleware
async def add_custom_css(request, handler):

    if isinstance(request.match_info.route.resource, aiowud.PlainResource):
        path = request.match_info.route.resource.url_for()
        extra_css = request.get('_extra_css_hook', [])

        project, cat, page = project_cat_page_from_path(path.path[1:])

        if (rp / '_css' / f"{project}_common.css").exists():
            extra_css.append(f'_css/{project}_common.css')
        else:
            extra_css.append(f'_css/{projectPath.name}_common.css')
            # use default common if none is defined for current project

        trace(path, extra_css)
        pathcss = path.name or f"{project}_index.css"
        if (rp / '_css' / pathcss).exists():
            extra_css.append(f"_css/{pathcss}")

        trace(path, extra_css)

        if '_extra_css_hook' in request:
            request['_extra_css_hook'] += extra_css
        else:
            request['_extra_css_hook'] = extra_css

    resp = await handler(request)
    return resp


@aiow.middleware
async def render_html(request, handler):
    try:
        resp = await handler(request)
    except Exception as e:
        trace(e, request)
        raise e
    extra_css = request.get('_extra_css_hook', '')
    extra_html = request.get('_extra_html_hook', '')
    if not is_static_request(request) \
            and hasattr(resp, 'text'):   # no binarycontent (images)
        tplname = request.path[1:] or 'index'
        project, cat, page = project_cat_page_from_path(request.path[1:])
        extra_vars = {key: val for key, val in request.items() if not key.startswith('_')}
        resp.text = templating.parse(
            request,
            (project, cat),
            page,
            extracss=extra_css,
            title=f"{settings.project} - {tplname}",
            extra_html=extra_html,
            defcontent=resp.text,
            **extra_vars
        )

        resp.headers['Content-Type'] = 'text/html'

    return resp


routes = aiow.RouteTableDef()


routes.static('/_css', rp / '_css')
routes.static('/assets', projectPath / 'assets')
for project_route in utils.yield_folders(rp / 'projects'):
    routes.static(f"/{project_route.name}/scss", project_route / 'scss')


def plain_routes(routes_: [aiow.RouteDef]):
    return [route.path for route in routes_ if isinstance(route.path, str)]


def nooproute(_):
    return aiow.Response(text='')


def main():
    logging.basicConfig(level=logging.DEBUG)

    middlewares = [add_custom_css, render_html]
    trace("middlewares", middlewares)

    app = aiow.Application(middlewares=middlewares)

    app['projectPath'] = projectPath

    app.on_startup.append(start_sass_listener)

    for project in (rp / 'projects').iterdir():

        if not (project / 'startup').exists():
            continue

        for file in utils.parse_folder(project / 'startup'):

            globals()[f"{project.name}_startup_{file.stem}"] = importlib.import_module(
                'projects.' + project.name + '.startup.' + file.stem
            )

            temp = globals()[f"{project.name}_startup_{file.stem}"]

            if hasattr(temp, 'task_reg'):
                app.on_startup.append(
                    getattr(temp, 'task_reg')
                )

            if hasattr(temp, 'on_shutdown'):
                app.on_shutdown.append(
                    getattr(temp, 'on_shutdown')
                )

            if hasattr(temp, 'middleware_reg'):
                app.middlewares.append(aiow.middleware(temp.middleware_reg))

            trace(globals()[f"{project.name}_startup_{file.stem}"])

    for project in {folder.name for folder in utils.yield_folders(rp / 'projects')}:
        for filename in utils.parse_folder(rp / 'projects' / project / 'controllers'):
            module = importlib.import_module(f"projects.{project}.controllers.{filename.stem}")
            module.View = routes.view(f"/{project}/{filename.stem}")(module.View)
            if project == settings.project:
                module.View = routes.view(f"/{filename.stem}")(module.View)
                if filename.stem == 'index':
                    module.View = routes.view(f"/")(module.View)  # this makes index point onto /

        templating.add_project(project)

    global nooproute
    for tpl in [f"/{el[0]}/{el[2]}" for el in list(templating.tpls)]:
        if tpl not in plain_routes(routes):
            nooproute = routes.get(tpl)(nooproute)

    trace("templates", list(templating.tpls))

    app.add_routes(routes)

    trace("routes", type(routes), list(routes))
    trace("routes dispatch", type(app.router.routes()), list(app.router.routes()))

    aiow.run_app(app)


if __name__ == '__main__':
    main()
