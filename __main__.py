import os
import logging
import pathlib
import asyncio
import typing
import importlib
import time
import datetime

import sass
from aiohttp import web as aiow, web_urldispatcher as aiowud
from logic import utils, templating, resources
import settings
trace = utils.trace


templating.load_files(pathlib.Path('.'), templating.ProjectName('global'))
templating.add_project(settings.project)

rp = pathlib.Path('.')
projectPath = rp / 'projects' / settings.project

if not (rp / '_css').exists():
    (rp / '_css').mkdir()


def yield_scss_folders(rootdir: pathlib.Path):
    for project in (rootdir / 'projects').iterdir():
        if not (project / 'scss').exists():
            continue
        yield project, project / 'scss'


def compile_sass():
    for css in (rp / '_css').iterdir():
        css.unlink()

    for project, scss_folder in yield_scss_folders(rp):

        for scss_file in scss_folder.iterdir():
            if scss_file.name.startswith('_'):
                continue
            try:
                css, sourcemap = sass.compile(
                    filename=str(scss_file),
                    source_map_filename=f"{scss_file.parent / (project.name + '_' + scss_file.stem)}.css.map",
                    source_map_root=f"../{project.name}/scss/",
                    source_comments=True,
                    include_paths=(
                        str(scss_folder) for _, scss_folder in yield_scss_folders(rp)
                    )
                )
            except Exception as e:
                trace("sass compilation failed", e)
                raise

            with open(rp / '_css' / f"{project.name}_{scss_file.stem}.css", 'w') as write_file:
                write_file.write(css)
            with open(rp / '_css' / f"{project.name}_{scss_file.stem}.css.map", 'w') as write_file:
                write_file.write(sourcemap)


async def listen_to_sass_changes(app):
    # todo: uee app?
    # todo extract the file watcher to reuse it for template reparsing
    trace("sass listener started")
    compile_sass()
    sass_files: typing.Dict[pathlib.Path, os.stat_result] = {
        f: 0
        for f in (projectPath / 'scss').iterdir()
    }
    for f in sass_files:
        sass_files[f] = f.stat()
    trace("scss files", list(sass_files))
    while True:
        await asyncio.sleep(2.0)
        for f in sass_files:
            stats = f.stat()
            if sass_files[f].st_mtime < stats.st_mtime:
                trace(f, "has changed, recompiling...")
                compile_sass()
                sass_files[f] = stats


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
    return typing.cast(typing.Tuple[str, str, str], tuple(path.split('/')))


@aiow.middleware
async def first_middleware(request, handler):

    request['_extra_css_hook'] = []
    request['_extra_html_hook'] = []
    request['start_time'] = time.time_ns()
    resp = await handler(request)

    return resp


@aiow.middleware
async def add_custom_css(request, handler):

    if isinstance(request.match_info.route.resource, aiowud.PlainResource):
        path = request.match_info.route.resource.url_for()
        extra_css = request.get('_extra_css_hook', [])

        if not isinstance(request.match_info.route.resource, aiowud.DynamicResource):
            project, cat, page = project_cat_page_from_path(request.path[1:])
        else:
            project, cat, page = settings.project, settings.maincat, settings.default_template

        if (rp / '_css' / f"{project}_common.css").exists():
            extra_css.append(f'_css/{project}_common.css')
        else:
            extra_css.append(f'_css/{projectPath.name}_common.css')
            # use default common if none is defined for current project

        pathcss = path.name and f"{project}_{path.name}.css" or f"{project}_index.css"
        if (rp / '_css' / pathcss).exists():
            extra_css.append(f"_css/{pathcss}")

        request['_extra_css_hook'] += extra_css

    if isinstance(request.match_info.route.resource, aiowud.DynamicResource):
        request['_extra_css_hook'].append(f'_css/{projectPath.name}_common.css')

    resp = await handler(request)
    return resp


@aiow.middleware
async def render_html(request: aiow.Request, handler):
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
        if not isinstance(request.match_info.route.resource, aiowud.DynamicResource):
            project, cat, page = project_cat_page_from_path(request.path[1:])
        else:
            project, cat, page = settings.project, settings.maincat, settings.default_template
        extra_vars = {key: val for key, val in request.items() if not key.startswith('_')}
        extra_vars.update({key: val for key, val in resp.items() if not key.startswith('_')})
        extra_vars['elapsed_time'] = datetime.timedelta(microseconds=(time.time_ns() - request['start_time']) / 1_000)
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


def all_projects() -> typing.Iterable[pathlib.Path]:
    for project in (rp / 'projects').iterdir():
        if project.name.startswith('_'):
            continue
        yield project


def all_statrup_files() -> typing.Iterable[typing.Tuple[pathlib.Path, pathlib.Path]]:
    for project in all_projects():
        if not (project / 'startup').exists():
            continue
        for file in utils.parse_folder(project / 'startup'):
            yield project, file


def all_controllers_files() -> typing.Iterable[typing.Tuple[pathlib.Path, pathlib.Path]]:
    for project in all_projects():
        if not (project / 'controllers').exists():
            continue
        for file in utils.parse_folder(project / 'controllers'):
            yield project, file


def all_models_files() -> typing.Iterable[typing.Tuple[pathlib.Path, pathlib.Path]]:
    for project in all_projects():
        if not (project / 'models').exists():
            continue
        for file in utils.parse_folder(project / 'models'):
            if file.suffix == '.py':
                yield project, file


def main():
    # todo: better errors messages?

    logging.basicConfig(level=logging.DEBUG)

    import mpyq
    import mypyq
    arch = mpyq.MPQArchive("projects/w3vault/maps/epicwar/AoS GT 2 v1.01.w3m", listfile=False)
    arch = mypyq.MPQArchive("projects/w3vault/maps/epicwar/AoS GT 2 v1.01.w3m")

    middlewares = [first_middleware, add_custom_css, render_html]
    trace("middlewares", middlewares)

    app = resources.ResourcefulApp(middlewares=middlewares)
    app['resources'] = resources.ResourcesProxy()

    dummy = importlib.import_module('dummy')
    dummy.app_holder = app

    app.on_startup.append(start_sass_listener)

    for project, file in all_statrup_files():
        mod_ = importlib.import_module('projects.' + project.name + '.startup.' + file.stem)

        if hasattr(mod_, 'on_startup'):
            app.on_startup.append(getattr(mod_, 'on_startup'))

        if hasattr(mod_, 'on_shutdown'):
            app.on_shutdown.append(getattr(mod_, 'on_shutdown'))

        if hasattr(mod_, 'middleware_reg'):
            app.middlewares.append(aiow.middleware(mod_.middleware_reg))

    for project, file in all_controllers_files():
        module = importlib.import_module(f"projects.{project.name}.controllers.{file.stem}")
        module.View = routes.view(f"/{project.name}/{file.stem}")(module.View)
        if project.name == settings.project:
            module.View = routes.view(f"/{file.stem}")(module.View)
            if file.stem == 'index':
                module.View = routes.view(f"/")(module.View)  # this makes index point onto /

    for project in all_projects():
        templating.add_project(project.name)

    for project, model in all_models_files():
        module = importlib.import_module(f"projects.{project.name}.models.{model.stem}")
        if hasattr(module, 'load_existing_resources'):
            app.on_startup.append(getattr(module, 'load_existing_resources'))
        if hasattr(module, 'shutdown_resource_manager'):
            app.on_shutdown.append(getattr(module, 'shutdown_resource_manager'))

    # registers pure template routes
    async def nooproute(_):
        return aiow.Response(text='')

    for tpl in [f"/{el[0]}/{el[2]}" for el in list(templating.tpls)]:
        if tpl not in plain_routes(routes):
            nooproute = routes.get(tpl)(nooproute)

    trace("templates", list(templating.tpls))

    app.add_routes(routes)

    trace("routes", list(routes))
    trace("routes dispatch", list(app.router.routes()))

    aiow.run_app(app)

    print("exiting")


if __name__ == '__main__':
    main()
