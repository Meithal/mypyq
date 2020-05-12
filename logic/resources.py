import time
import typing
import dataclasses
import pathlib
import asyncio

import aiohttp.web as aiow
import aioredis

from logic.utils import trace


async def rename_prefix(app: aiow.Application, from_: str, to: str):
    import re

    redis: aioredis.Redis = app['redis']
    async for key in redis.iscan(match=f'{from_}:*'):
        await redis.rename(key, re.sub(from_, to, key.decode('utf8'), count=1))


class Ourdict(dict):

    def __init__(self, *vals, **kwargs):
        print("init")
        super().__init__(*vals, **kwargs)


async def load_redis_resources(app: aiow.Application, key: typing.Tuple[str, ...]):
    redis = app['redis']

    redis_key = '_'.join(map(lambda k: k.lower(), key))
    class_name = ''.join(map(lambda k: k.capitalize(), key))

    resource_key = next(v[0] for v in Resource.resources_types.items() if v[1].__name__ == class_name)

    async for red_key in redis.iscan(match=f'{resource_key}:*'):

        resource: Resource = getattr(Resource.resources_types[resource_key], 'from_redis_hash_key')(red_key)
        async for name, val in redis.ihscan(red_key):
            setattr(resource, name.decode('utf8'), val.decode('utf8'))

        app['resources'].set_resource(red_key.decode('utf8'), resource)

        resource.after_redis_load()
        resource.final_after_redis_load()

    trace(app['resources'])


@dataclasses.dataclass()
class Resource:
    resources_types: typing.ClassVar[typing.Dict[str, typing.Type['Resource']]] = {}
    views: typing.ClassVar[typing.Dict[str, aiow.View]] = {}
    _resource_fully_loaded = False
    _created_at = None
    templates: typing.ClassVar[typing.Dict[str, str]] = {}
    project: typing.ClassVar[str] = ""
    key: typing.ClassVar[typing.Tuple[str, ...]] = ""
    discriminant: typing.ClassVar[str] = ""

    def __init_subclass__(cls, aiohttp_app: aiow.Application, discriminant: str, **kwargs):
        cls.aiohttp_app = aiohttp_app
        cls.discriminant = discriminant
        print("init a resource", cls, kwargs)

        _, project, _, key = cls.__module__.split('.')
        cls.project = project
        cls.key = key.split("_")
        Resource.resources_types[f"{project}:{cls.__name__}"] = cls
        path = pathlib.Path(cls.__module__.replace('.', '/') + '.py')
        for file in path.parent.iterdir():
            if file.suffix == '.html':
                model, key = file.stem.split('-')
                if model == path.stem:
                    with file.open() as f:
                        cls.templates[key] = f.read()
        views = cls.views
        for _, val in views.items():
            pattern, instance, name = val.values()
            instance.resource_type = cls
            aiohttp_app.router.add_view(pattern, instance, name=name)

        super().__init_subclass__(**kwargs)

    @property
    def persistent_name(self):
        return f"{getattr(self, self.discriminant)}"

    @property
    def short_discriminant(self):
        return getattr(self, self.discriminant).split(':')[-1]

    def after_redis_load(self):
        if self._created_at is None:
            self._created_at = time.time_ns()

    def final_after_redis_load(self):
        self._resource_fully_loaded = True

    @property
    def created_at_getter(self):
        return self._created_at


class ResourcesProxy(dict):
    def __init__(self, app: typing.ForwardRef('ResourcefulApp')):
        self.resources = {}
        self.app = app
        self.redis = None
        super().__init__()

    def __getitem__(self, item):
        if item not in self:
            return None
        return dataclasses.asdict(self.resources[item], dict_factory=Ourdict)

    async def _ensure_redis(self):
        while 'redis' not in self.app:
            await asyncio.sleep(2)
        self.redis = self.app['redis']

    def get_resource(self, k) -> Resource:
        return self.resources[k]

    def set_resource(self, key: str, instance: Resource):
        self.resources[key] = instance

    def get_resource_safe(self, k) -> Ourdict:
        return self[k]

    async def rename_resource(self, redis, old, new):
        await self._ensure_redis()
        await redis.rename(old, new)
        self.resources[new] = self.resources.pop(old)

    async def update_resource(self, resource_key: str, mapping: dict):
        await self._ensure_redis()
        dc = self.resources[resource_key]
        values = {k: v for k, v in mapping.items() if k in (f.name for f in dataclasses.fields(dc))}

        self.redis.hmset_dict(dc.persistent_name, values)

        for k, v in mapping.items():
            setattr(dc, k, v)



class ResourcefulApp(aiow.Application):

    @property
    def resources(self) -> ResourcesProxy:
        return self["resources"]
