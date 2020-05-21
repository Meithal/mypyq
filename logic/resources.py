import time
import typing
import dataclasses
import pathlib
import asyncio

import aiohttp.web as aiow
import aioredis

from logic.utils import trace


class Ourdict(dict):

    def __init__(self, *vals, **kwargs):
        print("init")
        super().__init__(*vals, **kwargs)


class ResourceKey(str):
    def __init__(self, value):

        if ":" not in value:
            raise ValueError("Resource key should be fully qualified")

        super().__init__()


class ResourcesProxy(dict):
    """
    This is a bridge to the resources store of the app, the resources are a collection of datasets
    We also handle the persistence, with the lest round trips possible
    """
    def __init__(self, app: typing.ForwardRef('ResourcefulApp')):
        self.resources = {}
        self.app = app
        self.redis: aioredis.Redis
        super().__init__()

    def __getitem__(self, item):
        if item not in self:
            return None
        return dataclasses.asdict(self.resources[item], dict_factory=Ourdict)

    async def _ensure_redis(self):
        while 'redis' not in self.app:
            await asyncio.sleep(2)
        self.redis = self.app['redis']

    def get_resource(self, k: typing.Union[ResourceKey, bytes]) -> typing.ForwardRef('Resource'):
        if type(k) is bytes:
            k = k.decode()
        if k not in self.resources:
            return None
        return self.resources[k]

    async def loop_through(self, key):
        async for k in self.redis.iscan(match=f"{key}:*"):
            yield self.get_resource(k)

    async def rename_resource(self, old, new):
        await self._ensure_redis()
        await self.redis.rename(old, new)
        self.resources[new] = self.resources.pop(old)

        return self.resources[new]

    async def batch_resource(
            self,
            resource_key: ResourceKey,
            mapping: typing.Dict[str, str],
            existing_dataclass: dataclasses.dataclass = None
    ):
        await self._ensure_redis()
        dc = self.get_resource(resource_key)
        was_created = False
        if not dc:
            project, rtype, disc = resource_key.split(":")
            if not existing_dataclass:
                dc = Resource.resources_types[f"{project}:{rtype}"](redis_key=disc)
                self.resources[dc.persistent_name] = dc
            else:
                dc = existing_dataclass
                setattr(existing_dataclass, 'redis_key', resource_key)
                self.resources[dc.persistent_name] = dc
            was_created = True

        if mapping:
            values = {k: str(v) for k, v in mapping.items() if k in (f.name for f in dataclasses.fields(dc))}

            await self.redis.hmset_dict(str(dc.persistent_name), values)

            for k, v in mapping.items():
                setattr(dc, k, v)

        if was_created:
            await dc.after_resource_load()

        return dc


class ResourcefulApp(aiow.Application):

    @property
    def resources(self) -> ResourcesProxy:
        return self["resources"]


async def rename_prefix(app: aiow.Application, from_: str, to: str):
    import re

    redis: aioredis.Redis = app['redis']
    async for key in redis.iscan(match=f'{from_}:*'):
        await redis.rename(key, re.sub(from_, to, key.decode('utf8'), count=1))


async def load_redis_resources(app: ResourcefulApp, key: typing.Tuple[str, ...]):
    while 'redis' not in app:
        await asyncio.sleep(2)

    redis = app['redis']

    class_name = ''.join(map(lambda k: k.capitalize(), key))

    resource_key = next(v[0] for v in Resource.resources_types.items() if v[1].__name__ == class_name)

    async for red_key in redis.iscan(match=f'{resource_key}:*'):
        await app.resources.batch_resource(
            ResourceKey(red_key.decode()), await redis.hgetall(red_key, encoding='utf-8')
        )

    trace(app['resources'])


@dataclasses.dataclass()
class Resource:
    resources_types: typing.ClassVar[typing.Dict[str, typing.Type['Resource']]] = {}
    views: typing.ClassVar[typing.Dict[str, aiow.View]] = {}
    _created_at = None
    templates: typing.ClassVar[typing.Dict[str, str]] = {}
    project: typing.ClassVar[str] = ""
    key: typing.ClassVar[typing.Tuple[str, ...]] = ""
    discriminant: typing.ClassVar[str] = ""
    aiohttp_app: typing.ClassVar[ResourcefulApp] = None

    def __init_subclass__(cls, aiohttp_app: ResourcefulApp, discriminant: str, **kwargs):
        cls.aiohttp_app = aiohttp_app
        cls.discriminant = discriminant

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
    def persistent_name(self) -> ResourceKey:
        return ResourceKey(f"{self.project}:{self.__class__.__name__}:{getattr(self, self.discriminant)}")

    @classmethod
    def make_persistent_name(cls, name: str) -> ResourceKey:
        return ResourceKey(f"{cls.project}:{cls.__name__}:{name}")

    @classmethod
    async def loop_through(cls):
        async for resource in cls.aiohttp_app.resources.loop_through(f"{cls.project}:{cls.__name__}"):
            yield resource

    async def after_resource_load(self):
        """Expects all the dataclass fields to be set"""
        if self._created_at is None:
            self._created_at = time.time_ns()
