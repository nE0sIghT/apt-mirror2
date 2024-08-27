import asyncio
import sys
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Optional, TypeVar

_T = TypeVar("_T")

try:
    import uvloop
    from uvloop import Loop

    # Copied from uvloop
    def _cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> None:
        # Copied from python/cpython

        to_cancel = asyncio.all_tasks(loop)
        if not to_cancel:
            return

        for task in to_cancel:
            task.cancel()

        loop.run_until_complete(asyncio.gather(*to_cancel, return_exceptions=True))

        for task in to_cancel:
            if task.cancelled():
                continue
            if task.exception() is not None:
                loop.call_exception_handler(
                    {
                        "message": "unhandled exception during asyncio.run() shutdown",
                        "exception": task.exception(),
                        "task": task,
                    }
                )

    if TYPE_CHECKING:
        # pylint: disable=unused-argument

        def run(  # type: ignore
            main: Coroutine[Any, Any, _T],
            *,
            loop_factory: Optional[Callable[[], Loop]] = uvloop.new_event_loop,
            debug: Optional[bool] = None,
        ) -> _T:  # type: ignore
            """The preferred way of running a coroutine with uvloop."""

        # pylint: enable=unused-argument
    else:

        def run(
            main: Coroutine[Any, Any, Any],
            *,
            loop_factory: Callable[
                [], asyncio.AbstractEventLoop
            ] = uvloop.new_event_loop,
            **run_kwargs: str,
        ):
            async def wrapper():
                # If `loop_factory` is provided we want it to return
                # either uvloop.Loop or a subtype of it, assuming the user
                # is using `uvloop.run()` intentionally.
                loop = asyncio.get_running_loop()
                if not isinstance(loop, Loop):
                    raise TypeError("uvloop.run() uses a non-uvloop event loop")
                return await main

            vi = sys.version_info[:2]

            if vi <= (3, 10):
                loop = loop_factory()
                try:
                    asyncio.set_event_loop(loop)
                    return loop.run_until_complete(wrapper())
                finally:
                    try:
                        _cancel_all_tasks(loop)
                        loop.run_until_complete(loop.shutdown_asyncgens())
                        if hasattr(loop, "shutdown_default_executor"):
                            loop.run_until_complete(loop.shutdown_default_executor())
                    finally:
                        asyncio.set_event_loop(None)
                        loop.close()

            elif vi == (3, 11):
                with asyncio.Runner(  # pylint: disable=no-member  # type: ignore
                    loop_factory=loop_factory, **run_kwargs
                ) as runner:  # type: ignore
                    return runner.run(wrapper())  # type: ignore

            else:
                return asyncio.run(  # pylint: disable=unexpected-keyword-arg
                    wrapper(),
                    loop_factory=loop_factory,  # type: ignore
                    **run_kwargs,
                )

    UVLOOP_AVAILABLE = True

except ImportError:
    UVLOOP_AVAILABLE = False  # type: ignore

    def run(main: Coroutine[Any, Any, Any]):
        return asyncio.run(main)
