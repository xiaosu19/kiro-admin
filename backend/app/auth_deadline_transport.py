"""Deadline-scoped transport for a native CAPTCHA image or answer request.

The native adapter still validates destinations, prepares cookies/body, commits
write intent, parses AWS responses and records password uncertainty. This module
only bounds the wire wait, including streaming and DNS, without another thread
continuing a credential write after the caller has returned.
"""
import asyncio
import time

import httpx
import requests


def send(prepared, session, *, proxy, guard, deadline, limit):
    async def wire():
        guard()
        async with httpx.AsyncClient(proxy=proxy, trust_env=False, follow_redirects=False,
                timeout=max(.001, deadline - time.monotonic()), cookies=session.cookies) as client:
            headers = dict(prepared.headers)
            headers["Accept-Encoding"] = "identity"
            async with client.stream(prepared.method, prepared.url, headers=headers,
                                     content=prepared.body) as incoming:
                if incoming.headers.get("content-encoding", "identity").lower() != "identity":
                    raise requests.RequestException("unsupported authentication encoding")
                body = bytearray()
                async for chunk in incoming.aiter_bytes(chunk_size=4096):
                    guard()
                    if len(body) + len(chunk) > limit:
                        raise requests.RequestException("authentication response too large")
                    body.extend(chunk)
                guard()
                outgoing = requests.Response()
                outgoing.status_code, outgoing.url = incoming.status_code, prepared.url
                outgoing.headers = requests.structures.CaseInsensitiveDict(incoming.headers)
                outgoing._content, outgoing._content_consumed = bytes(body), True
                for cookie in client.cookies.jar:
                    session.cookies.set_cookie(cookie)
                return outgoing

    async def watch():
        while True:
            guard()
            await asyncio.sleep(.2)

    async def bounded():
        if deadline <= time.monotonic():
            raise requests.Timeout("authentication deadline exceeded")
        task = watcher = None
        try:
            async with asyncio.timeout(deadline - time.monotonic()):
                task, watcher = asyncio.create_task(wire()), asyncio.create_task(watch())
                done, _ = await asyncio.wait((task, watcher), return_when=asyncio.FIRST_COMPLETED)
                if watcher in done:
                    await watcher
                return await task
        except TimeoutError:
            raise requests.Timeout("authentication deadline exceeded") from None
        except httpx.HTTPError:
            raise requests.RequestException("authentication transport failed") from None
        finally:
            pending = [value for value in (task, watcher) if value is not None]
            for value in pending:
                value.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    # asyncio.run waits for cancelled getaddrinfo threads on shutdown. Closing
    # this private loop cancels HTTP work without extending the caller's deadline.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(bounded())
    finally:
        loop.close()
