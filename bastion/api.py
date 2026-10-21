import json
import re
import time
from collections import deque

from aiohttp import web

from . import VERSION
from .loader import bootstrap, public_url
from .store import AccessDenied


def make_app(store, base_url, clock=time.monotonic):
    base_url = public_url(base_url)
    buckets = {}

    @web.middleware
    async def controls(request, handler):
        if request.path.startswith("/v1/"):
            now = clock()
            identity = request.remote or "unknown"
            for key in list(buckets):
                if not buckets[key] or buckets[key][-1] <= now - 60:
                    del buckets[key]
            if identity not in buckets and len(buckets) >= 1000:
                return web.json_response({"error": "Server busy. Try later."}, status=429)
            queue = buckets.setdefault(identity, deque())
            while queue and queue[0] <= now - 60:
                queue.popleft()
            if len(queue) >= 60:
                return web.json_response({"error": "Too many requests. Wait one minute."}, status=429, headers={"Retry-After": "60"})
            queue.append(now)
        try:
            response = await handler(request)
        except AccessDenied as exc:
            response = web.json_response({"error": str(exc)}, status=403)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            response = web.json_response({"error": "Invalid request."}, status=400)
        except web.HTTPException as exc:
            response = web.json_response({"error": exc.reason}, status=exc.status)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app = web.Application(client_max_size=8192, middlewares=[controls])

    def script_id(request):
        value = request.match_info["script_id"]
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            raise AccessDenied("Script unavailable.")
        return value

    async def health(request):
        return web.json_response({"service": "A3K Bastion", "version": VERSION, "status": "online"})

    async def loader(request):
        script = store.script(script_id(request), enabled=True)
        return web.Response(text=bootstrap(base_url, script), content_type="text/plain", charset="utf-8")

    async def authenticate(request):
        if request.content_type != "application/json":
            raise ValueError("JSON required")
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("JSON object required")
        token = store.authenticate(script_id(request), body["key"], body["device"])
        return web.json_response({"access_token": token, "expires_in": 60})

    async def payload(request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise AccessDenied("Authorization required.")
        source = store.consume(script_id(request), auth[7:], request.headers.get("X-Bastion-Device", ""))
        return web.Response(body=source, content_type="text/plain", charset="utf-8")

    app.router.add_get("/", health)
    app.router.add_get("/health", health)
    app.router.add_get("/v1/loader/{script_id}", loader)
    app.router.add_post("/v1/auth/{script_id}", authenticate)
    app.router.add_get("/v1/payload/{script_id}", payload)
    return app
