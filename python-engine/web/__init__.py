"""Factory Flask de la plateforme Web locale."""

from __future__ import annotations

import hmac
import os
import secrets

from flask import Flask, abort, request, session

from web.services import ReportService, WebOrchestrationService


_SESSION_KEYS = frozenset(
    {
        "_csrf_token",
        "client_id",
        "environment",
        "provider",
        "credential_profile_id",
        "state_profile_id",
        "template_id",
    }
)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("MLZ_WEB_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        MAX_CONTENT_LENGTH=128 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    app.extensions["web_orchestration"] = WebOrchestrationService()
    app.extensions["report_service"] = ReportService()
    app.extensions["web_results"] = {}
    app.extensions["web_runtimes"] = {}

    @app.before_request
    def csrf_protection():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf_token", "")
            supplied = request.form.get("csrf_token", "") or request.headers.get(
                "X-CSRF-Token", ""
            )
            if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                abort(400, description="CSRF token is missing or invalid.")

    @app.after_request
    def enforce_safe_session(response):
        for key in tuple(session):
            if key not in _SESSION_KEYS:
                session.pop(key, None)
        return response

    @app.context_processor
    def inject_csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return {"csrf_token": token}

    from web.routes import web

    app.register_blueprint(web)
    return app
