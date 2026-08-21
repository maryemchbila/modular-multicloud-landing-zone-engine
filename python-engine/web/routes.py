"""Routes sans effet de bord sur GET et actions internes exclusivement en POST."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

from catalog import CatalogError
from web.services import WebServiceError


web = Blueprint("web", __name__)


def _service():
    return current_app.extensions["web_orchestration"]


def _context_key() -> tuple[str, str, str]:
    return (
        session.get("client_id", ""),
        session.get("environment", ""),
        session.get("provider", ""),
    )


def _runtime(required: bool = False):
    client_id, environment, provider = _context_key()
    if not all((client_id, environment, provider)):
        if required:
            raise WebServiceError("Configure Client & Cloud first.")
        return None
    key = (client_id, environment, provider)
    runtime = current_app.extensions["web_runtimes"].get(key)
    if runtime is None and required:
        runtime = _service().load_runtime(client_id, environment, provider)
        current_app.extensions["web_runtimes"][key] = runtime
    return runtime


def _runtime_view():
    runtime = _runtime()
    return _service().safe_runtime_view(runtime) if runtime else None


def _result_view():
    return current_app.extensions["web_results"].get(_context_key())


@web.app_errorhandler(WebServiceError)
@web.app_errorhandler(CatalogError)
def handle_safe_error(error):
    return render_template("status.html", page_title="Request rejected", error=str(error)), 400


@web.app_errorhandler(ValueError)
def handle_validation_error(error):
    return render_template(
        "status.html",
        page_title="Request rejected",
        error="Server-side validation rejected the request.",
    ), 400


@web.get("/")
def dashboard():
    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        runtime=_runtime_view(),
        result=_result_view(),
    )


@web.route("/client", methods=["GET", "POST"])
def client():
    if request.method == "POST":
        client_id = request.form.get("client_id", "").strip()
        environment = request.form.get("environment", "").strip().casefold()
        provider = request.form.get("provider", "").strip().casefold()
        runtime = _service().load_runtime(client_id, environment, provider)
        runtime_key = (runtime.client_id, runtime.environment, runtime.provider)
        current_app.extensions["web_runtimes"][runtime_key] = runtime
        session.pop("template_id", None)
        session.update(
            {
                "client_id": runtime.client_id,
                "environment": runtime.environment,
                "provider": runtime.provider,
                "credential_profile_id": runtime.credential_profile.credential_id,
                "state_profile_id": runtime.state_profile.state_profile_id,
            }
        )
        return redirect(url_for("web.client"))
    return render_template("client.html", page_title="Client & Cloud", runtime=_runtime_view())


@web.route("/infrastructure", methods=["GET", "POST"])
def infrastructure():
    runtime = _runtime(required=request.method == "POST")
    provider = runtime.provider if runtime else session.get("provider", "gcp")
    templates = _service().catalog.list_templates(provider)
    selected_id = (
        request.form.get("template_id")
        if request.method == "POST"
        else request.args.get("template_id") or session.get("template_id")
    )
    selected = _service().catalog.get(selected_id) if selected_id else (templates[0] if templates else None)
    if selected is not None and selected.provider != provider:
        raise WebServiceError("Template provider does not match the selected provider.")
    if request.method == "POST":
        session["template_id"] = selected.template_id
        submitted = {
            key: value
            for key, value in request.form.items()
            if key not in {"csrf_token", "template_id"}
        }
        result = _service().execute(runtime, selected.template_id, submitted)
        current_app.extensions["web_results"][_context_key()] = result.view
        return redirect(url_for("web.result"))
    return render_template(
        "infrastructure.html",
        page_title="Infrastructure",
        runtime=_service().safe_runtime_view(runtime) if runtime else None,
        templates=templates,
        selected=selected,
    )


@web.get("/result")
def result():
    return render_template("result.html", page_title="Result", result=_result_view())


@web.get("/plan")
def plan():
    return render_template("status.html", page_title="Plan", section="plan", result=_result_view())


@web.get("/security")
def security():
    return render_template(
        "status.html",
        page_title="Security",
        section="security",
        result=_result_view(),
        baseline="INTERNAL_SECURITY_BASELINE",
    )


@web.get("/governance")
def governance():
    return render_template(
        "status.html", page_title="Governance", section="governance", result=_result_view()
    )


@web.get("/reports")
def reports():
    report_service = current_app.extensions["report_service"]
    return render_template(
        "reports.html",
        page_title="Reports",
        reports=report_service.list_reports(),
        runtime=_runtime_view(),
    )


@web.get("/reports/view/<report_type>/<report_id>")
def report_view(report_type: str, report_id: str):
    report_service = current_app.extensions["report_service"]
    report = report_service.read_report(report_type, report_id)
    return render_template(
        "reports.html",
        page_title="Report",
        reports=[],
        report=report,
        report_type=report_type,
    )
