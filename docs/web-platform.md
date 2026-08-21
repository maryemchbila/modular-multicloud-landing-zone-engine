# Local client Web platform

## Purpose

J3 exposes the existing Modular Multi-Cloud Landing Zone Automation Engine through a local browser interface. It selects a client, environment, provider and versioned infrastructure template, then runs generation, Terraform `fmt/init/validate/plan`, Security, Policy, Approval and Governance. It never deploys infrastructure.

## Architecture

Flask and Jinja2 form a thin presentation layer. `WebOrchestrationService` converts server-validated forms into the existing request models and validators. The CLI and Web entrypoints both call `run_governed_workflow`, which sequences the existing Go generator and final governance pipeline. The catalog accepts canonical template IDs only; neither users nor routes provide filesystem paths.

## Install and start

Python 3.14 is supported by the selected dependency ranges.

```powershell
python -m pip install -r requirements.txt
cd python-engine
python web_app.py
```

Open `http://127.0.0.1:5000`. The default listener is loopback-only.

## Pages and workflow

The navigation contains Dashboard, Client & Cloud, Infrastructure, Plan, Security, Governance and Reports. Configure `example-client`, an environment and GCP or OCI. The safe client view loads cloud identifiers, credential validation status and isolated state identity without exposing credential material. Select a provider-matched template in Infrastructure, complete its supported parameters, then use **Generate & Validate**.

Reports are listed from the fixed Security, Policy and Governance artifact roots. Report views use validated identifiers and remove local path fields.

## Credential and request safety

Templates receive an explicit safe view model, never credential objects or their dictionaries. The signed session contains selection IDs and a CSRF token only. All form actions use POST and server-side validation. GET requests never generate files or run Terraform. The catalog rejects traversal and arbitrary YAML paths.

## Terraform Plan workflow

The shared workflow runs generation followed by Terraform formatting, initialization, validation and plan, then the existing Security, Policy, Approval and Governance stages. UI results contain statuses, safe counts and sanitized findings, not raw state, credentials, subprocess output or full plan JSON.

## J3 safety boundary and J4

J3 has no Apply or Destroy controls. It performs no cloud write and no automatic approval. An `AUTHORIZED` result means only **Authorized for future Deployment Gate**; Terraform Apply remains `NOT EXECUTED`. J4 may add a separately controlled Deployment Gate, but it is outside this implementation.
