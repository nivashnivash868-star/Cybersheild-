# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

SOC analysts and security administrators operate monitoring, triage alerts, and respond to incidents. Employees use a security portal for advisories and reporting.

## Product Purpose

CYBERSHIELD AI is an enterprise security-operations platform connecting telemetry monitoring and threat detection to alerting, incident response, forensics, and employee-facing security workflows.

## Positioning

The platform brings operational security workflows together, from telemetry and detection through response and employee reporting.

## Operating Context

Security teams monitor telemetry, review alerts, investigate and respond to incidents, and use forensic information. Employees review security advisories and report suspicious activity.

## Capabilities and Constraints

- The product has a four-role access model.
- Clearly identify simulated telemetry and integrations; do not present them as live.
- Never expose raw secret values.
- The existing implementation uses React, TypeScript, and Vite for the frontend, and FastAPI and Python for the backend.

## Brand Commitments

- Preserve the CYBERSHIELD AI name.

## Evidence on Hand

- The repository README documents the platform's modules and workflows.
- The frontend and backend implementations are in `frontend/` and `backend/`.
- The README distinguishes simulated telemetry or integrations from production-connected services.

## Product Principles

- Connect detection to actionable security operations and incident response.
- Support both security-team workflows and employee-facing security reporting.
- Preserve role-scoped access.
- Distinguish simulated activity from live integrations.
- Keep secret values masked.
