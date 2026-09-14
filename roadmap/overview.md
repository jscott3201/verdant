# Roadmap

[Back to README](../README.md) · [Current capabilities](../docs/capabilities.md) ·
[Evidence levels](../docs/evidence-levels.md)

Verdant is progressing from a local site foundation toward building operations.
This is milestone direction, not a release schedule or a claim that the planned
features are available. Each step needs its own evidence before its capabilities
can be relied on.

| Milestone | Direction | Status and boundary |
| --- | --- | --- |
| **M01 — Native site foundation** | Represent site meaning, store local state, and support a headless setup journey through validation, sealing and acceptance. | **Synthetic gate recorded.** Local fixtures exercise the foundation; this is not real-site native-semantic qualification or a complete application. |
| **M02 — Acquisition and writer** | Bring source acquisition and an observation-writing path into the local runtime. | **In progress.** The current runtime API is inert only. It does not read devices, persist field observations or send equipment commands. |
| **M03 — Faults and work** | Turn appropriately qualified observations into fault findings and corrective-work workflows, with evidence of resolution. | **Planned.** No operational fault-detection or corrective-work service is delivered today. |
| **M04 — Hub and history** | Coordinate sites and make retained history useful across the edge and hub. | **Planned.** Today's `edge` and `hub` roles are local shell configurations, not coordination or historian services. |
| **M05 — MCP** | Expose appropriately scoped capabilities to agent tools through a Model Context Protocol interface. | **Planned.** No MCP surface or agent authority is delivered today. |
| **M06 — Operations** | Bring the foundations together for operator workflows, qualified human equipment control and evidence of outcomes. | **Planned.** No equipment control or physical-safety qualification is available in this checkout. |

## Boundaries throughout

- Structural meaning, accepted configuration and a running process are not
  observed qualification or authorization to act on equipment.
- Synthetic credentials and fixtures are not real authentication, real-site
  evidence or a substitute for deployment-specific safety decisions.
- Current evidence remains macOS / arm64 / debug only. Future milestones do not
  imply additional platform, durability, conformance or performance guarantees.

For what you can run locally now, start with the
[README quick start](../README.md#quick-start). For the distinction between
compiled code, isolated tests and readiness, read
[evidence levels](../docs/evidence-levels.md).
