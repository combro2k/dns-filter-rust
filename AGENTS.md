# AGENTS.md

## Agent Architecture Overview

This project follows Clean Architecture with DDD-style domain modeling and uses Chain of Responsibility in the request processing pipeline.

### Clean Architecture Structure
- **entities:** Pure domain model and business rules. No framework or I/O dependencies.
- **use_cases:** Application orchestration and policy. Depends on entities.
- **interface_adapters:** Protocol and boundary adapters (DNS, DoT, DoH, DoQ, HTTP).
- **frameworks:** External systems and drivers (config loading, logging, metrics, upstream I/O).

### Dependency Rule
- Dependencies point inward only.
- `entities` must not depend on any other project layer.
- `use_cases` can depend only on `entities`.
- `interface_adapters` can depend on `use_cases` and `entities`.
- `frameworks` can depend on adapters/use_cases/entities, but they must not leak framework concerns back into entities.

### Source Layout (Target)
```text
src/
    entities/
    use_cases/
    interface_adapters/
    frameworks/
        config/
        plugin_runtime/   # cfg(feature = "plugins")
```

### Protocol Scope
- DNS UDP/TCP
- DNS over TLS (DoT)
- DNS over HTTPS (DoH)
- DNS over QUIC (DoQ)
- HTTP admin/metrics
- MCP (Model Context Protocol) via Streamable HTTP

### Chain of Responsibility Pattern
- **Placement:** Implemented inside use-case orchestration.
- **Request Handling:** Processing stages should be chained with explicit pass/short-circuit behavior.
- **Extensibility:** New handlers should be composable without modifying existing handlers.

#### Example (Pseudocode)
```rust
trait AgentHandler {
    fn handle(&self, request: Request) -> Option<Response>;
}

struct ConcreteAgentA { next: Option<Box<dyn AgentHandler>> }
impl AgentHandler for ConcreteAgentA {
    fn handle(&self, request: Request) -> Option<Response> {
        if self.can_handle(&request) {
            // handle request
        } else if let Some(ref next) = self.next {
            next.handle(request)
        } else {
            None
        }
    }
}
```

## Project Rules
- **Always add changes to `CHANGELOG.md`**
- **Always add cargo tests if implementing a new feature**
- **Always run `tests/release-check.sh` before committing**
- **Code must not contain any formatting errors or clippy warnings/errors**
- **Always run `./tests/listener_batch_test.sh` after finishing changes**
- **Reject changes that invert layer dependencies**
- **Keep `AGENTS.md` synchronized with structural module changes**

## AI Agent Role

The coding agent in this repository acts as a security-first software engineer.

### Responsibilities
- Prioritize secure-by-default design and implementation choices.
- Review every change for security flaws, misuse paths, and unintended side effects.
- Analyze concurrent code for race conditions, deadlocks, and TOCTOU risks.
- Follow the `Project Rules` section as the single source of truth for changelog, testing, quality gates, and architecture-boundary constraints.

## Security-First Engineering Requirements

All code changes must be designed, implemented, and reviewed with a security-first mindset.

### Mandatory Security Review Checklist
- Define threat model and trust boundaries for new or changed components.
- Validate and sanitize all untrusted inputs.
- Prevent injection risks (command, SQL, template, header, and path traversal).
- Enforce authentication and authorization consistently.
- Apply least privilege for runtime permissions and external access.
- Avoid exposing secrets or sensitive data in logs, errors, or metrics.
- Fail securely (no fail-open behavior on errors or timeouts).
- Protect against denial-of-service and resource exhaustion.
- Review dependency and supply-chain risk for new crates and features.
- Add and maintain tests for abuse cases and malformed inputs.

### Concurrency and Race-Condition Requirements
- Explicitly review for data races, deadlocks, starvation, and lock contention.
- Avoid TOCTOU flaws around filesystem, config reload, and shared state.
- Ensure concurrent request paths are deterministic and safe under load.
- Minimize shared mutable state; prefer immutable data and message passing.
- Document synchronization strategy where shared state is unavoidable.
- Add concurrency-focused tests for critical paths.

## File Conventions
- `AGENTS.md`: Documents agent architecture and design patterns
- `CHANGELOG.md`: All changes must be recorded here
- `Cargo.toml` and `src/`: Standard Rust project structure

## Release and Compliance Requirements

- **Changelog is mandatory for every version update**: Each version update **MUST** be documented in `CHANGELOG.md` with a clear summary of what changed.
- **Version is mandatory for every version update**: `Cargo.toml` **MUST** have the exact same version.
- **Version update workflow is mandatory**: A version update **MUST** explicitly include all of the following steps:
    - Update the version in all required files (`Cargo.toml`, `README.md` version badge, `README.md` footer "Current Version" line). If the exact target version is assumed rather than provided, explicitly ask the user to confirm the version before proceeding.
    - If the user asks for a version update without specifying a target version, calculate and suggest:
        - Next minor version (`x.x.(y+1)`) as the default/recommended option.
        - Next major version (`(x+1).0.0`) as an alternative option.
            Present these choices using an input selector (interactive option picker), with next minor preselected/recommended, while still allowing explicit freeform version input.
      Always ask for explicit confirmation before applying any version change.
    - Commit scope policy for version updates: All files, including version-update files.
    - Create a Git tag for the version.
    - Push only when the user explicitly asks for a push.
- **Release validation is mandatory**: `bash tests/release-check.sh` **MUST** be run and pass without errors on every version update.
    - `cargo clean` is conditional inside the script and only runs when relevant code/assets/test/migration paths changed.
- **No personal or private information in the codebase**:
    - The repository **MUST NOT** contain personal/private data or secrets.
    - This includes (but is not limited to): tokens, passwords, usernames, API keys, credentials, private identifiers, or similar sensitive values.

---

*This file should be updated if the agent architecture or project rules change.*
