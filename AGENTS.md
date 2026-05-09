# AGENTS.md

## Agent Architecture Overview

This project follows the Domain-Driven Design (DDD) pattern and implements the Chain of Responsibility pattern for agent logic and request handling.

### Domain-Driven Design (DDD)
- **Bounded Contexts:** Each domain concept is encapsulated in its own module or component.
- **Entities & Value Objects:** Core business logic is modeled using entities and value objects.
- **Aggregates:** Aggregates enforce business invariants and transactional consistency.
- **Repositories:** Data access is abstracted via repository interfaces.

### Chain of Responsibility Pattern
- **Request Handling:** Agents are organized in a chain, where each agent can handle a request or pass it to the next agent in the chain.
- **Extensibility:** New agents can be added to the chain without modifying existing code, promoting open/closed principle.

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
- **Always run `cargo fmt` and `cargo clippy --all -- -D warnings` before committing**
- **Code must not contain any formatting errors or clippy warnings/errors**

## File Conventions
- `AGENTS.md`: Documents agent architecture and design patterns
- `CHANGELOG.md`: All changes must be recorded here
- `Cargo.toml` and `src/`: Standard Rust project structure

---

*This file should be updated if the agent architecture or project rules change.*
