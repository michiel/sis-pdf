# Architecture: sis-pdf

This document defines the high-level design, architectural constraints, and security principles for the **sis-pdf** ecosystem. It serves as the primary technical reference for maintainers and contributors.

---

## 1. Design Philosophy

The development of **sis-pdf** is guided by three non-negotiable pillars:

* **Zero-Trust Input**: All external data—CLI arguments, environment variables, and configuration files—is treated as hostile. No input is trusted until it has been sanitised and validated against strict internal schemas.
* **Total Reliability**: The use of `unwrap()`, `expect()`, or any logic that triggers a panic is strictly prohibited. All fallible operations must use structured error handling and propagation.
* **Self-Contained Portability**: The tool aims for minimal runtime dependencies. Documentation and assets are interned at compile-time to ensure a single, portable binary.

---

## 2. Workspace Structure

The project is structured as a **Cargo Workspace** to consolidate dependency versions and ensure no duplication of crates across the system.

| Crate | Responsibility |
| --- | --- |
| **`sis-pdf-cli`** | Entry point, `clap` argument parsing, configuration loading, and terminal output formatting. |
| **`sis-pdf-storage`** | Persistence layer using **SeaORM** and **SQLite**. Manages migrations, entities, and data access. |
| **`sis-pdf-core`** | Shared domain logic, internal traits, and the centralised error hierarchy. |
| **`sis-pdf-discovery`** | Management of internalised strings and documentation logic for `describe` commands. |

---

## 3. Data Persistence

**sis-pdf** uses a local-first persistence model.

* **Engine**: [SeaORM](https://www.sea-ql.org/) (an async ORM built on `sqlx`).
* **Backend**: **SQLite** is used as the starting point for ease of distribution and zero-configuration requirements.
* **Encapsulation**: All database logic is isolated within the `sis-pdf-storage` crate. Other crates must interact with data via defined service methods rather than raw SQL or ORM entities.

---

## 4. Error Handling and Propagation

We use a structured, hierarchical approach to error management. Every crate defines its own error enum using the `thiserror` crate, ensuring that errors are both descriptive and type-safe.

1. **Definitions**: Errors are categorised by domain (e.g., `StorageError`, `ConfigError`).
2. **Propagation**: The `?` operator is used exclusively to bubble errors up to the caller.
3. **No Panics**: Any operation that could fail must return a `Result`.
4. **User Reporting**: Only the `sis-pdf-cli` crate is permitted to format and print errors to the user.

---

## 5. Configuration and Environment

The system prioritises a predictable configuration hierarchy.

* **Location**: Platform-dependent user storage is determined via the `dirs` crate.
* **Linux/macOS**: `~/.config/proj/config.toml`
* **Windows**: `AppData\Roaming\proj\config.toml`


* **Priority**:
1. Explicit command-line flags (e.g., `--config <FILE>`).
2. Environment variables.
3. The local `config.toml` file.


* **Format**: All configuration is stored in **TOML** and deserialised using `serde`.

---

## 6. Observability

Tracing and logging are critical for debugging without polluting user data.

* **Crate**: [tracing](https://github.com/tokio-rs/tracing).
* **Destination**: All diagnostic logs are emitted to **STDERR**.
* **Default Level**: Initialised at the `WARN` level to remain quiet during standard operations unless an issue is detected or the user explicitly increases verbosity.

---

## 7. Discovery Commands

To facilitate onboarding and usage, the CLI includes discovery commands that serve embedded documentation.

* **Commands**: `proj describe usage`, `proj describe walkthrough`.
* **Implementation**: Documentation files are written in Markdown and interned into the binary at compile-time using the `include_str!` macro.
* **Output**: The contents are streamed to **STDOUT**, allowing for integration with standard Unix pagers.

---

## 8. Technical Decision Log (ADR)

| Decision | Selection | Justification |
| --- | --- | --- |
| **Spelling** | Australian English | Standardises internal naming and documentation (e.g., `initialise`, `sanitise`). |
| **Crates** | Rust Native | Minimises "foreign" code to ensure memory safety and easier cross-compilation. |
| **Input** | Hostile Posture | Prevents common vulnerabilities such as path traversal or SQL injection. |
| **Logging** | STDERR | Separates application data from diagnostic information for better piping/redirection. |

