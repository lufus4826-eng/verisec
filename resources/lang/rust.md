# Rust Security PoC Adapter

## 1. Target Resolution & Offline Execution
- Run `cargo test --offline` inside `S/sandbox-fix/` (`CARGO_NET_OFFLINE=true` is automatically set by `vs.py`).
- Test Axum/Actix handlers via `tower::ServiceExt::oneshot` or `actix_web::test::call_service` strictly in-memory without binding external sockets.
- Name positive control test `test_control_authorized_*` and invariant test `test_unauthorized_*_blocked` (or emit `VERISEC_POC:{...}`).

## 2. Concurrency (`RACE_DOUBLE_SPEND`)
Use `std::sync::Barrier` (`Arc::new(Barrier::new(n))`) across spawned threads or `tokio::sync::Barrier` across async tasks and assert `success_count == 1`.
