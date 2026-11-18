# .NET (C#) Security PoC Adapter

## 1. Target Resolution & Offline Execution
- Run `dotnet test --no-restore` inside `S/sandbox-fix/` using `WebApplicationFactory` or direct service/controller unit calls (`TestServer`, in-memory EF Core / store).
- Name positive control method `ControlAuthorized...` and invariant breach method `Unauthorized...Blocked`, or emit `VERISEC_POC:{...}`.

## 2. Concurrency (`RACE_DOUBLE_SPEND`)
Use `CountdownEvent(n)` or `Task.WhenAll` across parallel `Task.Run` workers and assert only 1 redemption/withdrawal succeeds.
