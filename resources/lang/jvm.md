# JVM (Java / Kotlin) Security PoC Adapter

## 1. Target Resolution & Offline Execution
- Run Maven/Gradle offline inside `S/sandbox-fix/` (`mvn -o test` or `gradle --offline test`) using `MockMvc` or direct service calls — never open outbound connections.
- Use `VERISEC_POC:` JSON stdout markers if integrating with custom JUnit runners, or standard JUnit 5 tests naming the positive test `controlAuthorized...` and invariant test `unauthorized...Blocked`.

## 2. Concurrency (`RACE_DOUBLE_SPEND`)
Use `CyclicBarrier(n)` with `ExecutorService` (`Executors.newFixedThreadPool(n)`) and assert `AtomicInteger successCount.get() == 1`.
