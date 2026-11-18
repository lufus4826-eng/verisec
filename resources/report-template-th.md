# แม่แบบรายงานความปลอดภัย VeriSec (ภาษาไทย — Lazy-Load เฉพาะ Phase 6)

> **คำแนะนำ:** คัดลอกตั้งแต่ใต้เส้นแบ่งลงไปเขียนที่ `S/sec-report.md` ใส่ให้ครบทั้ง 7 หัวข้อ (ถ้าหัวข้อไหนว่างให้เขียน `"ไม่มี"`) **ห้ามลบหัวข้อทิ้ง** ใช้ข้อมูลจริงจาก `vs.py summary --snippets`, Diff จาก `vs.py sandbox --mode diff` และผลสแกนจาก `vs.py redact-output --scan` เท่านั้น

---

# รายงานการตรวจสอบช่องโหว่ลอจิกและสิทธิ์รั่ว (VeriSec Security Advisory)

## ข้อมูลเซสชัน (Session Metadata)
- **รหัสเซสชัน (`S`):** `.bughunt/<SNAME>/`
- **โฟลเดอร์โปรเจกต์ (`ROOT`):** `<path>`
- **ขอบเขตที่ตรวจ:** <ทั้งโปรเจกต์ หรือ โมดูลที่ระบุ>
- **มาตรการความปลอดภัยและการกรองข้อมูล:** แยกเครือข่ายภายนอก 100% (`VERISEC_OFFLINE=1` / `VERISEC_NET_GUARD`) | ปกปิดข้อมูลลับอัตโนมัติ (`redact-output`) | ยืนยันผล 2 ชั้น (Dual Gate)
- **สถานะรายงาน:** ฉบับสมบูรณ์ (Final Complete)

---

## 1. บทสรุปผู้บริหารและตัวชี้วัด Dual-Gate

| ตัวชี้วัด | ผลลัพธ์ | หมายเหตุ |
|---|---:|---|
| เส้นทาง API / Handler ที่สแกนพบ | <N> | ตรวจด้วย `vs.py surface-map` |
| จุดเสี่ยงทางลอจิกที่ถูกคัดกรอง | <N> | `IDOR_BOLA` / `MISSING_AUTH_GUARD` / `MASS_ASSIGNMENT` / `RACE_DOUBLE_SPEND` |
| **ช่องโหว่ที่ยืนยันจริงและอุดสำเร็จ** | **<N>** | ผ่านทั้ง Gate 1 และ Gate 2 ใน `S/sandbox-fix` |
| **สมมติฐานที่ระบบป้องกันไว้แล้ว (`REFUTED_SAFE`)** | **<N>** | Gate 1 ยืนยันว่าบล็อกได้ตั้งแต่โค้ดเดิม (กันผลลวง) |
| **แพตช์ที่เข้มเกิน/ทำของเดิมพังและถูกย้อนกลับ** | **<N>** | คืนโค้ดอัตโนมัติด้วย `verify --auto-rollback` |
| **ข้อมูลลับ/โทเคนที่ถูกปกปิดอัตโนมัติ** | **<N>** | `[REDACT-SCAN]` unredacted remaining = `0` |

---

## 2. แผนผังเส้นทาง API และตารางสิทธิ์ (`surface-map`)

| Endpoint / Handler | ตำแหน่งโค้ด | ตัวกรองสิทธิ์ (Auth Guards) | จุดรับข้อมูลภายนอก | หมวดความเสี่ยง | ระดับความสำคัญ |
|---|---|---|---|---|---|
| `<symbol>` | `<file:line>` | `<guards หรือ NONE>` | `<inputs>` | `<tags หรือ SAFE>` | `<HIGH/MED/LOW>` |

---

## 3. ช่องโหว่ที่ยืนยันจริงและอุดเรียบร้อยแล้ว (ผ่าน Gate 1 + Gate 2)

<!-- ทำซ้ำตามจำนวนช่องโหว่ที่ CONFIRMED_REMEDIATED -->

### <ID>: <ชื่อสรุปช่องโหว่> (`<CATEGORY>`)
- **ระดับความรุนแรง:** <Critical / High / Medium / Low>
- **ตำแหน่งโค้ด:** [`<relative/path:line>`](<relative/path>) `<symbol>`
- **ต้นตอและกลไกการเจาะ:** <อธิบายเหตุผลที่ลอจิกเดิมหลุดสิทธิ์หรือทำรายการซ้ำซ้อนได้>
- **ผลตรวจ Dual Gate:**
  - **ด่านที่ 1 (Gate 1 — ยืนยันช่องโหว่จริง):** เคสควบคุมผู้มีสิทธิ์ = `PASS` | ผลเจาะบนโค้ดเดิม = `BREACH_CONFIRMED` | แยกเครือข่าย = `ENFORCED`
  - **ด่านที่ 2 (Gate 2 — ยืนยันแพตช์ & ไม่กระทบของเดิม):** ผลเจาะหลังแก้ = `BREACH_BLOCKED` | เคสควบคุมผู้มีสิทธิ์ = `PASS` | เทสต์รวมของโปรเจกต์ = `<PASS>`
- **สคริปต์ PoC แบบปิดตาย:** [`<S>/pocs/<file>`](<S>/pocs/<file>)

#### หลักฐาน PoC ที่ผ่านการปกปิดความลับแล้ว (Baseline vs. Remediation)
```text
<คัดลอก snippet จาก vs.py summary --snippets (ห้ามมีโทเคน/รหัสผ่านดิบ)>
```

#### โค้ดแก้ไขที่ยืนยันใน Sandbox (Sandbox-Verified Unified Diff)
```diff
<คัดลอก Unified Diff ที่กรองความลับแล้วจาก vs.py sandbox --mode diff>
```

---

## 4. รายการผลลวงที่คัดทิ้ง (`REFUTED_SAFE`) และแพตช์ที่ถูกย้อนกลับอัตโนมัติ

> VeriSec คัดกรองผลลวงด้วย Gate 1 (`REFUTED_SAFE`) และย้อนกลับแพตช์ที่แก้เข้มเกินไปจนผู้ใช้ปกติใช้งานไม่ได้หรือทำเทสต์พังด้วย Gate 2 (`--auto-rollback`)

| ID | หมวดความเสี่ยง | ผลลัพธ์ | เคสควบคุม | สถานะการเจาะ | การจัดการ / เหตุผล |
|---|---|---|---|---|---|
| <ID หรือ ไม่มี> | <CATEGORY> | <REFUTED_SAFE / REJECTED_CONTROL_BROKEN / REJECTED_TEST_REGRESSION> | <PASS/FAIL> | <status> | <AUTO_RESTORED / โค้ดเดิมกันไว้แล้ว> |

---

## 5. บันทึกการแยกเครือข่ายและการปกปิดความลับ
- **การแยกเครือข่าย (`isolated-poc`):** `<ENFORCED — VERISEC_OFFLINE=1 + sitecustomize socket guard, 0 external connections>`
- **ผลการตรวจจับความลับคงค้าง (`vs.py redact-output --s "$S" --scan`):** `<[REDACT-SCAN] files=N scrubbed_files=M masked=K unredacted_remaining=0 status=CLEAN>`

---

## 6. ความสะอาดของพื้นที่ทำงาน (Workspace Cleanliness)
- **ไฟล์ Snapshot:** `<S>/logs/fs-before.txt`, `<S>/logs/fs-after.txt`
- **ผลการตรวจ:** `<cleanliness: CLEAN (ไม่มีไฟล์นอก .bughunt/ เปลี่ยนแปลง)>`
- **ไฟล์ส่งมอบที่เก็บไว้:** `<S>/sec-report.md`, `<S>/worklog.md`, `<S>/pocs/`, `<S>/logs/`

---

## 7. บันทึกการนำแพตช์ขึ้นระบบจริง (Applied Security Patches Log)
> อัปเดตเฉพาะเมื่อผู้ใช้อนุมัติให้แก้โค้ดจริงในโปรเจกต์แล้วเท่านั้น

| วันเวลา | ID | ไฟล์ที่แก้ | เทสต์โปรเจกต์จริง | ยืนยัน PoC ในพื้นที่ปิด | สถานะ |
|---|---|---|---|---|---|
| ไม่มี | - | - | - | - | รอผู้ใช้อนุมัติ |
