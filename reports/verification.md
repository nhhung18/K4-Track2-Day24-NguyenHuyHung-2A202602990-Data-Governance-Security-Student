# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Linux x86_64 (Kernel 6.6.137+ / Ubuntu environment)
  - Python: 3.13.5 (trong virtual environment `.venv`)
  - Gitleaks: 8.30.1 (chính thức từ release binary, nằm trong PATH tại `~/.local/bin/gitleaks`)

- `python -m pytest tests/ -q`:
  - Kết quả: `33 passed in 0.25s`
  - 100% test suites passed bao gồm: `test_check_lure_cli`, `test_injection` (4 biến thể x 2 principals), `test_ledger`, `test_obo`, `test_pii` (recall 1.0, precision 1.0), `test_policy`, `test_scaffold_dispatch`, `test_split`, `test_supply_chain`.

- `pre-commit run --all-files`:
  - Kết quả: `Detect hardcoded secrets.................................................Passed`
  - Hook `gitleaks-system` (rev `v8.30.1`, `pass_filenames: false`) chạy thành công, working tree hoàn toàn sạch secret.

- Ledger verify:
  - Lệnh kiểm tra: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi sha256 hash chain liên tục, mọi entry đều có `reason` hợp lệ và `prev_hash` chuẩn xác).

- Các lỗi còn lại:
  - Không có lỗi nào còn tồn đọng. Hệ thống đáp ứng đầy đủ tất cả các tiêu chí trong RUBRIC.md và CHECKPOINTS.md:
    - Baseline attack thành công trước containment (`reports/attack-before.log` có PII của `KH-000999`).
    - Sau containment, `reports/attack-after.log` rỗng (0 bytes).
    - Trifecta Split và OBO hoạt động chuẩn xác: `support_l1` bị chặn đọc PII nhạy cảm, `dpo` vẫn phục vụ được khách hàng hợp lệ gắn với ticket.
    - Cả 4 biến thể lure đều sẵn sàng (`check_lure` 4/4) và bị chặn sau containment.
