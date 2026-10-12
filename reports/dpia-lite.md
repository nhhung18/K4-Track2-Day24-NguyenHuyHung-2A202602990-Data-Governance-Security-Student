# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- **Dữ liệu ticket hỗ trợ (`corpus/*.md`):** Phân loại `internal`. Chứa nội dung yêu cầu hỗ trợ, phản hồi đối soát của khách hàng.
- **Dữ liệu hồ sơ khách hàng (`data/customers.json`):** Phân loại `restricted`. Chứa thông tin PII nhạy cảm: Họ tên, Số CCCD (12 chữ số), Số điện thoại (10 chữ số), Số tài khoản ngân hàng (STK), Địa chỉ email.
- **Tính chất dữ liệu:** Toàn bộ là dữ liệu tổng hợp (synthetic data), định dạng mã khách hàng `KH-xxxxxx`, phục vụ bài thực hành an toàn bảo mật; không chứa dữ liệu cá nhân thật của bất kỳ cá nhân nào.

2. Mục đích xử lý và principal:
- **Mục đích xử lý:**
  - `summarize-tickets`: Tổng hợp các yêu cầu, trạng thái ticket đang mở trong tuần để phục vụ báo cáo vận hành.
  - `support-reply`: Hỗ trợ tra cứu thông tin khách hàng gắn với ticket cụ thể để xử lý phản hồi khiếu nại.
  - `privacy-audit`: Kiểm toán tuân thủ chính sách bảo vệ dữ liệu và quyền riêng tư.
- **Principals (danh tính mô phỏng từ `data/principals.json`):**
  - `support_l1`: Nhân viên hỗ trợ kỹ thuật cấp 1. Chỉ được phép gọi `search_docs`, bị cấm truy cập `read_customer` nhằm tuân thủ nguyên tắc đặc quyền tối thiểu (least privilege).
  - `billing`: Nhân viên đối soát tài chính. Được phép gọi `search_docs` và `read_customer` cho mục đích đối soát tài khoản.
  - `dpo`: Chuyên viên bảo vệ dữ liệu (Data Protection Officer). Được phép truy cập hồ sơ khách hàng hợp lệ gắn với ticket để thẩm tra và kiểm toán.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Run A (`lab24-agent/run-a`):**
  - Thực thi tool `search_docs(message)` để quét kho ticket `corpus/`.
  - Chạy bộ lọc PII `agent/pii.py:redact()` để che giấu các trường CCCD/SĐT/STK/Email nếu có.
  - Trích xuất danh sách số nguyên `ticket_id` từ tên tệp (vd: `ticket-901.md` -> `901`). Chỉ truyền dữ liệu định kiểu (typed list[int]) sang Run B; loại bỏ hoàn toàn free text của người dùng/kẻ tấn công tại ranh giới Run A.
- **Run B (`lab24-agent/run-b`):**
  - Nhận typed `ticket_ids` từ Run A, đối chiếu với nguồn dữ liệu cấu trúc tin cậy `data/customers.json:related_tickets` để suy ra `customer_id` hợp lệ.
  - Gọi tool `read_customer(customer_id)` chỉ khi được Policy Enforcement Point (PEP) cho phép (cho phép với `dpo`, từ chối với `support_l1`).
- **Endpoint Egress:**
  - Kẻ tấn công cố tình chỉ định đích exfiltration tại `http://127.0.0.1:10024/reconcile`.
  - PEP chặn tuyệt đối tool `http_post` khi phân loại là `restricted` và `egress_enabled=True`. Không có bất kỳ payload nào được chuyển ra ngoài.

4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng allow/deny:**
  - Trước containment: `reports/attack-before.log` ghi lại dữ liệu PII của `KH-000999` bị rò rỉ ra sink do `_naive_loop` thiếu cơ chế kiểm soát.
  - Sau containment: `reports/attack-after.log` hoàn toàn rỗng sau khi hoàn tất pipeline với `--as dpo`.
  - Phân quyền OBO: `reports/ledger.jsonl` ghi nhận các bản ghi `decision: "deny"` đối với `tool: "read_customer"` cho `support_l1`, và `decision: "allow"` cho `dpo`.
  - Chặn egress: `reports/ledger.jsonl` ghi nhận `decision: "deny"` đối với `tool: "http_post"` với lý do cụ thể: `"Deny: restricted data classification with egress enabled is prohibited"`.
- **Giới hạn của mock:**
  - `MockLLM` là mô hình deterministic mô phỏng hành vi nhận diện injection dựa trên danh sách từ khoá và mẫu cấu trúc trong phạm vi bài lab.
  - Mock không thể hiện được tính bất định (non-deterministic) và các biến thể ngôn ngữ ngữ cảnh tinh vi của các mô hình LLM tiên tiến trong thực tế.
  - Cơ chế xác thực qua tham số `--as` chỉ mang tính giả lập phân quyền RBAC/ABAC trong nội bộ tiến trình, không thay thế cho hạ tầng xác thực danh tính phân tán (OAuth2/OIDC, mTLS, JWT, IAM/KMS).
