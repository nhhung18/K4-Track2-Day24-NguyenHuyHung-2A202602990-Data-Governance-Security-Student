# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks phiên bản v8.30.1 (`gitleaks version 8.30.1`), thực thi quét lịch sử thông qua lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .`.

- Commit chứa token giả:
  Commit `1bdd849` (full commit hash: `1bdd849922156c868a5ee9293d68f5b72e242d2c`), commit bởi VinUni AI20k Lab ngày 2026-10-09T16:22:06Z.

- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` tại dòng 1.
  - Rule ID: `lab24-synthetic-token` (mô tả: "A deliberately invalid lab token; never use real credentials", regex: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`).
  - Kết quả quét lịch sử: Tìm thấy 1 leak (WRN leaks found: 1) với exit code 1.

- Kết quả quét file hiện tại:
  Lệnh `gitleaks dir --config .gitleaks.toml .` và hook pre-commit `gitleaks-system` trên working tree hiện tại báo sạch (no leaks found, 0 findings, exit code 0). File chứa token giả đã được xoá khỏi HEAD ở commit kế tiếp.

- Nếu đây là credential thật, cần xử lý thế nào:
  Nếu đây là credential thật, quy trình ứng phó sự cố bắt buộc là:
  1. Ngay lập tức thu hồi (revoke) và rotate credential đó tại nhà cung cấp / IAM / service tương ứng.
  2. Kiểm tra access log / audit log của dịch vụ xem credential đã bị bên thứ ba lạm dụng chưa.
  3. Xoá triệt để credential khỏi toàn bộ lịch sử Git bằng các công cụ rewrite history (như `git-filter-repo` hoặc BFG Repo-Cleaner) và force push lại các nhánh.
  4. Cập nhật secret mới vào Secret Manager an toàn và phân phối lại cho các thành phần hợp lệ.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ làm file không còn xuất hiện ở commit hiện tại, nhưng toàn bộ nội dung và commit cũ vẫn nằm nguyên vẹn trong lịch sử Git (`.git` object database). Bất kỳ ai clone hoặc pull repo về đều có thể checkout commit cũ hoặc dùng `git log`/`git show` để lấy được secret.
  - Pin dependency và pre-commit hook chỉ bảo vệ chuỗi cung ứng khỏi dependency tampered và ngăn chặn việc vô tình commit secret mới trong tương lai. Chúng không thể làm vô hiệu hóa hay thu hồi (rotate) một secret đã từng bị lộ ra ngoài. Do đó, bước thu hồi/rotate secret tại nguồn là biện pháp duy nhất đảm bảo an toàn thực chất khi secret đã lộ.
