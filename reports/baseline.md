# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Trong `agent/loop.py` tại hàm `_naive_loop()` (dòng 27–54), agent chỉ nhận `message: str` và `llm`, hoàn toàn không khởi tạo hoặc gán định danh `agent_id`, `run_id` hay gắn với bất kỳ principal identity nào từ `data/principals.json` (tham số `principal_id` từ CLI bị bỏ qua).

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có ai cho phép hay kiểm soát. Trong `agent/loop.py` tại hàm `_naive_loop()` (dòng 44), lệnh `tools.http_post(injected.target_url, {"records": collected})` được thực thi trực tiếp mà không đi qua bất kỳ Policy Enforcement Point (PEP) hay cơ chế phân quyền nào (`agent/policy.py` hoàn toàn không được import hay gọi tới). Bất kỳ URL nào do payload injection chỉ định (`injected.target_url`) đều được agent tự động gọi.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bên trong agent hoàn toàn không có bằng chứng hay cơ chế audit ledger nội bộ nào ghi lại việc gọi tool hay rò rỉ dữ liệu. Bằng chứng duy nhất nằm ở phía server nhận ngoài luồng tại file `reports/sink.log`, do hàm `make_handler.Handler.do_POST()` trong `sink/sink.py` (dòng 45–47) ghi lại nội dung HTTP request nhận được. Nếu sink ở bên ngoài localhost hoặc không ghi log, toàn bộ vụ rò rỉ sẽ không để lại bất kỳ dấu vết kiểm toán nào.
