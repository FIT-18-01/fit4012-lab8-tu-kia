# Lab 8 - Peer review response

## Nhóm được review

- Tên nhóm: tu kia
- Người review: Không có review chính thức

## Góp ý nhận được

1. Cần hoàn thiện phần mã hóa DES key bằng RSA-OAEP và giải mã trên Receiver.
2. Cần kiểm tra SHA-256 để phát hiện dữ liệu bị sửa đổi.
3. Cần nộp log minh chứng Sender/Receiver và xóa các chỗ TODO trong báo cáo.

## Phản hồi và chỉnh sửa

| Góp ý | Phản hồi của nhóm | File/commit đã sửa |
|---|---|---|
| Cần hoàn thiện phần mã hóa RSA-OAEP. | Đã hoàn thiện `secure_transfer_utils.py`, `sender.py`, `receiver.py` để mã hóa/deskey và giải mã dữ liệu theo yêu cầu Lab 8. | `secure_transfer_utils.py`, `sender.py`, `receiver.py` |
| Cần kiểm tra SHA-256 và packet tamper. | Đã thêm test cho SHA-256, packet format, tampered hash/ciphertext. | `tests/test_lab8_crypto.py`, `tests/test_lab8_packet.py` |
| Cần nộp log demo và xóa TODO document. | Đã tạo sample logs trong `logs/` và cập nhật README, report, peer-review response. | `logs/sender_success.log`, `logs/receiver_success.log`, `README.md`, `report-1page.md`, `peer-review-response.md` |

## Tự đánh giá sau chỉnh sửa

- Chương trình chạy được demo Sender/Receiver: Có
- Có kiểm tra SHA-256: Có
- Có mã hóa DES key bằng RSA-OAEP: Có
- Có test cho packet/tamper: Có
- Có log minh chứng: Có
