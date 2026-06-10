# Phân Chia Công Việc — Đồ Án AES-128 & Padding Oracle Attack

> **Nhóm:** Lê Gia Bảo & An — Đại học Bách Khoa Hà Nội (HUST)

---

## 📊 Tổng Quan

| Thành viên | Vai trò chính | File phụ trách |
|:---:|---|---|
| **An** | Cài đặt lõi thuật toán AES-128 (toán học, mật mã) | `aes128.js` |
| **Bảo** | Mô phỏng tấn công Padding Oracle & demo | `padding_oracle_demo.js` |

---

## 🔐 An — `aes128.js` (Lõi AES-128)

Phụ trách toàn bộ file `aes128.js` — cài đặt thuật toán AES-128 từ bảng tra cứu đến mã hóa/giải mã khối.

### 1. Bảng Tra Cứu Tĩnh
| Mục | Mô tả |
|---|---|
| `SBOX` | Bảng S-Box 16×16 — phép thế phi tuyến (Confusion) |
| `INV_SBOX` | Bảng Inverse S-Box 16×16 — dùng cho giải mã |
| `RCON` | Hằng số vòng Rcon — dùng trong Key Expansion |

### 2. Tiện Ích Hiển Thị
| Hàm | Mô tả |
|---|---|
| `bytesToHex()` | Chuyển mảng byte → chuỗi hex |
| `printState()` | In ma trận trạng thái 4×4 dạng hex |

### 3. Quản Lý Trạng Thái & Phép Thế Phi Tuyến
| Hàm | Mô tả |
|---|---|
| `bufferToState()` | Nạp 16 byte → State matrix (column-major) |
| `stateToBuffer()` | Xuất State matrix → mảng 16 byte |
| `subBytes()` | Phép thế phi tuyến dùng S-Box |
| `invSubBytes()` | Phép thế ngược dùng Inverse S-Box |
| `addRoundKey()` | XOR State với khóa vòng |

### 4. Biến Đổi Đại Số & Trường Hữu Hạn GF(2⁸)
| Hàm | Mô tả |
|---|---|
| `shiftRows()` | Dịch vòng trái các hàng (Diffusion) |
| `invShiftRows()` | Dịch vòng phải các hàng (giải mã) |
| `galoisMultiply()` | Phép nhân trong GF(2⁸) với đa thức tối giản P(x)=x⁸+x⁴+x³+x+1 |
| `mixColumns()` | Trộn cột với ma trận cố định [02 03 01 01] |
| `invMixColumns()` | Trộn cột ngược với ma trận [0E 0B 0D 09] |

### 5. Mở Rộng Khóa (Key Expansion)
| Hàm | Mô tả |
|---|---|
| `keyExpansion()` | Mở rộng khóa 128-bit → 11 khóa vòng (176 byte), gồm RotWord, SubWord, XOR Rcon |

### 6. Mã Hóa & Giải Mã Khối
| Hàm | Mô tả |
|---|---|
| `encryptBlock()` | Mã hóa 1 khối 16 byte — 10 vòng (9 vòng đầy đủ + vòng cuối không MixColumns) |
| `decryptBlock()` | Giải mã 1 khối 16 byte — 10 vòng ngược |
| `getRoundKey()` | Trích xuất khóa vòng từ expanded key (debug) |

### 7. Demo (trong `require.main === module`)
- Mã hóa & giải mã khối với plaintext `HUST_A+_Grade_12`
- In chi tiết từng vòng (verbose mode)
- Kiểm tra khớp plaintext gốc ↔ giải mã

---

## ⚔️ Bảo — `padding_oracle_demo.js` (Tấn Công & Demo)

Phụ trách toàn bộ file `padding_oracle_demo.js` — mô phỏng hệ thống có lỗ hổng Padding Oracle và kịch bản tấn công.

### 1. Tiện Ích
| Hàm | Mô tả |
|---|---|
| `bytesToHex()` | Chuyển Buffer → chuỗi hex |
| `xorBuffers()` | XOR hai Buffer cùng độ dài |

### 2. PKCS#7 Padding
| Hàm | Mô tả |
|---|---|
| `pkcs7Pad()` | Thêm byte đệm PKCS#7 vào plaintext |
| `pkcs7Unpad()` | Gỡ byte đệm + kiểm tra tính hợp lệ |

### 3. AES-128-CBC (Tự Cài Đặt)
| Hàm | Mô tả |
|---|---|
| `aes128cbcEncrypt()` | Mã hóa AES-128-CBC dùng class `AES128` của An |
| `aes128cbcDecrypt()` | Giải mã AES-128-CBC dùng class `AES128` của An |

### 4. Victim Server (Hệ Thống Có Lỗ Hổng)
| Lớp | Mô tả |
|---|---|
| `VictimServer` | Server giả lập với khóa bí mật ngẫu nhiên |
| `getEncryptedSecret()` | Mã hóa tin nhắn, trả về IV + ciphertext (thứ hacker nghe lén được) |
| `checkPadding()` | **Lỗ hổng:** trả lời padding hợp lệ hay không (Oracle) |

### 5. Kịch Bản Tấn Công Padding Oracle
| Hàm | Mô tả |
|---|---|
| `decryptByteCandidates()` | Tấn công 1 byte — duyệt 256 giá trị guess, thu thập ứng viên hợp lệ |
| `decryptBlock()` | Tấn công toàn bộ 1 khối AES-CBC — có backtracking để loại false-positive |
| `paddingOracleAttack()` | Tấn công toàn bộ bản mã nhiều khối, ghép kết quả & gỡ padding |

### 6. Demo So Sánh
| Hàm | Mô tả |
|---|---|
| `runComparisonDemo()` | So sánh kết quả mã hóa giữa `AES128` tự cài và `Node.js crypto` |

### 7. Demo Tấn Công
| Hàm | Mô tả |
|---|---|
| `runAttackDemo()` | Demo đầy đủ: khởi tạo server → mã hóa 2 tin nhắn → tấn công → so sánh kết quả |

### 8. Main — Chạy Tất Cả Demo
- Gọi `runComparisonDemo()` → so sánh AES128 tự cài vs Node.js crypto
- Gọi `runAttackDemo()` → tấn công Padding Oracle với 2 tin nhắn mẫu
- In ghi chú bảo mật

---

## 🔗 Mối Liên Kết Giữa Hai Phần

```
aes128.js (An)                    padding_oracle_demo.js (Bảo)
──────────────                    ──────────────────────────
class AES128                      require('./aes128.js')
  ├── SBOX, INV_SBOX, RCON  ──►  aes128cbcEncrypt() dùng AES128.encryptBlock()
  ├── subBytes, shiftRows,       aes128cbcDecrypt() dùng AES128.decryptBlock()
  │   mixColumns, addRoundKey     VictimServer.checkPadding() ← Oracle cho attacker
  ├── galoisMultiply()            decryptByteCandidates() → gọi Oracle 256 lần/byte
  ├── keyExpansion()              decryptBlock() → backtracking attack
  ├── encryptBlock()              paddingOracleAttack() → tấn công toàn bộ
  └── decryptBlock()              runComparisonDemo() → so sánh với Node.js crypto
                                   runAttackDemo() → demo đầy đủ
```

---

> **Ghi chú:** Đây là mã nguồn **giáo dục**, không dùng cho mục đích thực tế. Trong production, hãy dùng `Node.js crypto` hoặc `Web Crypto API`.
