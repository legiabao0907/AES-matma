/**
 * ===========================================================================
 * THUẬT TOÁN AES-128 (MÃ HÓA & GIẢI MÃ KHỐI)
 * Phiên bản cải tiến — Mô phỏng giáo dục đầy đủ
 * Thực hiện: Lê Gia Bảo & An — Đại học Bách Khoa Hà Nội (HUST)
 * ===========================================================================
 * 
 * NỘI DUNG:
 *   1. Các bảng tra cứu (S-Box, Inverse S-Box, Rcon)
 *   2. Quản lý ma trận trạng thái (State Matrix)
 *   3. Phép thế phi tuyến SubBytes / InvSubBytes
 *   4. Phép dịch hàng ShiftRows / InvShiftRows
 *   5. Phép trộn cột MixColumns / InvMixColumns (GF(2^8))
 *   6. Mở rộng khóa Key Expansion
 *   7. Mã hóa encryptBlock() — 10 vòng
 *   8. Giải mã decryptBlock() — 10 vòng
 *   9. Demo trực quan: mã hóa → giải mã → so sánh
 *
 * ĐỘ PHỨC TẠP:
 *   - Key Expansion:  O(1) — 44 word, cố định với AES-128
 *   - Mã hóa 1 khối: O(1) — luôn 10 vòng × 16 byte = 160 phép thế
 *   - MixColumns:     O(1) — 4 cột × 4 phép nhân GF(2^8) mỗi cột
 *   - GaloisMultiply: O(1) — tối đa 8 vòng lặp bit
 */

'use strict';

class AES128 {
    // =====================================================================
    // BẢNG TRA CỨU TĨNH
    // =====================================================================

    /** Bảng S-Box 16×16 — Phép thế phi tuyến (Confusion) */
    static SBOX = new Uint8Array([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]);

    /** Bảng Inverse S-Box 16×16 — Dùng cho giải mã */
    static INV_SBOX = new Uint8Array([
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]);

    /** Hằng số vòng Rcon — dùng trong Key Expansion */
    static RCON = new Uint8Array([
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]);

    // =====================================================================
    // TIỆN ÍCH HIỂN THỊ
    // =====================================================================

    /**
     * Chuyển mảng byte thành chuỗi hex để hiển thị.
     * Độ phức tạp: O(n) với n = độ dài mảng
     */
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
    }

    /**
     * In ma trận trạng thái 4×4 dưới dạng hex.
     * Độ phức tạp: O(1) — cố định 16 byte
     */
    static printState(label, state) {
        console.log(`\n  [${label}]`);
        for (let row = 0; row < 4; row++) {
            const line = [];
            for (let col = 0; col < 4; col++) {
                line.push(state[col * 4 + row].toString(16).padStart(2, '0'));
            }
            console.log(`    ${line.join('  ')}`);
        }
    }

    // =====================================================================
    // PHẦN 1: QUẢN LÝ TRẠNG THÁI & PHÉP THẾ PHI TUYẾN
    // =====================================================================

    /**
     * Nạp dữ liệu đầu vào (16 byte) thành ma trận State 4×4 (column-major).
     * Độ phức tạp: O(1) — copy 16 byte
     */
    static bufferToState(buffer) {
        return new Uint8Array(buffer);
    }

    /**
     * Xuất ma trận State thành mảng 16 byte.
     * Độ phức tạp: O(1) — copy 16 byte
     */
    static stateToBuffer(state) {
        return new Uint8Array(state);
    }

    /**
     * SubBytes — Phép thế phi tuyến dùng S-Box (Confusion).
     * Mỗi byte được thay bằng giá trị tra từ S-Box.
     * Độ phức tạp: O(1) — duyệt 16 byte, mỗi byte tra bảng O(1)
     */
    static subBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = this.SBOX[state[i]];
        }
    }

    /**
     * InvSubBytes — Phép thế ngược dùng Inverse S-Box (cho giải mã).
     * Độ phức tạp: O(1) — duyệt 16 byte
     */
    static invSubBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = this.INV_SBOX[state[i]];
        }
    }

    /**
     * AddRoundKey — XOR State với khóa vòng.
     * Độ phức tạp: O(1) — 16 phép XOR
     */
    static addRoundKey(state, roundKey) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    // =====================================================================
    // PHẦN 2: BIẾN ĐỔI ĐẠI SỐ & TRƯỜNG HỮU HẠN GF(2^8)
    // =====================================================================

    /**
     * ShiftRows — Dịch vòng trái các hàng của State.
     *   Hàng 0: không dịch
     *   Hàng 1: dịch trái 1
     *   Hàng 2: dịch trái 2
     *   Hàng 3: dịch trái 3
     * Độ phức tạp: O(1) — cố định 16 byte
     */
    static shiftRows(state) {
        const temp = new Uint8Array(16);
        // Hàng 0: giữ nguyên
        temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
        // Hàng 1: dịch trái 1
        temp[1] = state[5]; temp[5] = state[9]; temp[9] = state[13]; temp[13] = state[1];
        // Hàng 2: dịch trái 2
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
        // Hàng 3: dịch trái 3
        temp[3] = state[15]; temp[7] = state[3]; temp[11] = state[7]; temp[15] = state[11];
        state.set(temp);
    }

    /**
     * InvShiftRows — Dịch vòng phải các hàng (ngược với ShiftRows).
     *   Hàng 0: không dịch
     *   Hàng 1: dịch phải 1
     *   Hàng 2: dịch phải 2
     *   Hàng 3: dịch phải 3
     * Độ phức tạp: O(1) — cố định 16 byte
     */
    static invShiftRows(state) {
        const temp = new Uint8Array(16);
        // Hàng 0: giữ nguyên
        temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
        // Hàng 1: dịch phải 1
        temp[1] = state[13]; temp[5] = state[1]; temp[9] = state[5]; temp[13] = state[9];
        // Hàng 2: dịch phải 2
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
        // Hàng 3: dịch phải 3
        temp[3] = state[7]; temp[7] = state[11]; temp[11] = state[15]; temp[15] = state[3];
        state.set(temp);
    }

    /**
     * Phép nhân trong trường hữu hạn Galois GF(2^8).
     * Đa thức tối giản của AES: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
     * Độ phức tạp: O(1) — tối đa 8 vòng lặp bit, early-exit khi b = 0
     * 
     * @param {number} a - Toán hạng thứ nhất (0-255)
     * @param {number} b - Toán hạng thứ hai (0-255)
     * @returns {number} Tích trong GF(2^8)
     */
    static galoisMultiply(a, b) {
        let p = 0;
        while (b !== 0) {                         // Early-exit: dừng khi b = 0
            if (b & 1) p ^= a;                    // Nếu bit thấp nhất của b = 1, cộng a
            const hiBitSet = (a & 0x80) !== 0;    // Kiểm tra bit cao nhất của a
            a <<= 1;                               // Nhân a với x
            if (hiBitSet) a ^= 0x11b;              // Nếu tràn, rút gọn modulo P(x)
            b >>= 1;                               // Chia b cho x
        }
        return p & 0xFF;
    }

    /**
     * MixColumns — Trộn các cột của State với ma trận cố định (Diffusion).
     * Ma trận: [02 03 01 01]
     *          [01 02 03 01]
     *          [01 01 02 03]
     *          [03 01 01 02]
     * Mỗi cột tính 4 phép nhân GF(2^8) cho 02·x, rồi tận dụng 03·x = 02·x ⊕ x.
     * Độ phức tạp: O(1) — 4 cột × 4 phép nhân GF(2^8)
     */
    static mixColumns(state) {
        for (let c = 0; c < 4; c++) {
            const col = c * 4;
            const s0 = state[col];
            const s1 = state[col + 1];
            const s2 = state[col + 2];
            const s3 = state[col + 3];

            // Chỉ 4 phép nhân GF(2^8): tính 02·x một lần cho mỗi đầu vào
            const s0x2 = this.galoisMultiply(0x02, s0);
            const s1x2 = this.galoisMultiply(0x02, s1);
            const s2x2 = this.galoisMultiply(0x02, s2);
            const s3x2 = this.galoisMultiply(0x02, s3);
            // 03·x = 02·x ⊕ x (tận dụng, không cần nhân lại)
            state[col]     = s0x2 ^ s1x2 ^ s1 ^ s2 ^ s3;           // 02·s0 ⊕ 03·s1 ⊕ s2 ⊕ s3
            state[col + 1] = s0 ^ s1x2 ^ s2x2 ^ s2 ^ s3;           // s0 ⊕ 02·s1 ⊕ 03·s2 ⊕ s3
            state[col + 2] = s0 ^ s1 ^ s2x2 ^ s3x2 ^ s3;           // s0 ⊕ s1 ⊕ 02·s2 ⊕ 03·s3
            state[col + 3] = s0x2 ^ s0 ^ s1 ^ s2 ^ s3x2;           // 03·s0 ⊕ s1 ⊕ s2 ⊕ 02·s3
        }
    }

    /**
     * InvMixColumns — Trộn cột ngược (cho giải mã).
     * Ma trận: [0E 0B 0D 09]
     *          [09 0E 0B 0D]
     *          [0D 09 0E 0B]
     *          [0B 0D 09 0E]
     * Độ phức tạp: O(1) — 4 cột × 16 phép nhân GF(2^8)
     */
    static invMixColumns(state) {
        for (let c = 0; c < 4; c++) {
            const col = c * 4;
            const s0 = state[col];
            const s1 = state[col + 1];
            const s2 = state[col + 2];
            const s3 = state[col + 3];

            state[col]     = this.galoisMultiply(0x0e, s0) ^ this.galoisMultiply(0x0b, s1) ^ this.galoisMultiply(0x0d, s2) ^ this.galoisMultiply(0x09, s3);
            state[col + 1] = this.galoisMultiply(0x09, s0) ^ this.galoisMultiply(0x0e, s1) ^ this.galoisMultiply(0x0b, s2) ^ this.galoisMultiply(0x0d, s3);
            state[col + 2] = this.galoisMultiply(0x0d, s0) ^ this.galoisMultiply(0x09, s1) ^ this.galoisMultiply(0x0e, s2) ^ this.galoisMultiply(0x0b, s3);
            state[col + 3] = this.galoisMultiply(0x0b, s0) ^ this.galoisMultiply(0x0d, s1) ^ this.galoisMultiply(0x09, s2) ^ this.galoisMultiply(0x0e, s3);
        }
    }

    // =====================================================================
    // PHẦN 3: MỞ RỘNG KHÓA (KEY EXPANSION)
    // =====================================================================

    /**
     * Key Expansion — Mở rộng khóa 128-bit thành 11 khóa vòng (176 byte).
     * Thuật toán: với mỗi 4 byte mới:
     *   1. Lấy word trước đó
     *   2. Nếu là bội của 16 byte → RotWord → SubWord → XOR Rcon
     *   3. XOR với word cách 4 vị trí
     * 
     * Độ phức tạp: O(1) — cố định 44 word với AES-128
     * Bộ nhớ:       O(1) — 176 byte
     */
    static keyExpansion(key) {
        const expandedKey = new Uint8Array(176);
        expandedKey.set(key, 0);

        let bytesGenerated = 16;
        let rconIteration = 1;
        const temp = new Uint8Array(4);

        while (bytesGenerated < 176) {
            // Đọc word trước đó (4 byte)
            for (let i = 0; i < 4; i++) {
                temp[i] = expandedKey[bytesGenerated - 4 + i];
            }

            // Cứ mỗi 16 byte (1 khóa vòng) thì thực hiện biến đổi đặc biệt
            if (bytesGenerated % 16 === 0) {
                // RotWord: dịch vòng trái 1 byte
                const t = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                // SubWord: thế mỗi byte qua S-Box
                for (let i = 0; i < 4; i++) {
                    temp[i] = this.SBOX[temp[i]];
                }
                // XOR byte đầu với Rcon
                temp[0] ^= this.RCON[rconIteration++];
            }

            // XOR với word cách 4 vị trí (16 byte phía trước)
            for (let i = 0; i < 4; i++) {
                expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ temp[i];
                bytesGenerated++;
            }
        }
        return expandedKey;
    }

    // =====================================================================
    // PHẦN 4: MÃ HÓA & GIẢI MÃ KHỐI
    // =====================================================================

    /**
     * Mã hóa một khối 16 byte bằng AES-128.
     * 
     * SƠ ĐỒ LUỒNG CHẠY:
     *   1. Key Expansion → 11 khóa vòng (176 byte)
     *   2. AddRoundKey (vòng 0) — XOR với khóa gốc
     *   3. Lặp 9 vòng: SubBytes → ShiftRows → MixColumns → AddRoundKey
     *   4. Vòng cuối (vòng 10): SubBytes → ShiftRows → AddRoundKey (không MixColumns)
     * 
     * Độ phức tạp thời gian: O(1) — cố định 10 vòng × 16 byte
     * Độ phức tạp không gian: O(1) — 16 byte State + 176 byte expanded key
     *
     * @param {Uint8Array|Array} plaintext - 16 byte bản rõ
     * @param {Uint8Array|Array} key - 16 byte khóa
     * @param {boolean} verbose - In chi tiết từng vòng (mặc định false)
     * @returns {Uint8Array} 16 byte bản mã
     */
    static encryptBlock(plaintext, key, verbose = false) {
        if (plaintext.length !== 16 || key.length !== 16) {
            throw new Error("Plaintext và Key phải đúng 16 bytes.");
        }

        // Bước 1: Mở rộng khóa
        const expandedKey = this.keyExpansion(key);

        // Bước 2: Khởi tạo State
        const state = this.bufferToState(plaintext);

        if (verbose) {
            this.printState('Bản rõ (Plaintext)', state);
            console.log(`  Khóa gốc: ${this.bytesToHex(key)}`);
        }

        // Vòng 0: AddRoundKey với khóa gốc
        this.addRoundKey(state, expandedKey.slice(0, 16));
        if (verbose) console.log(`  --- Vòng 0: AddRoundKey ---`);

        // Vòng 1 → 9: 4 phép biến đổi đầy đủ
        for (let round = 1; round <= 9; round++) {
            this.subBytes(state);
            this.shiftRows(state);
            this.mixColumns(state);
            this.addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
            if (verbose) {
                console.log(`  --- Vòng ${round}: SubBytes → ShiftRows → MixColumns → AddRoundKey ---`);
                if (round === 1 || round === 9) this.printState(`State sau vòng ${round}`, state);
            }
        }

        // Vòng 10: không có MixColumns
        this.subBytes(state);
        this.shiftRows(state);
        this.addRoundKey(state, expandedKey.slice(160, 176));
        if (verbose) {
            console.log(`  --- Vòng 10: SubBytes → ShiftRows → AddRoundKey (không MixColumns) ---`);
            this.printState('Bản mã (Ciphertext)', state);
        }

        return this.stateToBuffer(state);
    }

    /**
     * Giải mã một khối 16 byte bằng AES-128.
     * 
     * SƠ ĐỒ LUỒNG CHẠY (ngược với mã hóa):
     *   1. Key Expansion → 11 khóa vòng
     *   2. AddRoundKey (vòng 10) — XOR với khóa vòng cuối
     *   3. Lặp 9 vòng ngược: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
     *   4. Vòng cuối: InvShiftRows → InvSubBytes → AddRoundKey (không InvMixColumns)
     * 
     * Độ phức tạp: giống mã hóa — O(1)
     *
     * @param {Uint8Array|Array} ciphertext - 16 byte bản mã
     * @param {Uint8Array|Array} key - 16 byte khóa
     * @param {boolean} verbose - In chi tiết từng vòng
     * @returns {Uint8Array} 16 byte bản rõ
     */
    static decryptBlock(ciphertext, key, verbose = false) {
        if (ciphertext.length !== 16 || key.length !== 16) {
            throw new Error("Ciphertext và Key phải đúng 16 bytes.");
        }

        // Bước 1: Mở rộng khóa
        const expandedKey = this.keyExpansion(key);

        // Bước 2: Khởi tạo State từ bản mã
        const state = this.bufferToState(ciphertext);

        if (verbose) {
            this.printState('Bản mã đầu vào (Ciphertext)', state);
        }

        // Vòng 10 ngược: AddRoundKey với khóa vòng cuối
        this.addRoundKey(state, expandedKey.slice(160, 176));
        if (verbose) console.log(`  --- Vòng 10 ngược: AddRoundKey ---`);

        // Vòng 9 → 1 ngược: 4 phép biến đổi đầy đủ (thứ tự ngược)
        for (let round = 9; round >= 1; round--) {
            this.invShiftRows(state);
            this.invSubBytes(state);
            this.addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
            this.invMixColumns(state);
            if (verbose) {
                console.log(`  --- Vòng ${round} ngược: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns ---`);
                if (round === 9 || round === 1) this.printState(`State sau vòng ${round} ngược`, state);
            }
        }

        // Vòng 0 ngược: không có InvMixColumns
        this.invShiftRows(state);
        this.invSubBytes(state);
        this.addRoundKey(state, expandedKey.slice(0, 16));
        if (verbose) {
            console.log(`  --- Vòng 0 ngược: InvShiftRows → InvSubBytes → AddRoundKey ---`);
            this.printState('Bản rõ giải mã (Plaintext)', state);
        }

        return this.stateToBuffer(state);
    }

    /**
     * Trích xuất khóa vòng từ expanded key.
     * Hữu ích cho việc debug và mô phỏng từng vòng.
     *
     * @param {Uint8Array} expandedKey - 176 byte khóa mở rộng
     * @param {number} round - Số vòng (0-10)
     * @returns {Uint8Array} 16 byte khóa vòng
     */
    static getRoundKey(expandedKey, round) {
        return expandedKey.slice(round * 16, (round + 1) * 16);
    }
}

// =====================================================================
// DEMO: Chạy thử mã hóa & giải mã
// =====================================================================
if (require.main === module) {
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║     MÔ PHỎNG AES-128 — MÃ HÓA & GIẢI MÃ         ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log('║  Bản rõ  : HUST_A+_Grade_12                     ║');
    console.log('║  Khóa    : mySecretKey!!16!                     ║');
    console.log('╚══════════════════════════════════════════════════╝');

    const plaintext = Buffer.from('HUST_A+_Grade_12', 'utf8');  // 16 byte
    const key       = Buffer.from('mySecretKey!!16!', 'utf8');    // 16 byte

    console.log('\n══════════════ QUÁ TRÌNH MÃ HÓA ══════════════');
    const ciphertext = AES128.encryptBlock(plaintext, key, true);

    console.log('\n══════════════ QUÁ TRÌNH GIẢI MÃ ══════════════');
    const decrypted = AES128.decryptBlock(ciphertext, key, true);

    console.log('\n══════════════ KẾT QUẢ ══════════════');
    console.log(`  Bản rõ gốc:       ${AES128.bytesToHex(plaintext)}  (${Buffer.from(plaintext).toString('utf8')})`);
    console.log(`  Bản mã (hex):     ${AES128.bytesToHex(ciphertext)}`);
    console.log(`  Giải mã được:     ${AES128.bytesToHex(decrypted)}  (${Buffer.from(decrypted).toString('utf8')})`);
    
    // Kiểm tra khớp
    const match = Buffer.from(plaintext).equals(Buffer.from(decrypted));
    console.log(`\n  ${match ? '✅ Mã hóa & Giải mã KHỚP chính xác!' : '❌ LỖI: Không khớp!'}`);
}

// =====================================================================
// XUẤT MODULE
// =====================================================================
module.exports = AES128;