/**
 * THUẬT TOÁN AES-128 (BLOCK CIPHER)
 * Thực hiện: Lê Gia Bảo & An
 */

class AES128 {
    // Bảng S-Box (16x16) dùng cho hàm thế phi tuyến (An phụ trách)
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

    // Hằng số vòng (Round Constant) dùng cho sinh khóa (Bảo phụ trách)
    static RCON = new Uint8Array([
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]);


    // =====================================================================
    // PHẦN 1: ĐÓNG GÓP CỦA AN (TẦNG DỮ LIỆU & PHÉP THẾ PHI TUYẾN)
    // =====================================================================

    /**
     * An: Quản lý trạng thái dữ liệu (State Matrix Management)
     * Đầu vào mặc định đã là column-major chuẩn AES, chỉ cần nạp thẳng vào State!
     */
    static bufferToState(buffer) {
        return new Uint8Array(buffer); // Copy y nguyên dữ liệu vào ma trận
    }

    static stateToBuffer(state) {
        return new Uint8Array(state); // Xuất y nguyên ma trận ra thành mảng
    }
    /**
     * An: Lập trình hàm thế phi tuyến subBytes (Tra cứu S-Box)
     * Tạo tính hỗn loạn (Confusion)
     */
    static subBytes(state) {
        for (let i = 0; i < 16; i++) {
            state[i] = this.SBOX[state[i]];
        }
    }

    /**
     * An: Lập trình hàm addRoundKey 
     * Phép toán XOR ở mức bit giữa State và Subkey
     */
    static addRoundKey(state, roundKey) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }


    // =====================================================================
    // PHẦN 2: ĐÓNG GÓP CỦA GIA BẢO (BIẾN ĐỔI ĐẠI SỐ & SINH KHÓA)
    // =====================================================================

    /**
     * Bảo: Hàm shiftRows - Dịch chuyển vòng các phần tử theo hàng
     */
    static shiftRows(state) {
        const temp = new Uint8Array(16);
        // Hàng 0: Không dịch
        temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
        // Hàng 1: Dịch trái 1 bước
        temp[1] = state[5]; temp[5] = state[9]; temp[9] = state[13]; temp[13] = state[1];
        // Hàng 2: Dịch trái 2 bước
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
        // Hàng 3: Dịch trái 3 bước
        temp[3] = state[15]; temp[7] = state[3]; temp[11] = state[7]; temp[15] = state[11];
        
        state.set(temp);
    }

    /**
     * Bảo: Phép nhân đa thức trong trường hữu hạn Galois GF(2^8)
     */
    static galoisMultiply(a, b) {
        let p = 0;
        for (let counter = 0; counter < 8; counter++) {
            if ((b & 1) !== 0) p ^= a;
            let hiBitSet = (a & 0x80) !== 0;
            a <<= 1;
            if (hiBitSet) a ^= 0x11b; // Đa thức tối giản của AES: x^8 + x^4 + x^3 + x + 1
            b >>= 1;
        }
        return p & 0xFF;
    }

    /**
     * Bảo: Lập trình hàm mixColumns (Khuếch tán dữ liệu - Diffusion)
     */
    static mixColumns(state) {
        for (let c = 0; c < 4; c++) {
            const col = c * 4;
            const s0 = state[col];
            const s1 = state[col + 1];
            const s2 = state[col + 2];
            const s3 = state[col + 3];

            state[col]     = this.galoisMultiply(0x02, s0) ^ this.galoisMultiply(0x03, s1) ^ s2 ^ s3;
            state[col + 1] = s0 ^ this.galoisMultiply(0x02, s1) ^ this.galoisMultiply(0x03, s2) ^ s3;
            state[col + 2] = s0 ^ s1 ^ this.galoisMultiply(0x02, s2) ^ this.galoisMultiply(0x03, s3);
            state[col + 3] = this.galoisMultiply(0x03, s0) ^ s1 ^ s2 ^ this.galoisMultiply(0x02, s3);
        }
    }

    /**
     * Bảo: Lập trình thuật toán Key Expansion 
     * Mở rộng khóa từ 16 bytes lên 176 bytes (44 words)
     */
    static keyExpansion(key) {
        const expandedKey = new Uint8Array(176);
        expandedKey.set(key, 0); // Copy 16 byte gốc vào đầu

        let bytesGenerated = 16;
        let rconIteration = 1;
        const temp = new Uint8Array(4);

        while (bytesGenerated < 176) {
            // Lấy 4 byte của word trước đó
            for (let i = 0; i < 4; i++) {
                temp[i] = expandedKey[bytesGenerated - 4 + i];
            }

            // Xử lý chu kỳ 4 words (16 bytes)
            if (bytesGenerated % 16 === 0) {
                // RotWord
                const t = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                // SubWord
                for (let i = 0; i < 4; i++) {
                    temp[i] = this.SBOX[temp[i]];
                }
                // Rcon
                temp[0] ^= this.RCON[rconIteration++];
            }

            // XOR với word cách đó 4 vị trí
            for (let i = 0; i < 4; i++) {
                expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ temp[i];
                bytesGenerated++;
            }
        }
        return expandedKey;
    }


    // =====================================================================
    // HÀM CHẠY CHÍNH: SỰ PHỐI HỢP CỦA BẢO VÀ AN (10 VÒNG LẶP)
    // =====================================================================

    static encryptBlock(plaintext, key) {
        if (plaintext.length !== 16 || key.length !== 16) {
            throw new Error("Plaintext và Key phải đúng 16 bytes.");
        }

        // 1. Bảo sinh khóa vòng
        const expandedKey = this.keyExpansion(key);
        
        // 2. An khởi tạo ma trận State
        const state = this.bufferToState(plaintext);

        // Vòng 0: AddRoundKey
        this.addRoundKey(state, expandedKey.slice(0, 16));

        // Vòng 1 đến 9
        for (let round = 1; round <= 9; round++) {
            this.subBytes(state);                   // An
            this.shiftRows(state);                  // Bảo
            this.mixColumns(state);                 // Bảo
            this.addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16)); // An
        }

        // Vòng 10 (Không có MixColumns)
        this.subBytes(state);                       // An
        this.shiftRows(state);                      // Bảo
        this.addRoundKey(state, expandedKey.slice(160, 176)); // An

        // Trả về bản mã
        return this.stateToBuffer(state);
    }
}


// =====================================================================
// KHU VỰC CHẠY THỬ NGHIỆM (TEST)
// Cung cấp các vector chuẩn của viện NIST (Mỹ) để kiểm tra độ chính xác
// =====================================================================

console.log("=== BẮT ĐẦU CHẠY THUẬT TOÁN AES-128 CỦA BẢO & AN ===");

// Khóa gốc: 2b7e151628aed2a6abf7158809cf4f3c
const key = new Uint8Array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
console.log("Key (16 bytes):", Array.from(key).map(b => b.toString(16).padStart(2, '0')).join(' '));

// Bản rõ: 6bc1bee22e409f96e93d7e117393172a
const plaintext = new Uint8Array([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a]);
console.log("Plaintext (16 bytes):", Array.from(plaintext).map(b => b.toString(16).padStart(2, '0')).join(' '));

console.log("Đang mã hóa...");

// Chạy hàm mã hóa
const ciphertext = AES128.encryptBlock(plaintext, key);

// In kết quả ra mã Hex
const hexResult = Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('');

console.log("====================================================");
console.log("Kết quả bản mã (Ciphertext):", hexResult);
console.log("Kết quả chuẩn NIST mong đợi: 3ad77bb40d7a3660a89ecaf32466ef97");
if (hexResult === "3ad77bb40d7a3660a89ecaf32466ef97") {
    console.log("✅ THUẬT TOÁN CHẠY CHUẨN XÁC 100% TOÁN HỌC!");
} else {
    console.log("❌ CÓ LỖI XẢY RA TRONG QUÁ TRÌNH TÍNH TOÁN!");
}