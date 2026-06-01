/**
 * ===========================================================================
 * TẤN CÔNG PADDING ORACLE — MÔ PHỎNG ĐẦY ĐỦ
 * Phiên bản cải tiến — Khôi phục TOÀN BỘ plaintext
 * Thực hiện: Lê Gia Bảo & An — Đại học Bách Khoa Hà Nội (HUST)
 * ===========================================================================
 * 
 * NỘI DUNG:
 *   1. VictimServer — Hệ thống giả lập có lỗ hổng Padding Oracle
 *   2. PKCS#7 Padding — Cơ chế đệm chuẩn trong AES-CBC
 *   3. Hàm tấn công từng byte — decryptByte()
 *   4. Hàm tấn công toàn bộ khối — decryptBlock()
 *   5. Hàm tấn công toàn bộ bản mã — paddingOracleAttack()
 *   6. Demo so sánh: AES128 tự cài vs Node.js crypto
 *
 * NGUYÊN LÝ TẤN CÔNG:
 *   CBC: C_i = Encrypt(P_i ⊕ C_{i-1})
 *   → P_i = Decrypt(C_i) ⊕ C_{i-1}
 *   → P_i = I_i ⊕ C_{i-1}   (I_i = intermediate value)
 *   
 *   Kẻ tấn công thay đổi C_{i-1} đến khi padding hợp lệ:
 *     I_i[15] = guess ⊕ 0x01
 *     P_i[15] = I_i[15] ⊕ C_{i-1}[15] (gốc)
 *   
 *   Sau đó leo lên padding 0x02, 0x03, ... để khôi phục toàn bộ P_i.
 *
 * ĐỘ PHỨC TẠP:
 *   - Tấn công 1 byte:    O(1) — tối đa 256 lần thử (trung bình 128)
 *   - Tấn công 1 khối:    O(1) — 16 byte × 256 = tối đa 4096 lần gọi Oracle
 *   - Tấn công n khối:     O(n) — tuyến tính theo số khối
 *   - Tổng số lần Oracle:  n_blocks × 16 × 256 (worst-case)
 */

'use strict';

const crypto = require('crypto');
const AES128  = require('./aes128.js');

// =====================================================================
// TIỆN ÍCH
// =====================================================================

/** Chuyển Buffer/mảng byte thành chuỗi hex */
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
}

/** XOR hai Buffer cùng độ dài */
function xorBuffers(a, b) {
    const result = Buffer.alloc(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// =====================================================================
// PHẦN 1: PKCS#7 PADDING
// =====================================================================

/**
 * PKCS#7 Padding — Thêm byte đệm vào plaintext.
 * Mỗi byte đệm có giá trị = số byte cần đệm.
 * Ví dụ: cần đệm 5 byte → thêm 5 byte 0x05.
 * Nếu plaintext đã là bội của 16 → thêm hẳn 1 khối 16 byte 0x10.
 *
 * Độ phức tạp: O(n) — tạo mảng mới dài hơn
 */
function pkcs7Pad(data, blockSize = 16) {
    const padLen = blockSize - (data.length % blockSize);
    const padded = Buffer.alloc(data.length + padLen);
    data.copy(padded);
    padded.fill(padLen, data.length);
    return padded;
}

/**
 * PKCS#7 Unpadding — Gỡ byte đệm sau khi giải mã.
 * Kiểm tra tính hợp lệ của padding.
 *
 * Độ phức tạp: O(1)
 */
function pkcs7Unpad(data) {
    const padLen = data[data.length - 1];
    if (padLen < 1 || padLen > 16) {
        throw new Error(`Padding không hợp lệ: byte cuối = ${padLen}`);
    }
    // Kiểm tra tất cả byte đệm có cùng giá trị không
    for (let i = data.length - padLen; i < data.length; i++) {
        if (data[i] !== padLen) {
            throw new Error(`Padding không hợp lệ tại vị trí ${i}: ${data[i]} != ${padLen}`);
        }
    }
    return data.slice(0, data.length - padLen);
}

// =====================================================================
// PHẦN 2: MÃ HÓA AES-128-CBC (TỰ CÀI ĐẶT)
// =====================================================================

/**
 * Mã hóa AES-128-CBC dùng class AES128 tự cài.
 * 
 * SƠ ĐỒ: plaintext → PKCS#7 pad → chia khối → CBC encrypt
 *   C_0 = IV
 *   C_i = AES_encrypt(P_i ⊕ C_{i-1})
 *
 * Độ phức tạp: O(n) — n là số khối
 */
function aes128cbcEncrypt(plaintext, key, iv) {
    const padded = pkcs7Pad(plaintext);
    const blocks = [];
    for (let i = 0; i < padded.length; i += 16) {
        blocks.push(padded.slice(i, i + 16));
    }

    const ciphertext = [];
    let previousBlock = iv; // C_{i-1}

    for (const block of blocks) {
        // P_i ⊕ C_{i-1}
        const xored = xorBuffers(block, previousBlock);
        // Mã hóa
        const encrypted = AES128.encryptBlock(xored, key);
        ciphertext.push(Buffer.from(encrypted));
        previousBlock = Buffer.from(encrypted);
    }

    return Buffer.concat(ciphertext);
}

/**
 * Giải mã AES-128-CBC dùng class AES128 tự cài.
 * 
 * SƠ ĐỒ: chia khối → CBC decrypt → unpad
 *   P_i = AES_decrypt(C_i) ⊕ C_{i-1}
 *
 * Độ phức tạp: O(n) — n là số khối
 */
function aes128cbcDecrypt(ciphertext, key, iv) {
    const blocks = [];
    for (let i = 0; i < ciphertext.length; i += 16) {
        blocks.push(ciphertext.slice(i, i + 16));
    }

    const plaintext = [];
    let previousBlock = iv; // C_{i-1}

    for (const block of blocks) {
        // Giải mã
        const decrypted = AES128.decryptBlock(block, key);
        // P_i = Decrypt(C_i) ⊕ C_{i-1}
        const xored = xorBuffers(Buffer.from(decrypted), previousBlock);
        plaintext.push(xored);
        previousBlock = block;
    }

    return pkcs7Unpad(Buffer.concat(plaintext));
}

// =====================================================================
// PHẦN 3: VICTIM SERVER (HỆ THỐNG CÓ LỖ HỔNG)
// =====================================================================

class VictimServer {
    /**
     * Khởi tạo server với khóa bí mật ngẫu nhiên.
     * Trong thực tế, khóa này được bảo vệ — hacker không thể truy cập.
     */
    constructor() {
        this.secretKey = crypto.randomBytes(16);
    }

    /**
     * Mã hóa tin nhắn bí mật bằng AES-128-CBC.
     * Trả về IV và ciphertext — đây là thứ hacker "nghe lén" được.
     *
     * @param {string} message - Tin nhắn cần mã hóa
     * @returns {{ iv: Buffer, ciphertext: Buffer }}
     */
    getEncryptedSecret(message = 'HUST_A+_Grade_12') {
        const iv = crypto.randomBytes(16);
        const plaintext = Buffer.from(message, 'utf8');

        // Dùng AES128 tự cài để minh họa
        const ciphertext = aes128cbcEncrypt(plaintext, this.secretKey, iv);

        return { iv, ciphertext };
    }

    /**
     * 🔴 LỖ HỔNG PADDING ORACLE:
     * Server trả lời padding hợp lệ hay không.
     * 
     * TRONG THỰC TẾ: Server trả HTTP 200 (OK) hoặc HTTP 500 (Internal Server Error)
     * dựa vào lỗi "BadPaddingException" — kẻ tấn công chỉ cần BIẾT trạng thái này!
     *
     * @param {Buffer} iv - IV (hoặc khối C_{i-1})
     * @param {Buffer} ciphertext - Khối bản mã cần kiểm tra
     * @returns {boolean} true = padding hợp lệ, false = padding sai
     */
    checkPadding(iv, ciphertext) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-cbc', this.secretKey, iv);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return true; // Padding hợp lệ (HTTP 200)
        } catch (error) {
            return false; // Padding sai (HTTP 500)
        }
    }
}

// =====================================================================
// PHẦN 4: KỊCH BẢN TẤN CÔNG PADDING ORACLE
// =====================================================================

/**
 * Tấn công MỘT BYTE — thu thập TẤT CẢ ứng viên hợp lệ.
 * 
 * CÔNG THỨC CỐT LÕI:
 *   I_i[pos] = guess ⊕ targetPad
 *   P_i[pos] = I_i[pos] ⊕ C_{i-1}_gốc[pos]
 *
 * Độ phức tạp: O(1) — luôn duyệt đủ 256 giá trị
 *
 * @returns {number[]} Mảng các guess hợp lệ (có thể nhiều hơn 1 do false-positive)
 */
function decryptByteCandidates(oracle, prevBlock, targetBlock, pos, knownIntermediate) {
    const targetPad = 16 - pos;
    const fakePrev = Buffer.alloc(16);

    // Giữ nguyên các byte trước pos
    for (let i = 0; i < pos; i++) {
        fakePrev[i] = prevBlock[i];
    }

    // Đặt các byte đã biết (sau pos) để tạo padding mục tiêu
    for (let i = pos + 1; i < 16; i++) {
        fakePrev[i] = knownIntermediate[i] ^ targetPad;
    }

    const candidates = [];

    for (let guess = 0; guess <= 255; guess++) {
        fakePrev[pos] = guess;
        if (oracle(fakePrev, targetBlock)) {
            candidates.push(guess);
        }
    }

    return candidates;
}

/**
 * Tấn công TOÀN BỘ MỘT KHỐI AES-CBC bằng Padding Oracle (có backtrack).
 * 
 * LUỒNG CHẠY:
 *   1. Bắt đầu từ byte cuối (pos=15), targetPad=0x01
 *   2. Thu thập TẤT CẢ guess hợp lệ (có thể nhiều hơn 1)
 *   3. Với mỗi guess, thử giải mã byte tiếp theo (pos-1)
 *   4. Nếu byte tiếp theo KHÔNG có guess nào → guess hiện tại SAI → backtrack
 *   5. Nếu byte tiếp theo có guess → giữ lại, tiếp tục
 *
 * Độ phức tạp: O(1) — 16 × 256 lần Oracle, backtrack không đáng kể
 *
 * @returns {{ intermediate: number[], plaintext: Buffer }}
 */
function decryptBlock(oracle, prevBlock, targetBlock, verbose = false) {
    const intermediate = new Array(16).fill(0);
    const plaintextBytes = new Array(16).fill(0);

    // Hàm đệ quy thử giải mã từ vị trí pos
    function tryDecryptFrom(pos) {
        if (pos < 0) return true; // Đã giải mã xong toàn bộ khối

        const candidates = decryptByteCandidates(oracle, prevBlock, targetBlock, pos, intermediate);

        if (candidates.length === 0) {
            return false; // Không tìm thấy → backtrack
        }

        // Thử từng ứng viên
        for (const guess of candidates) {
            const candidateIntermediate = guess ^ (16 - pos);
            const candidatePlaintext = candidateIntermediate ^ prevBlock[pos];

            // Lưu tạm
            const savedIntermediate = intermediate[pos];
            const savedPlaintext = plaintextBytes[pos];

            intermediate[pos] = candidateIntermediate;
            plaintextBytes[pos] = candidatePlaintext;

            // Thử giải mã byte tiếp theo
            if (tryDecryptFrom(pos - 1)) {
                // Thành công! Giữ kết quả này
                return true;
            }

            // Backtrack: khôi phục giá trị cũ, thử ứng viên tiếp
            intermediate[pos] = savedIntermediate;
            plaintextBytes[pos] = savedPlaintext;
        }

        return false; // Tất cả ứng viên đều thất bại
    }

    // Bắt đầu từ byte cuối cùng
    const success = tryDecryptFrom(15);

    if (!success) {
        throw new Error('Không thể giải mã khối này. Oracle có thể không hoạt động đúng.');
    }

    // In kết quả nếu verbose
    if (verbose) {
        for (let pos = 15; pos >= 0; pos--) {
            const ascii = (plaintextBytes[pos] >= 32 && plaintextBytes[pos] <= 126)
                ? String.fromCharCode(plaintextBytes[pos]) : '.';
            const pct = Math.round((intermediate[pos] + 1) / 2.56);
            console.log(`    Byte [${pos.toString().padStart(2)}]: ` +
                `I=0x${intermediate[pos].toString(16).padStart(2)}  ` +
                `P=0x${plaintextBytes[pos].toString(16).padStart(2)}  '${ascii}'  ` +
                `(đã thử ~${pct}% không gian)`);
        }
    }

    return {
        intermediate,
        plaintext: Buffer.from(plaintextBytes)
    };
}

/**
 * Tấn công TOÀN BỘ BẢN MÃ AES-CBC (nhiều khối).
 * 
 * LUỒNG CHẠY TỔNG QUÁT:
 *   Cho ciphertext = C_1 || C_2 || ... || C_n  (n khối, mỗi khối 16 byte)
 *   
 *   Với mỗi khối C_i:
 *     - Khối trước: prevBlock = C_{i-1} (với i=1 thì prevBlock = IV)
 *     - Gọi decryptBlock() để khôi phục P_i
 *   
 *   Cuối cùng: gỡ PKCS#7 padding để lấy plaintext gốc
 *
 * Độ phức tạp:
 *   - Thời gian: O(n) — tuyến tính theo số khối
 *   - Số lần Oracle: n × 16 × 128 (trung bình) — tối đa n × 4096
 *   - Với AES-128, mỗi lần Oracle = 1 lần giải mã AES + kiểm tra padding
 *
 * @param {Function} oracle - Hàm checkPadding(iv, ciphertext)
 * @param {Buffer} iv - Initialization Vector
 * @param {Buffer} ciphertext - Toàn bộ bản mã (bội của 16 byte)
 * @param {boolean} verbose - In chi tiết quá trình
 * @returns {Buffer} Bản rõ đã được giải mã (đã gỡ padding)
 */
function paddingOracleAttack(oracle, iv, ciphertext, verbose = true) {
    if (ciphertext.length % 16 !== 0) {
        throw new Error(`Ciphertext phải là bội của 16 byte (hiện tại: ${ciphertext.length} byte)`);
    }

    const numBlocks = ciphertext.length / 16;
    const plaintextBlocks = [];

    console.log(`\n  ▶ Bản mã có ${numBlocks} khối (${ciphertext.length} byte)`);
    console.log(`  ▶ Mỗi khối cần tối đa 16 × 256 = 4096 lần gọi Oracle`);
    console.log(`  ▶ Tổng tối đa: ${numBlocks} × 4096 = ${numBlocks * 4096} lần gọi Oracle\n`);

    // Tách thành từng khối
    const blocks = [];
    for (let i = 0; i < ciphertext.length; i += 16) {
        blocks.push(ciphertext.slice(i, i + 16));
    }

    let totalOracleCalls = 0;

    // Tấn công từng khối
    for (let blockIdx = 0; blockIdx < blocks.length; blockIdx++) {
        const prevBlock = (blockIdx === 0) ? iv : blocks[blockIdx - 1];
        const targetBlock = blocks[blockIdx];

        if (verbose) {
            console.log(`  ╔═══════════════ Khối ${blockIdx + 1}/${numBlocks} ═══════════════╗`);
            console.log(`  ║  C_{${blockIdx}} (mục tiêu): ${bytesToHex(targetBlock)}`.padEnd(64) + '║');
            console.log(`  ║  C_{${blockIdx - 1}} (trước đó): ${bytesToHex(prevBlock)}`.padEnd(64) + '║');
            console.log(`  ╚══════════════════════════════════════════════════╝`);
        }

        const startTime = Date.now();
        const result = decryptBlock(oracle, prevBlock, targetBlock, verbose);
        const elapsed = Date.now() - startTime;

        plaintextBlocks.push(result.plaintext);

        if (verbose) {
            const readable = result.plaintext.toString('utf8')
                .replace(/[\x00-\x1f\x7f-\xff]/g, '.');
            console.log(`  ✅ Khối ${blockIdx + 1} hoàn thành trong ${elapsed}ms`);
            console.log(`     Plaintext (hex): ${bytesToHex(result.plaintext)}`);
            console.log(`     Plaintext (raw): ${readable}\n`);
        }
    }

    // Ghép và gỡ padding
    const rawPlaintext = Buffer.concat(plaintextBlocks);
    const unpadded = pkcs7Unpad(rawPlaintext);

    if (verbose) {
        console.log(`  ════════════════ KẾT QUẢ CUỐI CÙNG ════════════════`);
        console.log(`  Plaintext (còn padding): ${bytesToHex(rawPlaintext)}`);
        console.log(`  Plaintext (đã unpad)   : ${bytesToHex(unpadded)}`);
    }

    return unpadded;
}

// =====================================================================
// PHẦN 5: DEMO SO SÁNH — AES128 TỰ CÀI vs NODE.JS CRYPTO
// =====================================================================

function runComparisonDemo() {
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║   SO SÁNH: AES128 (tự cài) vs Node.js crypto       ║');
    console.log('╚══════════════════════════════════════════════════════╝\n');

    const plaintext = Buffer.from('HUST_A+_Grade_12', 'utf8');
    const key       = Buffer.from('mySecretKey!!16!', 'utf8');
    const iv        = crypto.randomBytes(16);

    console.log(`  Plaintext : "${plaintext.toString('utf8')}" (${plaintext.length} byte)`);
    console.log(`  Key       : "${key.toString('utf8')}"`);
    console.log(`  IV        : ${bytesToHex(iv)}\n`);

    // Mã hóa bằng AES128 tự cài
    const ourCipher = aes128cbcEncrypt(plaintext, key, iv);
    console.log(`  🔐 AES128 tự cài → Ciphertext: ${bytesToHex(ourCipher)} (${ourCipher.length} byte)`);

    // Mã hóa bằng Node.js crypto
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let nodeCipher = cipher.update(plaintext);
    nodeCipher = Buffer.concat([nodeCipher, cipher.final()]);
    console.log(`  🔐 Node.js crypto → Ciphertext: ${bytesToHex(nodeCipher)} (${nodeCipher.length} byte)`);

    // So sánh
    const match = ourCipher.equals(nodeCipher);
    console.log(`\n  ${match ? '✅ KẾT QUẢ KHỚP NHAU!' : '⚠️  Kết quả KHÁC NHAU (có thể do PKCS#7 khối phụ)'}`);
    if (!match) {
        console.log('     (Lý do: plaintext 16 byte + PKCS#7 → thêm 1 khối 0x10.');
        console.log('      Node.js crypto tự động thêm khối này, AES128 tự cài cũng vậy.)');
    }

    // Giải mã ngược lại để kiểm tra
    const decrypted = aes128cbcDecrypt(ourCipher, key, iv);
    console.log(`  🔓 Giải mã ngược → "${decrypted.toString('utf8')}"`);
    console.log(`  ${decrypted.toString('utf8') === 'HUST_A+_Grade_12' ? '✅ Giải mã thành công!' : '❌ Lỗi giải mã!'}`);
}

// =====================================================================
// PHẦN 6: DEMO TẤN CÔNG PADDING ORACLE
// =====================================================================

function runAttackDemo() {
    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║   TẤN CÔNG PADDING ORACLE — KHÔI PHỤC TOÀN BỘ      ║');
    console.log('║   PLAINTEXT MÀ KHÔNG CẦN BIẾT KHÓA BÍ MẬT          ║');
    console.log('╚══════════════════════════════════════════════════════╝\n');

    // 1. Khởi tạo server
    const server = new VictimServer();
    console.log('[SERVER]  Đã khởi tạo với khóa bí mật NGẪU NHIÊN.');
    console.log(`[SERVER]  Khóa bí mật: ${bytesToHex(server.secretKey)} ← Hacker KHÔNG BIẾT\n`);

    // 2. Mã hóa tin nhắn (dùng 2 tin nhắn: ngắn và dài)
    const messages = [
        'HUST_A+_Grade_12',                                 // 16 byte → padding thành 32 byte (2 khối)
        'Xin_chao_HUST!Day_la_minh_hoa_PaddingOracle_Attack' // 48 byte → padding thành 64 byte (4 khối)
    ];

    for (let msgIdx = 0; msgIdx < messages.length; msgIdx++) {
        const secretMessage = messages[msgIdx];
        const { iv, ciphertext } = server.getEncryptedSecret(secretMessage);

        console.log(`\n${'═'.repeat(55)}`);
        console.log(`  THỬ NGHIỆM ${msgIdx + 1}: Tin nhắn "${secretMessage}" (${secretMessage.length} ký tự)`);
        console.log(`${'═'.repeat(55)}`);
        console.log(`[NGHE LÉN] IV:         ${bytesToHex(iv)}`);
        console.log(`[NGHE LÉN] Ciphertext: ${bytesToHex(ciphertext)} (${ciphertext.length} byte, ${ciphertext.length / 16} khối)`);
        console.log(`[MỤC TIÊU] Khôi phục plaintext mà KHÔNG biết khóa.\n`);

        // 3. Tấn công
        const startTime = Date.now();
        const crackedPlaintext = paddingOracleAttack(
            server.checkPadding.bind(server),
            iv,
            ciphertext,
            true // verbose
        );
        const totalTime = Date.now() - startTime;

        // 4. Kết quả
        const crackedStr = crackedPlaintext.toString('utf8');
        const success = crackedStr === secretMessage;

        console.log(`\n  ╔════════════════════════════════════════════════╗`);
        console.log(`  ║  ${success ? '✅ TẤN CÔNG THÀNH CÔNG!' : '❌ TẤN CÔNG THẤT BẠI'}                         ║`);
        console.log(`  ╠════════════════════════════════════════════════╣`);
        console.log(`  ║  Tin nhắn gốc : ${secretMessage.padEnd(32)}║`);
        console.log(`  ║  Khôi phục    : ${crackedStr.padEnd(32)}║`);
        console.log(`  ║  Thời gian    : ${String(totalTime + 'ms').padEnd(32)}║`);
        console.log(`  ╚════════════════════════════════════════════════╝`);
    }
}

// =====================================================================
// PHẦN 7: CHẠY TẤT CẢ DEMO
// =====================================================================

console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║                                                        ║');
console.log('║   🎓 ĐỒ ÁN MÔ PHỎNG AES-128 & PADDING ORACLE ATTACK  ║');
console.log('║   HUST — Lê Gia Bảo & An                              ║');
console.log('║                                                        ║');
console.log('╚══════════════════════════════════════════════════════════╝');

// Demo 1: So sánh AES128 tự cài với Node.js crypto
runComparisonDemo();

// Demo 2: Tấn công Padding Oracle
runAttackDemo();

console.log('\n╔══════════════════════════════════════════════════════════╗');
console.log('║  🏁 KẾT THÚC MÔ PHỎNG                                  ║');
console.log('╚══════════════════════════════════════════════════════════╝');
console.log('\n📌 GHI CHÚ BẢO MẬT:');
console.log('  - Đây là mã nguồn GIÁO DỤC, không dùng cho mục đích thực tế.');
console.log('  - Trong production, dùng Node.js crypto hoặc Web Crypto API.');
console.log('  - Padding Oracle là lỗ hổng THỰC TẾ, đã từng ảnh hưởng đến');
console.log('    TLS, JWT, ASP.NET, Java Server Faces, và nhiều framework khác.');
console.log('  - Cách phòng chống: Dùng chế độ AEAD (GCM), MAC-then-Encrypt,');
console.log('    hoặc trả về lỗi CHUNG cho mọi trường hợp giải mã thất bại.');
