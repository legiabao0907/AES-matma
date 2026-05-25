const crypto = require('crypto');

/**
 * PHẦN 1: DUMMY SERVER (Hệ thống giả lập của An)
 * Nhiệm vụ: Giữ khóa bí mật, mã hóa dữ liệu và cung cấp "Oracle" (Lỗ hổng báo lỗi)
 */
class VictimServer {
    constructor() {
        // Khóa bí mật (Chỉ Server biết, Hacker không thể thấy)
        this.secretKey = crypto.randomBytes(16); 
    }

    // Hàm mã hóa tin nhắn bí mật của hệ thống
    getEncryptedSecret() {
        const iv = crypto.randomBytes(16);
        const secretMessage = "HUST_A+_Grade_12"; // Đúng 16 byte để dễ demo
        
        const cipher = crypto.createCipheriv('aes-128-cbc', this.secretKey, iv);
        let encrypted = cipher.update(secretMessage, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        return { iv: iv, ciphertext: encrypted };
    }

    // ĐÂY LÀ LỖ HỔNG (ORACLE): Trả về kết quả check Padding
    // True = Padding hợp lệ (HTTP 200) | False = Lỗi Padding (HTTP 500)
    checkPadding(iv, ciphertext) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-cbc', this.secretKey, iv);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return true; // Giải mã thành công, Padding đúng chuẩn PKCS#7
        } catch (error) {
            // Lỗi BadPaddingException sẽ nhảy vào đây
            return false; 
        }
    }
}

// ======================================================================= //

/**
 * PHẦN 2: KỊCH BẢN TẤN CÔNG (Hacker - Bảo)
 * Nhiệm vụ: Bẻ khóa byte cuối cùng của bản mã mà KHÔNG CẦN biết secretKey
 */
function runAttackDemo() {
    console.log("=== BẮT ĐẦU MÔ PHỎNG PADDING ORACLE ATTACK ===\n");
    
    // 1. Khởi tạo Server
    const server = new VictimServer();
    
    // 2. Hacker nghe lén được IV và Ciphertext trên mạng
    const { iv, ciphertext } = server.getEncryptedSecret();
    console.log("[+] Hacker thu thập được IV:", iv.toString('hex'));
    console.log("[+] Hacker thu thập được Ciphertext:", ciphertext.toString('hex'));
    console.log("[!] Hacker hoàn toàn KHÔNG BIẾT secretKey.\n");

    // Tách khối (Block) - Vì tin nhắn có 1 khối, ta tấn công ngay vào IV
    // C1_fake là khối đằng trước khối mục tiêu (Ở đây ta thao tác thẳng vào IV ảo)
    let fake_iv = Buffer.from(iv);
    
    let crackedByte = null;
    let intermediateByte = null;
    const targetPadding = 0x01; // Mục tiêu ép Server hiểu byte cuối là padding 0x01

    console.log(">> Bắt đầu vòng lặp dò tìm Byte cuối cùng (256 khả năng)...\n");

    // 3. Vòng lặp Brute-force Toán học (0 đến 255)
    for (let guess = 0; guess <= 255; guess++) {
        
        // Công thức thao tác: C1_fake[15] = guess
        fake_iv[15] = guess;
        
        // Gửi lên Server để hỏi: "Cái này đúng Padding chưa?"
        const isPaddingValid = server.checkPadding(fake_iv, ciphertext);
        
        if (isPaddingValid) {
            console.log(`[!] BINGO! Server không báo lỗi ở Guess = ${guess} (Hex: 0x${guess.toString(16)})`);
            
            // TÍNH TOÁN TOÁN HỌC (Công thức lõi của đồ án)
            // 1. Tìm giá trị trung gian (Intermediate Value)
            // Intermediate = Guess ^ 0x01
            intermediateByte = guess ^ targetPadding;
            
            // 2. Tìm Bản rõ gốc (Plaintext)
            // Plaintext = Intermediate ^ IV_gốc
            crackedByte = intermediateByte ^ iv[15];
            
            break; // Đã tìm thấy, thoát vòng lặp
        }
    }

    // 4. In kết quả giải mã
    console.log("\n=== KẾT QUẢ TOÁN HỌC TÍNH ĐƯỢC ===");
    console.log(`- Intermediate Byte tính được : 0x${intermediateByte.toString(16)}`);
    console.log(`- Byte Bản rõ (Plaintext)     : 0x${crackedByte.toString(16)}`);
    console.log(`- Dịch ra ký tự ASCII         : '${String.fromCharCode(crackedByte)}'`);
    console.log("\n(Bạn hãy nhìn lại tin nhắn gốc trên code xem chữ cuối cùng có đúng là '2' không nhé!)");
}

// Chạy hàm mô phỏng
runAttackDemo();