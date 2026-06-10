# Do An Mo Phong AES-128 & Tan Cong Padding Oracle

**Truong Dai hoc Bach Khoa Ha Noi (HUST)** — Thuc hien: Le Gia Bao & An

---

## Muc Luc

1. [Gioi Thieu](#gioi-thieu)
2. [Cau Truc Du An](#cau-truc-du-an)
3. [Cach Chay](#cach-chay)
4. [Luong Chay Input & Output](#luong-chay-input--output)
   - [aes128.js — Ma Hoa & Giai Ma Khoi AES-128](#aes128js--ma-hoa--giai-ma-khoi-aes-128)
   - [padding_oracle_demo.js — Tan Cong Padding Oracle](#padding_oracle_demojs--tan-cong-padding-oracle)
5. [Mo Ta Chi Tiet Tung Ham](#mo-ta-chi-tiet-tung-ham)
   - [aes128.js — Cac Ham Thanh Phan](#aes128js--cac-ham-thanh-phan)
   - [padding_oracle_demo.js — Cac Ham Thanh Phan](#padding_oracle_demojs--cac-ham-thanh-phan)
6. [Do Phuc Tap Thuat Toan](#do-phuc-tap-thuat-toan)
7. [Ghi Chu Bao Mat](#ghi-chu-bao-mat)

---

## Gioi Thieu

Du an nay mo phong **thuat toan ma hoa khoi AES-128** tu cac phep toan co ban (khong dung thu vien) va minh hoa **lo hong Padding Oracle Attack** — mot trong nhung lo hong mat ma noi tieng nhat da tung anh huong den TLS, JWT, ASP.NET, Java Server Faces va nhieu he thong thuc te.

### Muc Tieu

| Muc tieu | Mo ta |
|----------|-------|
| **Hieu AES** | Cai dat tung buoc AES-128: S-Box, ShiftRows, MixColumns (GF(2^8)), Key Expansion |
| **Hieu tan cong** | Mo phong cach hacker khoi phuc plaintext ma khong can biet khoa bi mat |
| **Giao duc** | Code co comment tieng Viet chi tiet, phu hop cho sinh vien hoc mat ma |

---

## Cau Truc Du An

```
.
├── aes128.js                  # Lop AES128: ma hoa + giai ma 1 khoi 16 byte
├── padding_oracle_demo.js     # Mo phong tan cong Padding Oracle (AES-CBC)
├── README.md                  # File nay — tai lieu & danh gia
├── AGENTS.md                  # Huong dan cho AI coding agent
├── PHAN_CHIA_CONG_VIEC.md     # Phan chia cong viec giua hai thanh vien
└── chuong4-5.tex              # Tai lieu Ly thuyet (LaTeX)
```

---

## Cach Chay

```bash
# Che do tuong tac — nhap plaintext tu ban phim
node padding_oracle_demo.js

# Truyen plaintext truc tiep qua tham so dong lenh
node padding_oracle_demo.js "Xin chao HUST"

# Chay che do demo goc (so sanh AES128 vs Node.js crypto + tan cong 2 ban ma mau)
node padding_oracle_demo.js --demo

# Chay demo AES-128 don thuan (ma hoa + giai ma 1 khoi)
node aes128.js
```

---

## Luong Chay Input & Output

### aes128.js — Ma Hoa & Giai Ma Khoi AES-128

File nay chua **lop AES128** cai dat thuat toan AES-128 tu cac phep toan co ban. Lop nay duoc export ra nhu mot module de `padding_oracle_demo.js` su dung.

#### Luong Ma Hoa (encryptBlock)

```
INPUT:  16 byte Plaintext + 16 byte Key
        |
        v
Buoc 1: Key Expansion — mo rong khoa 128-bit thanh 11 khoa vong (176 byte)
        |
        v
Buoc 2: Khoi tao State — nap 16 byte plaintext vao ma tran 4x4 (column-major)
        |
        v
Buoc 3: AddRoundKey (Vong 0) — XOR State voi khoa goc
        |
        v
Buoc 4: Lap 9 vong (Vong 1 -> 9):
           SubBytes    — the moi byte qua S-Box (Confusion)
        -> ShiftRows    — dich vong trai cac hang (Diffusion)
        -> MixColumns   — tron cot voi ma tran GF(2^8) (Diffusion)
        -> AddRoundKey  — XOR voi khoa vong
        |
        v
Buoc 5: Vong cuoi (Vong 10) — KHONG co MixColumns:
           SubBytes -> ShiftRows -> AddRoundKey
        |
        v
OUTPUT: 16 byte Ciphertext
```

#### Luong Giai Ma (decryptBlock)

```
INPUT:  16 byte Ciphertext + 16 byte Key
        |
        v
Buoc 1: Key Expansion — giong nhu ma hoa
        |
        v
Buoc 2: Khoi tao State tu ciphertext
        |
        v
Buoc 3: AddRoundKey (Vong 10 nguoc) — XOR voi khoa vong cuoi
        |
        v
Buoc 4: Lap 9 vong nguoc (Vong 9 -> 1):
           InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
        |
        v
Buoc 5: Vong 0 nguoc — KHONG co InvMixColumns:
           InvShiftRows -> InvSubBytes -> AddRoundKey
        |
        v
OUTPUT: 16 byte Plaintext (ban ro goc)
```

---

### padding_oracle_demo.js — Tan Cong Padding Oracle

File nay mo phong **toan bo kich ban tan cong Padding Oracle**, tu viec ma hoa tin nhan bang AES-128-CBC den viec khoi phuc plaintext ma khong biet khoa.

#### Tong Quan Luong Chay

```
                           +------------------+
                           |   NGUOI DUNG     |
                           | nhap plaintext   |
                           +--------+---------+
                                    |
                                    v
                           +--------+---------+
                           |   VictimServer   |
                           | sinh khoa NGAU   |
                           | NHIEN bi mat     |
                           +--------+---------+
                                    |
                    Ma hoa AES-128-CBC + PKCS#7
                                    |
                                    v
                     +--------------+--------------+
                     | IV (16 byte) | Ciphertext   |
                     |              | (n x 16 byte)|
                     +--------------+--------------+
                                    |
                            Hacker "nghe len"
                            chi biet IV + Ciphertext
                            KHONG biet khoa!
                                    |
                                    v
              +------------------------------------------+
              |        PADDING ORACLE ATTACK             |
              |                                          |
              |  Voi moi khoi C_i trong ciphertext:      |
              |    1. Gia su prevBlock = C_{i-1}         |
              |       (hoac IV neu i=0)                  |
              |    2. Voi moi byte tu 15 -> 0:           |
              |       - Thu 256 gia tri guess            |
              |       - Goi Oracle kiem tra padding      |
              |       - Tim I_i[pos] = guess xor pad     |
              |       - Tinh P_i[pos] =                  |
              |         I_i[pos] xor prevBlock[pos]      |
              |    3. Neu gap ngo cut -> backtrack       |
              +------------------------------------------+
                                    |
                                    v
                           +--------+---------+
                           | Plaintext khoi   |
                           | phuc + unpad     |
                           +--------+---------+
                                    |
                                    v
                              OUTPUT:
                              Plaintext goc
                              (trung voi input ban dau!)
```

#### Co Che Nhan Input (Che Do Tuong Tac)

Chuong trinh ho tro 3 cach nhan input:

| Cach | Cu phap | Mo ta |
|------|---------|-------|
| **Tuong tac** | `node padding_oracle_demo.js` | Hoi nguoi dung nhap plaintext qua ban phim. Enter de dung mac dinh. |
| **Dong lenh** | `node padding_oracle_demo.js "message"` | Truyen plaintext truc tiep qua tham so. |
| **Demo goc** | `node padding_oracle_demo.js --demo` | Chay demo so sanh AES128 + tan cong 2 ban ma mau. |

#### Vi Du Input/Output

**Vi du 1: Chuoi ngan**
```
Input:  "Hello" (5 ky tu)
-> PKCS#7 them 11 byte 0x0B -> 16 byte
-> AES-128-CBC ma hoa voi IV ngau nhien -> 16 byte ciphertext (1 khoi)
-> Padding Oracle Attack (toi da 4096 lan goi Oracle)
-> Khoi phuc: "Hello" (trung khop!)
```

**Vi du 2: Chuoi 16 ky tu**
```
Input:  "HUST_A+_Grade_12" (16 ky tu)
-> PKCS#7 them 16 byte 0x10 -> 32 byte
-> AES-128-CBC ma hoa -> 32 byte ciphertext (2 khoi)
-> Padding Oracle Attack (toi da 8192 lan goi Oracle)
-> Khoi phuc: "HUST_A+_Grade_12" (trung khop!)
```

**Vi du 3: Chuoi dai**
```
Input:  "Xin_chao_HUST!Day_la_minh_hoa_PaddingOracle_Attack" (48 ky tu)
-> PKCS#7 them 16 byte 0x10 -> 64 byte
-> AES-128-CBC ma hoa -> 64 byte ciphertext (4 khoi)
-> Padding Oracle Attack (toi da 16384 lan goi Oracle)
-> Khoi phuc: "Xin_chao_HUST!Day_la_minh_hoa_PaddingOracle_Attack" (trung khop!)
```

---

## Mo Ta Chi Tiet Tung Ham

### aes128.js — Cac Ham Thanh Phan

#### 1. Bang Tra Cuu Tinh

| Ham / Bang | Nhiem vu | Van de giai quyet |
|------------|----------|-------------------|
| `SBOX` | Bang S-Box 16x16 — thuc hien phep the phi tuyen | **Confusion**: Dam bao moi byte dau ra phu thuoc phi tuyen vao byte dau vao, gay kho khan cho tham ma tuyen tinh |
| `INV_SBOX` | Bang Inverse S-Box — the nguoc cho giai ma | **Dao nguoc Confusion**: Cho phep giai ma bang cach ap dung phep the nguoc |
| `RCON` | Hang so vong Rcon — dung trong Key Expansion | **Phan tan khoa**: Dam bao moi khoa vong duoc sinh ra doc lap, chong cac tan cong lien quan den khoa (related-key attack) |

#### 2. Tien Ich Hien Thi

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `bytesToHex(bytes)` | Chuyen mang byte thanh chuoi hex de hien thi | **Debug & giam sat**: Giu lap trinh vien co the doc duoc trang thai du lieu nhi phan trong qua trinh ma hoa/giai ma |
| `printState(label, state)` | In ma tran trang thai 4x4 duoi dang hex | **Truc quan hoa**: Giu hien thi ro rang tung buoc bien doi cua State matrix, phuc vu giao duc |

#### 3. Quan Ly Trang Thai & Phep The Phi Tuyen

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `bufferToState(buffer)` | Nap 16 byte dau vao thanh ma tran State 4x4 (column-major) | **Chuan hoa du lieu**: Chuyen tu dinh dang mang phang sang ma tran cot-truoc — dung dinh dang ma AES FIPS-197 yeu cau |
| `stateToBuffer(state)` | Xuat ma tran State thanh mang 16 byte | **Dau ra chuan**: Chuyen nguoc lai tu ma tran State ve mang byte de su dung tiep |
| `subBytes(state)` | Thay moi byte trong State bang gia tri tra tu S-Box | **Confusion (Shannon)**: Moi byte dau ra phu thuoc phi tuyen vao byte dau vao. Day la thanh phan "Confusion" trong nguyen ly Confusion-Diffusion cua Shannon, gay kho khan cho viec phan tich mat ma bang thong ke |
| `invSubBytes(state)` | Thay moi byte bang gia tri tra tu Inverse S-Box | **Dao nguoc Confusion**: Can thiet de giai ma — ap dung phep the nguoc de khoi phuc byte goc |
| `addRoundKey(state, roundKey)` | XOR toan bo State voi khoa vong 16 byte | **Trang thai phu thuoc khoa**: Day la noi khoa duoc "tron" vao du lieu. Neu khong co AddRoundKey, ke tan cong co the dao nguoc tat ca cac phep bien doi khac de tim plaintext |

#### 4. Bien Doi Dai So & Truong Huu Han GF(2^8)

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `shiftRows(state)` | Dich vong trai cac hang: hang 0->0, hang 1->1, hang 2->2, hang 3->3 | **Diffusion (Shannon)**: Lan truyen anh huong cua tung byte ra toan bo cot. Sau ShiftRows, moi cot chua byte tu ca 4 cot khac nhau, tao su phu thuoc cheo trong State |
| `invShiftRows(state)` | Dich vong phai cac hang (nguoc lai voi ShiftRows) | **Dao nguoc Diffusion**: Khoi phuc vi tri byte ban dau de giai ma |
| `galoisMultiply(a, b)` | Phep nhan trong truong huu han GF(2^8) voi da thuc toi gian P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B) | **Toan hoc AES**: MixColumns yeu cau phep nhan trong GF(2^8). Ham nay cai dat thuat toan nhan "shift-and-add" co gian luoc modulo da thuc toi gian. Day la nen tang toan hoc cho toan bo tinh Diffusion cua AES |
| `mixColumns(state)` | Tron moi cot cua State voi ma tran co dinh [[02,03,01,01],[01,02,03,01],[01,01,02,03],[03,01,01,02]] | **Diffusion toi da**: Moi byte dau ra cua cot la to hop tuyen tinh cua tat ca 4 byte dau vao trong GF(2^8). Dieu nay dam bao rang thay doi 1 byte dau vao se anh huong den toan bo 4 byte dau ra cua cot do (Branch Number = 5 — toi uu) |
| `invMixColumns(state)` | Tron cot nguoc voi ma tran [[0E,0B,0D,09],[09,0E,0B,0D],[0D,09,0E,0B],[0B,0D,09,0E]] | **Dao nguoc Diffusion**: Khoi phuc trang thai cot ban dau khi giai ma |

#### 5. Mo Rong Khoa (Key Expansion)

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `keyExpansion(key)` | Mo rong khoa 128-bit goc thanh 11 khoa vong (176 byte) | **Lich trinh khoa**: Thay vi dung cung 1 khoa cho ca 10 vong (se yeu ve mat mat ma), Key Expansion sinh ra 11 khoa vong doc lap. Moi khoa vong duoc sinh bang RotWord -> SubWord -> XOR Rcon -> XOR, dam bao moi khoa vong deu "khac biet" va "khong doan duoc" tu khoa vong truoc. Neu khong co Key Expansion, AES se de bi tan cong bang slide attack |

#### 6. Ma Hoa & Giai Ma Khoi

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `encryptBlock(plaintext, key, verbose)` | Ma hoa 1 khoi 16 byte bang AES-128 qua 10 vong | **Ma hoa khoi AES-128 hoan chinh**: To hop tat ca cac ham thanh phan theo dung thu tu cua FIPS-197. Giai quyet bai toan ma hoa du lieu thanh ban ma an toan, khong the giai ma neu thieu khoa |
| `decryptBlock(ciphertext, key, verbose)` | Giai ma 1 khoi 16 byte bang AES-128 qua 10 vong nguoc | **Giai ma khoi AES-128 hoan chinh**: Ap dung cac phep bien doi nguoc theo thu tu nguoc. Dam bao tinh chat co ban cua ma hoa: decrypt(encrypt(P)) = P |
| `getRoundKey(expandedKey, round)` | Trich xuat khoa vong tu mang expanded key | **Debug & kiem tra**: Huu ich khi can kiem tra gia tri tung khoa vong trong qua trinh phat trien va giam sat |

---

### padding_oracle_demo.js — Cac Ham Thanh Phan

#### 1. Tien Ich

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `bytesToHex(bytes)` | Chuyen Buffer/mang byte thanh chuoi hex | **Hien thi du lieu nhi phan**: Giu lap trinh vien doc duoc ciphertext, IV, plaintext trong qua trinh debug |
| `xorBuffers(a, b)` | XOR hai Buffer cung do dai | **Phep toan co ban cua CBC**: XOR duoc dung trong ca ma hoa (P_i xor C_{i-1}) va giai ma (I_i xor C_{i-1}). Day la phep toan trung tam cua che do CBC |

#### 2. PKCS#7 Padding

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `pkcs7Pad(data, blockSize)` | Them byte dem PKCS#7 vao plaintext | **Dua plaintext ve boi cua 16 byte**: AES chi ma hoa duoc du lieu co do dai boi cua 16 byte. PKCS#7 giai quyet van de nay bang cach them k byte co gia tri k vao cuoi plaintext. Neu plaintext da la boi cua 16, them 16 byte 0x10 |
| `pkcs7Unpad(data)` | Go byte dem PKCS#7 + kiem tra tinh hop le | **Khoi phuc du lieu goc**: Loai bo padding sau khi giai ma. Dong thoi kiem tra tinh hop le cua padding — chinh viec kiem tra nay la nguon goc cua lo hong Padding Oracle |

#### 3. AES-128-CBC (Tu Cai Dat)

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `aes128cbcEncrypt(plaintext, key, iv)` | Ma hoa AES-128-CBC dung lop `AES128` tu cai | **Ma hoa theo che do CBC**: Chia plaintext thanh cac khoi 16 byte roi ma hoa theo cong thuc C_i = AES_encrypt(P_i xor C_{i-1}). Che do CBC giai quyet van de cua ECB (cac khoi plaintext giong nhau se cho ra ciphertext giong nhau) bang cach "xich" cac khoi lai voi nhau |
| `aes128cbcDecrypt(ciphertext, key, iv)` | Giai ma AES-128-CBC dung lop `AES128` tu cai | **Giai ma theo che do CBC**: P_i = AES_decrypt(C_i) xor C_{i-1}. Dung de kiem tra tinh dung dan cua qua trinh ma hoa |

#### 4. VictimServer (He Thong Co Lo Hong)

| Lop / Ham | Nhiem vu | Van de giai quyet |
|------------|----------|-------------------|
| `VictimServer` | Server gia lap co lo hong Padding Oracle | Mo phong mot he thong thuc te: server co khoa bi mat, ma hoa du lieu, nhung **lo ra thong tin** ve tinh hop le cua padding. Day la mo hinh cua hang ngan cuoc tan cong thuc te vao TLS, JWT, ASP.NET... |
| `constructor()` | Sinh khoa bi mat ngau nhien 16 byte | **Mo phong thuc te**: Trong thuc te, hacker khong the truy cap khoa nay — chi co the goi API check padding |
| `getEncryptedSecret(message)` | Ma hoa tin nhan + tra ve IV va ciphertext | **Mo phong kenh nghe len**: Day la nhung gi hacker "bat duoc" tren duong truyen — IV va ciphertext, nhung khong co khoa |
| `checkPadding(iv, ciphertext)` | **LO HONG**: Tra loi padding hop le hay khong | **Oracle**: Day la "lo hong" — server tiet lo 1 bit thong tin (padding OK hay khong). Tu 1 bit thong tin nay, ke tan cong co the khoi phuc TOAN BO plaintext. Ham nay su dung Node.js crypto de giai ma va tu dong bao loi khi padding sai |

#### 5. Kich Ban Tan Cong Padding Oracle

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `decryptByteCandidates(oracle, prevBlock, targetBlock, pos, knownIntermediate)` | Tan cong **1 byte** — thu 256 gia tri guess de tim intermediate value | **Khoi phuc tung byte**: Voi moi vi tri byte (tu 15 xuong 0), thu tat ca 256 gia tri de tim ra gia tri lam cho padding hop le. Tu do tinh duoc intermediate value I_i[pos] = guess xor targetPad, roi suy ra P_i[pos] = I_i[pos] xor prevBlock[pos]. Day la "dong co" cua tan cong Padding Oracle |
| `decryptBlock(oracle, prevBlock, targetBlock, verbose)` | Tan cong **toan bo 1 khoi** AES-CBC bang Padding Oracle (co backtrack) | **Khoi phuc 1 khoi hoan chinh**: Goi decryptByteCandidates cho tung byte tu 15 -> 0. Neu co nhieu ung vien (false positive), thu tung ung vien va backtrack neu byte tiep theo khong the giai ma. Giai quyet van de "false positive" — tinh huong nhieu gia tri guess cung lam padding hop le |
| `paddingOracleAttack(oracle, iv, ciphertext, verbose)` | Tan cong **toan bo ban ma** nhieu khoi | **Khoi phuc toan bo plaintext tu ciphertext**: Goi decryptBlock cho moi khoi, ghep ket qua, go PKCS#7 padding. Day la ham "dieu phoi" chinh — giai quyet bai toan tan cong Padding Oracle hoan chinh |

#### 6. Che Do Chay

| Ham | Nhiem vu | Van de giai quyet |
|-----|----------|-------------------|
| `runInteractiveMode(userMessage)` | Chay che do tuong tac: nhan plaintext, ma hoa, tan cong, khoi phuc | **Minh hoa tan cong voi du lieu nguoi dung**: Cho phep nguoi dung nhap plaintext bat ky va chung kien toan bo qua trinh tu ma hoa den khoi phuc. Giai quyet nhu cau "toi muon thu voi du lieu cua rieng toi" |
| `runComparisonDemo()` | So sanh ket qua ma hoa giua AES128 tu cai voi Node.js crypto | **Xac thuc tinh dung dan**: Kiem tra rang lop AES128 tu cai dat cho ra ket qua GIONG HET voi thu vien chuan Node.js crypto. Neu khong khop, co nghia la cai dat AES co loi |
| `runAttackDemo()` | Chay demo tan cong voi 2 ban ma mau | **Minh hoa nhanh**: Chay tan cong voi 2 tin nhan co san de nguoi dung thay duoc toc do va tinh hieu qua |
| `runAllDemos()` | Chay ca 2 demo (so sanh + tan cong) | **Kiem tra tong the**: Kich ban day du cho viec trinh bay hoac kiem tra nhanh |

---

## Do Phuc Tap Thuat Toan

### aes128.js

| Thanh phan | Do phuc tap thoi gian | Giai thich |
|------------|----------------------|------------|
| `subBytes` / `invSubBytes` | O(1) | Luon duyet 16 byte |
| `shiftRows` / `invShiftRows` | O(1) | Luon copy co dinh 16 byte |
| `galoisMultiply` | O(1) | Toi da 8 vong lap bit, early-exit khi b=0 |
| `mixColumns` / `invMixColumns` | O(1) | 4 cot x 4-16 phep nhan GF(2^8) |
| `keyExpansion` | O(1) | Co dinh 44 word voi AES-128 |
| `encryptBlock` / `decryptBlock` | O(1) | Luon 10 vong x 16 byte = 160 phep the |
| Toan bo AES-128 | O(1) | Co dinh voi kich thuoc khoi 16 byte |

### padding_oracle_demo.js

| Thanh phan | Do phuc tap thoi gian | Giai thich |
|------------|----------------------|------------|
| Tan cong 1 byte | O(1) | Luon duyet du 256 gia tri (0..255) |
| Tan cong 1 khoi | O(1) | Co ban 16 x 256 = 4096 lan Oracle; co the hon do backtracking |
| Tan cong n khoi | O(n) | Tuyen tinh theo so khoi |
| Tong so lan Oracle | n x 16 x 256 | Voi n khoi, chua tinh backtracking |
| PKCS#7 pad/unpad | O(n) | Tuyen tinh theo kich thuoc du lieu |

---

## Ghi Chu Bao Mat

- **Day la ma nguon GIAO DUC**, khong dung cho muc dich thuc te.
- Trong production, **luon su dung thu vien chuan** nhu Node.js `crypto` hoac Web Crypto API.
- **Padding Oracle la lo hong THUC TE**, da tung anh huong den TLS, JWT, ASP.NET, Java Server Faces va nhieu framework khac.
- **Cach phong chong**:
  1. Dung che do AEAD nhu **AES-GCM** hoac **ChaCha20-Poly1305** (khong can padding)
  2. Dung **Encrypt-then-MAC** — kiem tra HMAC/tag TRUOC khi xu ly padding
  3. Dung thu vien opaque nhu **libsodium/NaCl** — tu dong chon thuat toan an toan
  4. **KHONG bao gio** tiet lo thong tin ve tinh hop le cua padding (tra ve cung mot loi cho tat ca cac truong hop)
  5. **KHONG tu viet ma ma hoa** cho production — dung thu vien da duoc kiem chung
