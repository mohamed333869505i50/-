# تحويل النص أو المفتاح إلى باينري
def key_to_binary(data):
    if len(data) == 64 and all(bit in '01' for bit in data):  # إذا كان النص أو المفتاح ثنائي
        return data
    return bin(int(data, 16))[2:].zfill(64)  # إذا كان هيكس، يتم تحويله إلى باينري
# تحويل Binary إلى Hexadecimal
def binary_to_hex(binary_str):
    return hex(int(binary_str, 2))[2:].zfill(16)  # تحويل Binary إلى Hex مع تعبئة إلى 16 رقم
# تبديل النص باستخدام جدول معين
def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)
# إزاحة لليسار
def left_shift(bits, n):
    return bits[n:] + bits[:n]
def generate_keys(input_key):
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    binary_key = key_to_binary(input_key)  # تحويل المفتاح إلى باينري
    permuted_key = permute(binary_key, PC1)  # تبديل باستخدام PC-1
    L, R = permuted_key[:28], permuted_key[28:]  # تقسيم المفتاح إلى نصفين
    keys = []
    for shift in LEFT_SHIFTS:
        L, R = left_shift(L, shift), left_shift(R, shift)  # إزاحة L و R
        keys.append(permute(L + R, PC2))  # تبديل باستخدام PC-2
    return keys
    #\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
def initial_permutation(bits):
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    return permute(bits, IP)
def encrypt(plaintext, keys):
    bits = initial_permutation(plaintext)
    L, R = bits[:32], bits[32:]
    for key in keys:
        L, R = des_round(L, R, key)
    final_bits = final_permutation(R + L)
    return final_bits   
S_BOXES = [
    # S-Box 1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S-Box 2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S-Box 3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S-Box 4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S-Box 5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S-Box 6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S-Box 7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S-Box 8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]
def des_round(L, R, key):
    # توسعة النص
    E_R = permute(R, [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1])
    xor_result = bin(int(E_R, 2) ^ int(key, 2))[2:].zfill(48)  # XOR مع المفتاح
    substituted = s_box_substitution(xor_result)  # استبدال S-Boxes
    
    # تطبيق جدول P-Box
    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]
    permuted = permute(substituted, P)
    return R, bin(int(L, 2) ^ int(permuted, 2))[2:].zfill(32)
# استبدال باستخدام S-Boxes
def s_box_substitution(bits):
    result = ""
    for i in range(8):  # 8 مجموعات في الصندوق
        chunk = bits[i * 6:(i + 1) * 6]  # تقسيم 48 بت إلى 8 مجموعات من 6 بت
        row = int(chunk[0] + chunk[5], 2)  # الصف يعتمد على أول وآخر بت
        col = int(chunk[1:5], 2)  # العمود يعتمد على البتات المتوسطة
        result += f"{S_BOXES[i][row][col]:04b}"  # تحويل النتيجة إلى 4 بت
    return result

# التبديل النهائي
def final_permutation(bits):
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]
    return permute(bits, FP)
    
#/for key in keys:L, R = des_round(L, R, key)
    final_bits = final_permutation(R + L)
    return final_bits #/
# فك التشفير
def decrypt(ciphertext, keys):
    return encrypt(ciphertext, keys[::-1])  # عكس ترتيب المفاتيح
# تشغيل البرنامج
key = input("Enter a 64-bit key (hex or binary): ")  # إدخال المفتاح
plaintext = input("Enter a 64-bit plaintext (hex or binary): ")  # إدخال النص
# تحويل النصوص إلى باينري
binary_key = key_to_binary(key)
binary_plaintext = key_to_binary(plaintext)
# توليد المفاتيح
round_keys = generate_keys(binary_key)
# تشفير النص
ciphertext_binary = encrypt(binary_plaintext, round_keys)
ciphertext_hex = binary_to_hex(ciphertext_binary)
print(f"Ciphertext (Binary): {ciphertext_binary}")
print(f"Ciphertext (Hex): {ciphertext_hex}")
# فك التشفير
decrypted_binary = decrypt(ciphertext_binary, round_keys)
decrypted_hex = binary_to_hex(decrypted_binary)
print(f"Decrypted Text (Binary): {decrypted_binary}")
print(f"Decrypted Text (Hex): {decrypted_hex}")