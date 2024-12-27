def key_to_binary(data):
    if all(bit in '01' for bit in data):
        return data
    raise ValueError("Input must be binary")

def permute(bits, table):
    if len(bits) < max(table):
        raise ValueError("Permutation table index exceeds input length")
    return ''.join(bits[i - 1] for i in table)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_keys(input_key):
    PC1 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  
    PC2 = [6, 3, 7, 4, 8, 5, 10, 9] 
    LEFT_SHIFTS = [1, 1]  

    binary_key = key_to_binary(input_key)  
    if len(binary_key) != 10:
        raise ValueError("Key must be 10 bits long")
    
    permuted_key = permute(binary_key, PC1)  

    L, R = permuted_key[:5], permuted_key[5:]  
    keys = []

    for shift in LEFT_SHIFTS:
        L, R = left_shift(L, shift), left_shift(R, shift)  
        keys.append(permute(L + R, PC2))  

    return keys

def initial_permutation(bits):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]  
    if len(bits) != 8:
        raise ValueError("Input must be 8 bits long for initial permutation")
    return permute(bits, IP)

def encrypt(plaintext, keys):
    bits = initial_permutation(plaintext)
    L, R = bits[:4], bits[4:]  

    for key in keys:
        L, R = des_round(L, R, key)

    final_bits = final_permutation(R + L)
    return final_bits

def decrypt(ciphertext, keys):
    bits = initial_permutation(ciphertext)
    L, R = bits[:4], bits[4:]  

    for key in reversed(keys):
        L, R = des_round(L, R, key)

    final_bits = final_permutation(R + L)
    return final_bits

def des_round(L, R, key):
   
    E_R = permute(R, [4, 1, 2, 3, 2, 3, 4, 1])
    xor_result = bin(int(E_R, 2) ^ int(key, 2))[2:].zfill(8)  
    substituted = s_box_substitution(xor_result)  

    P = [2, 4, 3, 1]
    permuted = permute(substituted, P)
    return R, bin(int(L, 2) ^ int(permuted, 2))[2:].zfill(4)

def s_box_substitution(bits):
    S_BOXES = [
      
        [[1, 0, 3, 2],
         [3, 2, 1, 0],
         [0, 2, 1, 3],
         [3, 1, 3, 2]],
        
        [[0, 1, 2, 3],
         [2, 0, 1, 3],
         [3, 0, 1, 0],
         [2, 1, 0, 3]]
    ]

    result = ""
    for i in range(2): 
        chunk = bits[i * 4 :(i + 1) * 4]  
        row = int(chunk[0] + chunk[3], 2) 
        col = int(chunk[1:3], 2)  
        result += f"{S_BOXES[i][row][col]:02b}"  

    return result

def final_permutation(bits):
    FP = [4, 1, 3, 5, 7, 2, 8, 6]  
    return permute(bits, FP)

def triple_des_encrypt(plaintext, keys1, keys2, keys3):
    
    step1 = encrypt(plaintext, keys1) 
   
    step2 = decrypt(step1, keys2)
    
    return encrypt(step2, keys3)

def triple_des_decrypt(ciphertext, keys1, keys2, keys3):
    
    step1 = decrypt(ciphertext, keys3)
    
    step2 = encrypt(step1, keys2)
   
    return decrypt(step2, keys1)

key1 = input("Enter the first 10-bit key (binary): ")  
key2 = input("Enter the second 10-bit key (binary): ")  
key3 = input("Enter the third 10-bit key (binary): ")  
plaintext = input("Enter an 8-bit plaintext (binary): ")  

keys1 = generate_keys(key1)
keys2 = generate_keys(key2)
keys3 = generate_keys(key3)

ciphertext_binary = triple_des_encrypt(plaintext, keys1, keys2, keys3)
print(f"Ciphertext (Binary): {ciphertext_binary}")

decrypted_binary = triple_des_decrypt(ciphertext_binary, keys1, keys2, keys3)
print(f"Decrypted Text (Binary): {decrypted_binary}")