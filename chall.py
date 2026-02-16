import struct
#Extracted bytes from xmmword_7FF6EBA54900 16 bytes in little endian
part1=bytes.fromhex("0D8FFF415E89A804F9FACC6850A34E95")
#Extracted from xmmword_7FF6EBA54910 16 bytes also little endian
part2=bytes.fromhex("78E18A6BA55AAEF317E55D0B65D8D34C")
#this two lines were hardcoded in v7/v8 from the pseudo
part3=struct.pack('<Q', 0x2A5993F984037330)
part4=struct.pack('<I',0x0B8A83F0)

encrypted_buffer=part1+part2+part3+part4
intermediate_bytes=bytearray()
for i in range(0,len(encrypted_buffer),4):
    chunk=encrypted_buffer[i:i+4]
    if len(chunk)<4: break
    val=struct.unpack('<I',chunk)[0]
    decrypted_block=val ^ 0xC3D2E1F0
    intermediate_bytes+=struct.pack('<I',decrypted_block)
#rotate right helper
def ror(val,r_bits,max_bits=8):
    return ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
        (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))

flag= ""

for i, byte_val in enumerate(intermediate_bytes):
    v19 = byte_val ^ ((92 - 9 * i) & 0xFF)

    rot_amt = (5 * i + 1) & 7
    v18 = ror(v19, rot_amt)
    mod_val = (3 * i + 7) % 29
    v17 = (v18 - mod_val) & 0xFF
    key_val = (11 * i - 89) & 0xFF
    original_char = v17 ^ key_val

    flag += chr(original_char)

print(flag)
