from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import sys

def get_function_address(elffile, func_name):
    for section in elffile.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol.name == func_name:
                    return symbol['st_value'], symbol['st_size']

def va_to_offset(elffile, va):
    for segment in elffile.iter_segments():
        seg_start = segment['p_vaddr']
        seg_end = seg_start + segment['p_memsz']
        if seg_start <= va < seg_end:
            return va - seg_start + segment['p_offset']

def patch_between_funcs3(filename, func1, func2, key):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        va1, size1 = get_function_address(elffile, func1)
        va2, size2 = get_function_address(elffile, func2)

        start_va = min(va1, va2)
        end_va = max(va1 + size1, va2 + size2)

        start_offset = va_to_offset(elffile, start_va)
        end_offset = va_to_offset(elffile, end_va)
        size = end_offset - start_offset

        print("+ bytes from VA {} to {}".format(size, hex(start_va), hex(end_va)))
        print("+ offset: {} to {}".format(hex(start_offset), hex(end_offset)))

        f.seek(0)
        data = bytearray(f.read())

    for i in range(start_offset, end_offset):
        data[i] = ((0xF & data[i])<<4) | ((0xF0 & data[i]) >> 4)

    output_file = filename + ""
    with open(output_file, 'wb') as f:
        f.write(data)

    print("+ binary written : {}".format(output_file))

def patch_between_funcs2(filename, func1, func2, key):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        va1, size1 = get_function_address(elffile, func1)
        va2, size2 = get_function_address(elffile, func2)

        start_va = min(va1, va2)
        end_va = max(va1 + size1, va2 + size2)

        start_offset = va_to_offset(elffile, start_va)
        end_offset = va_to_offset(elffile, end_va)
        size = end_offset - start_offset

        print("+ bytes from VA {} to {}".format(size, hex(start_va), hex(end_va)))
        print("+ offset: {} to {}".format(hex(start_offset), hex(end_offset)))

        f.seek(0)
        data = bytearray(f.read())

    for i in range(start_offset, end_offset):
        data[i] ^= key
        key = (key + 67)%256

    output_file = filename + ""
    with open(output_file, 'wb') as f:
        f.write(data)

    print("+ binary written : {}".format(output_file))

# Original random mapping
mapping = [
    223, 137, 199, 91, 171, 2, 227, 106, 36, 34, 44, 39, 251, 111, 172, 19,
    81, 97, 14, 54, 208, 90, 83, 135, 184, 37, 56, 107, 16, 159, 219, 149,
    166, 133, 28, 63, 168, 123, 197, 50, 103, 151, 189, 141, 60, 23, 9, 134,
    68, 20, 11, 150, 221, 156, 64, 217, 214, 164, 218, 225, 25, 126, 0, 99,
    147, 226, 122, 55, 104, 195, 35, 22, 51, 179, 202, 43, 240, 26, 196, 33,
    192, 247, 1, 110, 71, 131, 124, 244, 80, 190, 167, 86, 254, 185, 112, 215,
    117, 4, 239, 198, 24, 40, 102, 193, 75, 212, 7, 47, 116, 5, 203, 237,
    238, 216, 58, 161, 252, 32, 143, 250, 108, 96, 127, 139, 27, 222, 200, 53,
    101, 187, 152, 41, 228, 6, 144, 163, 8, 136, 173, 140, 170, 138, 142, 30,
    38, 242, 220, 157, 15, 211, 162, 243, 249, 233, 118, 128, 224, 186, 49, 119,
    82, 248, 109, 229, 207, 3, 65, 114, 241, 174, 74, 246, 61, 52, 158, 88,
    153, 230, 31, 21, 115, 155, 206, 121, 178, 234, 181, 85, 87, 236, 148, 130,
    169, 67, 46, 154, 210, 175, 72, 70, 120, 76, 94, 10, 12, 182, 129, 78,
    84, 183, 209, 145, 125, 255, 62, 42, 45, 160, 92, 191, 194, 79, 201, 95,
    188, 245, 73, 205, 253, 29, 176, 66, 59, 98, 17, 100, 105, 204, 146, 93,
    213, 231, 89, 77, 235, 13, 165, 132, 177, 48, 232, 180, 57, 18, 113, 69
]


def patch_between_funcs1(filename, func1, func2, key):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        va1, size1 = get_function_address(elffile, func1)
        va2, size2 = get_function_address(elffile, func2)

        start_va = min(va1, va2)
        end_va = max(va1 + size1, va2 + size2)

        start_offset = va_to_offset(elffile, start_va)
        end_offset = va_to_offset(elffile, end_va)
        size = end_offset - start_offset

        print("+ bytes from VA {} to {}".format(size, hex(start_va), hex(end_va)))
        print("+ offset: {} to {}".format(hex(start_offset), hex(end_offset)))

        f.seek(0)
        data = bytearray(f.read())

    for i in range(start_offset, end_offset):
        data[i] = mapping[data[i]]

    output_file = filename + ""
    with open(output_file, 'wb') as f:
        f.write(data)

    print("+ binary written : {}".format(output_file))

def inver_map_output():
    inverse_mapping = [0] * 256
    for i in range(256):
        inverse_mapping[mapping[i]] = i
    for i in range(256):
        if(i % 16 ==0):
            print()
        print(inverse_mapping[i], end=" ")


if __name__ == "__main__":
    binary = ""
    func1 = ""
    func2 = ""
    if len(sys.argv) != 5:
        # print("Usage: python crypt.py <binary> <func1> <func2> <start_key>")
        binary = "safe_main"
        func1 = "codecave"
        func2 = "print_bytes"
        key = int(sys.argv[1], 16)
    else:
        binary = sys.argv[1]
        func1 = sys.argv[2]
        func2 = sys.argv[3]
        key = int(sys.argv[4], 16) #note self: input FF or OxFF works
    
    print(key)
    patch_between_funcs3(binary, "codecave", "print_bytes", key)
    patch_between_funcs2(binary, "codecave", "crypt3", key)
    patch_between_funcs1(binary, "codecave", "crypt2", key)
