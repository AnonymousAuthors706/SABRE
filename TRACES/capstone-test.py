# #!/usr/bin/python

# from capstone import *
# from parse_mem import *

# CODE = b"".join(parse_mem(NS_WORLD))
# print(type(CODE))

# try:
#     md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
#     print(md.disasm(CODE, 0x80401f8, 1))
#     for i in md.disasm(CODE, 0x80401f8, 1):
#         print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

# except CsError as e:
#     print("ERROR: %s" %e)

from capstone import *
from elftools.elf.elffile import ELFFile

def disassemble_arm(file_path):
    # Open the ELF file and parse its structure
    with open(file_path, 'rb') as file:
        elf_file = ELFFile(file)

        # Initialize the Capstone disassembler for ARM
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

        # Iterate over sections
        for section in elf_file.iter_sections():
            # Check if the section is executable and has data
            if section['sh_flags'] & 0x4 and section['sh_size'] > 0:
                # Get the address and data of the section
                address = section['sh_addr']
                data = section.data()

                # Disassemble the section
                for insn in md.disasm(data, address):
                    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

if __name__ == "__main__":
    elf_file_path = './TRACES_NonSecure.elf'  # Replace with the path to your ELF file
    disassemble_arm(elf_file_path)