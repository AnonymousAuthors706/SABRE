from architectures import *
from os.path import exists
import pickle
from elftools.elf.elffile import ELFFile

def read_file(file, arch_type):
    '''
    This function receive the .s file name and read its lines.
    Return : 
        List with the lines of the assembly as strings
    '''
    #assert file.endswith('.s')
    if not(exists(file)) :
        raise NameError(f'File {file} not found !!')
    with open(file,'r') as f :
        lines = f.readlines()
    # Get rid of empty lines
    lines = [x.replace('\n','') for x in lines if x != '\n']

    # ARM: Get rid of "nop" and ".word" lines
    if arch_type == 'armv8-m33':
        lines = [x for x in lines if ("nop" not in x) and (".word" not in x)]

    return lines

def set_arch(arch):
    if arch == 'elf32-msp430':
        return MSP430() 
    elif arch == 'armv8-m33':
        return ARMv8M33() 
    else: 
        return None

def dump(obj, filename):
    filename = open(filename, 'wb')
    pickle.dump(obj, filename)
    filename.close()

def load(filename):
    f = open(filename,'rb')
    obj = pickle.load(f)
    f.close()
    return obj

def clean_comment(arch, comment):
    """
    This function attempts to extract a memory address from a given comment.
    """
    if arch.type == 'elf32-msp430':
        if comment is None:
            return comment
        comment = comment.split(' ')
        for c in comment:
            if '0x' in c:
                return c.strip('ghijklmnopqrstuvwyz!@#$%^&*(),<>/?.')
    # 
    elif arch.type == 'armv8-m33':
        if comment is None:
            return comment
        # comment = comment.split(' ')
        print("comment: "+str(comment))

def set_cfg_head(cfg, start_addr, end_addr=None):
    try: 
        cfg.head = cfg.nodes[start_addr]
    except KeyError as err:
        print(bcolors.RED + f'[!] Error: Start address ({start_addr}) to verify from is not a valid node' + bcolors.END)
        exit(1)
    return cfg

def conditional_print(str, file=None, flag=True):
    if flag:
        print(str, file=file)

def update_instruction(arch, elf_file_path, instr_addr, new_instruction_bytes):
    # text_start_addr = 0x80401f8
    # empty_start_addr = 0x8060000
    text_start_addr = int(arch.text_base, 16) #0xe000
    empty_start_addr = int(arch.patch_base, 16)

    # Open the ELF file for reading and writing
    with open(elf_file_path, 'rb+') as f:
        elf = ELFFile(f)
        
        if (text_start_addr) <= instr_addr < empty_start_addr:
            section_name = '.text'
            section_start_addr = text_start_addr
        else:
            section_name = '.empty'
            section_start_addr = empty_start_addr

        # Find the .text section
        text_section = None
        for section in elf.iter_sections():
            if section.name == section_name:
                text_section = section
                break
        
        if text_section is None:
            print(f"Error: {section_name} section not found")
            return
        
        # print(f"Writing to {section_name}")
        # Calculate the offset of the instruction within the .text section
        instr_offset = instr_addr - section_start_addr
        # print(f"text_section: {text_section}")
        # print(f"instruction_offset: {instruction_offset}")
        # Seek to the offset of the instruction within the ELF file
        f.seek(text_section['sh_offset'] + instr_offset)
        # print(f"text_section['sh_offset']: {text_section['sh_offset']}")
        # Write the new instruction bytes to the ELF file
        f.write(new_instruction_bytes)
        
        # print("Instruction updated successfully")
