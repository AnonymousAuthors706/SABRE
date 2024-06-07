from structures import *
from utils import *
from elftools.elf.elffile import ELFFile
from keystone import *
import os
from parse_asm import *
from verify import *
from MSProbe.assemble import *
import time

#------------------ Support for ARM ------------------#
def instr_to_binary_ARM(instr, arch):
    
    instr_addr = instr.addr
    instruction = instr.reconstruct()

    # print(f"trying '{instruction}'")
    debug = False
    if instr.instr in arch.all_br_insts:

        if ' ' in instr.arg:
            instr.arg = instr.arg.split(' ')[0]
        debug = True

        target = int(instr.arg,16)
        cur_addr = int(instr.addr,16)
        offset = target-cur_addr # shows as -4 in python, but is correct in the ELF
        instruction = instr.instr+f" #{offset}"
        print(instruction)

    # Initialize Keystone Engine for ARM Cortex-M architecture
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    # Assemble the instruction
    try:
        encoding, _ = ks.asm(instruction)
        hex_instr = ''.join(['{:02x}'.format(byte) for byte in encoding])
        bin_instr = bytes.fromhex(hex_instr)
        return bin_instr, hex_instr, debug
    except KsError as e:
        print(f"Error assembling {instruction}: {e}")
        return None

def add_instruction_ARM(asm, cfg, patch, pg, mode_1_args=None):
    if pg.mode == 1:
        loop_exit, idx = mode_1_args

        if patch.type == 0:
            asm.addr = hex(pg.base)
    
        if (asm.instr in cfg.arch.unconditional_br_instrs or asm.instr in cfg.arch.conditional_br_instrs) and idx != len(patch.instr)-1:
            if asm.arg == 'loop_exit':
                asm.arg = loop_exit
            else:
                for i in range(0, len(patch.instr)):
                    instr = patch.instr[i]
                    if instr.prev_addr is not None:
                        if instr.prev_addr[2:] in asm.arg:
                            asm.arg = asm.arg.replace(instr.prev_addr[2:], instr.addr[2:])
        bin_instr, hex_instr, debug = instr_to_binary_ARM(asm, cfg.arch)

        patch.instr[idx] = asm
        patch.bin[idx] = bin_instr
        patch.hex[idx] = hex_instr

        if patch.type == 0:
            pg.base += int(len(hex_instr)/2)
    else: 
        patch.instr.append(asm)
        patch.bin.append(b'')
        patch.hex.append('')

    return patch

def safe_loop_init_ARM(patch, def_addr, param, full_arg, cfg, pg):
    
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'r9, {param}')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    
    # str r9 [init_dest]
    asm = AssemblyInstruction(addr=None, instr='str', arg=f'r9, {full_arg}')
    patch = add_instruction_ARM(asm, cfg, patch, pg)

    return patch

def safe_loop_mem_access_ARM(patch, pg, def_addr, param, base_reg, full_arg, loopcount, loop_end_addr, cfg):
    # mov base reg into r10
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'r10, {base_reg}')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    
    # sub r9 from r10, (init base from base) to get the offset/loop count
    asm = AssemblyInstruction(addr=None, instr='sub', arg=f'r10, r10, r9')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    
    # compare loop count (in r10) to max count from analysis
    asm = AssemblyInstruction(addr=None, instr='cmp', arg=f'r10, #{loopcount}')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    
    ## if eequal, we branch to the loop's exit
    loop_exit = hex(int(loop_end_addr,16)+14)[2:] # 14 bytes added from patch
    asm = AssemblyInstruction(addr=None, instr='bge.n', arg=f'loop_exit')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    ## otherwise, we do the memory write
    asm = AssemblyInstruction(addr=None, instr='strb', arg=f'{param}, {full_arg}')
    patch = add_instruction_ARM(asm, cfg, patch, pg)
    return patch, loop_exit

def patch_nodes_ARM(pg, cfg):
    ## Given where patches should be applied,
    ##traverse cfg nodes and patch the nodes
    ## find node that needs a patch by checking if unsafe addr is in the node bounds
    patches = []
    patch_addrs = list(pg.patches.keys())
    # print(f'PATCH_ADDRS: {patch_addrs}')
    for unsafe_addr in patch_addrs:
        # print(f'UNSAFE_ADDR: {unsafe_addr}')
        for node_addr in cfg.nodes.keys():
            node = cfg.nodes[node_addr]
            if int(node.start_addr, 16) <= int(unsafe_addr, 16) <= int(node.end_addr, 16):
                # print(f"PATCHING NODE WITH NODE_ADDR = {node_addr}")
                p = patch_node_ARM(pg, node_addr, node.instr_addrs, cfg)
                patches.append(p)
    return patches

def patch_node_ARM(pg, node_addr, node_instrs, cfg):
    patch = Patch(node_addr)
    patch.type = 1

    p = pg.patches[node_addr]
    target_addr = hex(int(p.instr[0].addr, 16))
    asm = AssemblyInstruction(addr=node_addr, instr='b.n', arg=f"{target_addr[2:]}")
    pg.mode = 0
    patch = add_instruction_ARM(asm, cfg, patch, pg, (0, 0))
    pg.mode = 1
    patch = add_instruction_ARM(asm, cfg, patch, pg, (0, 0))
    patch.bytes = b''.join(patch.bin)
    return patch

def rewrite_nodes_ARM(pg, def_addr, param, full_arg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, loop_end_addr):
    print()
    print('INIT SITE: ')
    print(f'{def_addr}, {param}, {full_arg}')
    print()

    pg.mode = 0
    # first rewrite node for init site
    for node_addr in cfg.nodes.keys():
        node = cfg.nodes[node_addr]
        if int(node.start_addr, 16) <= int(def_addr, 16) <= int(node.end_addr, 16):
            patch = Patch(node_addr)
            patch.type = 0
            node_instrs = node.instr_addrs
            for instr in node_instrs:
                if instr.addr == def_addr:
                    patch = safe_loop_init_ARM(patch, def_addr, param, full_arg, cfg, pg)
                else:
                    instr.prev_addr = instr.addr
                    patch = add_instruction_ARM(instr, cfg, patch, pg)
        elif int(node.start_addr, 16) <= int(expl_instr_addr, 16) <= int(node.end_addr, 16):
            node_instrs = node.instr_addrs
            for instr in node_instrs:
                if instr.addr == expl_instr_addr:
                    loop_end_offest = int(loop_end_addr,16)-int(node.start_addr,16)
                    adj_loop_end_addr = hex(loop_end_offest+int(patch.instr[0].addr, 16))
                    patch, loop_exit = safe_loop_mem_access_ARM(patch, pg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, adj_loop_end_addr, cfg)
                else:
                    instr.prev_addr = instr.addr
                    patch = add_instruction_ARM(instr, cfg, patch, pg)
            # # branch back to the site
            ## not sure why need to add 4 when its just one instruction.....
            br_dest = hex(int(node.adj_instr,16))[2:]
            addr = hex(int(patch.instr[-1].addr,16)+2)
            # print(f"!!!!!!!! TRYING ADDR: {addr}")
            asm = AssemblyInstruction(addr=None, instr='b.n', arg=f'{br_dest}')
            asm.prev_addr = addr
            patch = add_instruction_ARM(asm, cfg, patch, pg)
            patch.bytes = b''.join(patch.bin)

    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_ARM(instr, cfg, patch, pg, (loop_exit, i))

    patch.type = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_ARM(instr, cfg, patch, pg, (loop_exit, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))

    pg.patches[patch.addr] = patch
    pg.total_patches += 1

def find_patch_variable_ARM(cfg, node_addr, expl_instr_addr, exp_func, tgt):
    tgt_param, tgt_full_arg, tgt_base_reg, tgt_def_addr, idx = tgt

    i=idx
    REG = 0
    MEM = 1
    last_def_type = REG
    def_label = ['REG', 'MEM']

    addr = node_addr
    func_addr = cfg.label_addr_map[exp_func]
    last_def_type = REG
    first = True
    base_reg = tgt_base_reg
    full_arg = tgt_full_arg
    while addr != func_addr:
        
        if first:
            while cfg.nodes[addr].instr_addrs[i].addr != expl_instr_addr:
                i -= 1
            first = False
            print(f'First time: skipping ahead to start at exploited instr {expl_instr_addr}')
        else:
            i = len(cfg.nodes[addr].instr_addrs)-1

        # print(f'i = {i}')
        while i >= 0:
            instr = cfg.nodes[addr].instr_addrs[i]
            # print(f"{instr.addr}")
            parts = cfg.nodes[addr].instr_addrs[i].arg.split(',')
            def_via_mov = base_reg in instr.arg and ('mov' in instr.instr or 'add' in instr.instr) and 'sp' not in instr.arg
            def_via_ldr = base_reg in instr.arg and 'ldr' in instr.instr
            def_via_str = full_arg in instr.arg and 'str' in instr.instr 


            if last_def_type == REG:
                # print('trying reg mode...')
                if def_via_mov:
                    param = parts[0].replace(' ','')
                    full_arg = ''
                    base_reg = parts[1].replace(' ','')
                    def_addr = instr.addr

                elif def_via_ldr:
                    param = parts[0]
                    full_arg = ','.join(parts[1:])
                    base_reg = full_arg.split(',')[0].replace('[','').replace(' ','')
                    def_addr = instr.addr

                    if param != base_reg:
                        last_def_type = MEM #since def came from mem

            else: #last_def_type == MEM
                # print('trying mem mode...')
                if def_via_str:
                    last_def_type = REG #since def came from reg
                    param = parts[0]
                    full_arg = ','.join(parts[1:])
                    base_reg = full_arg.split(',')[0].replace('[','').replace(' ','')
                    def_addr = instr.addr

            i -= 1
        # print(f'parents: {cfg.nodes[addr].parents}')
        addr = [p for p in cfg.nodes[addr].parents if p != addr][0]

    return param, full_arg, base_reg, def_addr

def generate_patch_ARM(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx, emulator):
    start = time.time()
    # print('------- Generating Patch ---------')
    instrs = [instr.addr for instr in cfg.nodes[node_addr].instr_addrs]
    idx = instrs.index(expl_instr_addr)
    print(idx)
    
    patch_base = cfg.arch.patch_base
    # print(f'patch_base: {patch_base}')

    ## get just the base reg, have to remove brackets and white space
    parts = cfg.nodes[node_addr].instr_addrs[idx].arg.split(',')
    tgt_param = parts[0]
    tgt_full_arg = ','.join(parts[1:])
    tgt_base_reg = tgt_full_arg.split(',')[0].replace('[','').replace(' ','')
    tgt_def_addr = cfg.nodes[node_addr].instr_addrs[idx].addr

    tgt = (tgt_param, tgt_full_arg, tgt_base_reg, tgt_def_addr, idx)

    param, full_arg, base_reg, def_addr = find_patch_variable_ARM(cfg, node_addr, expl_instr_addr, exp_func, tgt)

    reg, offset = full_arg.split(', ')
    reg = reg.replace('[', '').replace(' ', '')
    offset = offset.replace('#', '').replace(']', '')
    if '-' not in offset:
        offset = ' + '+offset

    stack_addr = emulator.evaluate_expression(emulator.get_reg(reg) + offset)
    base_addr = emulator.get_mem(stack_addr)
    ctrl_data_stack_addr = emulator.get_reg(tgt_base_reg)
    new_loop_count = emulator.evaluate_expression(ctrl_data_stack_addr + ' - ('+base_addr+')')


    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"\tLocate addr_init part 2: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()

    pg = PatchGenerator(patch_base)

    print('PATCH GENERATOR')
    print(pg)

    loop_end_addr = cfg.nodes[node_addr].instr_addrs[-1].addr
    print(f'loop_end_addr: {loop_end_addr}')    

    rewrite_nodes_ARM(pg, def_addr, param, full_arg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, loop_end_addr)
    
    ## replace unsafe ops in node with b's to the safe code
    patches = patch_nodes_ARM(pg, cfg)

    ### printing
    print('NODE PATCHES: ')
    for p in patches:
        print(p)
        pg.patches['self'] = p

    print()
    print("---- Generated Patches ----")
    count = 0
    for addr, patch in pg.patches.items():
        print(f"Patch {count}: patches {patch.addr}")
        for i in range(0, len(patch.instr)):
            instr = patch.instr[i]
            print(f"{instr.addr}({instr.prev_addr})\t\t{instr.reconstruct()}\t{patch.hex[i]}\t{patch.bin[i]}")
        print()
        count += 1
    
    # a = input()

    ## iterate over the patches and add the 
    elf_file_path = 'patched.elf'
    count=0
    print("---- Updating ELF ----")
    start = time.time()
    for addr, patch in pg.patches.items():
        print(f"Patch {count}...")
        for i in range(0, len(patch.instr)):
            instr_addr = int(patch.instr[i].addr, 16)
            # print(f"Updating {patch.instr[i].addr} to {patch.bin[i]}")
            update_instruction(cfg.arch, elf_file_path, instr_addr, patch.bin[i])
        count += 1
    pg.dump_patch_bin()
    
    bash_cmd = "arm-none-eabi-objdump -d ./patched.elf > ./patched.lst"
    os.system(bash_cmd)
    
    return pg

#------------------ Support for MSP430 ------------------#
def instr_to_binary_MSP430(instr, arch):
    debug = False
    instr_addr = instr.addr
    
    instruction = instr.reconstruct()

    # MSProbe needs white space after comma
    if instruction.count(',') > instruction.count(', '):
        instruction = instruction.replace(',', ', ')

    # from MSProbe: returns decimal int encoding of the instr.
    hex_list = assemble(instruction)
    
    hex_instr = '0x'
    for h in hex_list:
        hex_instr += hexrep(h)
    hex_instr = int(hex_instr, 16)
    bin_instr = hex_instr.to_bytes(2*len(hex_list), 'big') #big here since returned as little already from assemble()

    accum = ''
    for h in hex_list:
        accum += hexrep(h)
    
    hex_instr = accum

    return bin_instr, hex_instr, debug

def add_instruction_MSP430(asm, cfg, patch, pg, mode_1_args=None):
    if pg.mode >= 1:
        if patch.type == 0:
            asm.addr = hex(pg.base)

        loop_exit, idx = mode_1_args
        
        if (asm.instr in cfg.arch.unconditional_br_instrs or asm.instr in cfg.arch.conditional_br_instrs) and idx != len(patch.instr)-1:
            if asm.arg == 'loop_exit':
                asm.arg = loop_exit
            if pg.mode == 2:
                do_something = 1

                if asm.prev_addr != None:
                    offset = asm.arg.replace('$', '')

                    old_ref_addr = hex(int(asm.prev_addr, 16)+int(offset))

                    cur_ref_addr = ''
                    for instr in patch.instr:

                        if instr.prev_addr == old_ref_addr:
                            cur_ref_addr = instr.addr
                            break

                    new_offset = int(cur_ref_addr, 16)-int(asm.addr, 16)

                    if new_offset > 0:
                        asm.arg = f"$+{new_offset}"
                    else:
                        asm.arg = f"${new_offset}"

        bin_instr, hex_instr, debug = instr_to_binary_MSP430(asm, cfg.arch)
        patch.instr[idx] = asm
        patch.bin[idx] = bin_instr
        patch.hex[idx] = hex_instr

        if patch.type == 0:
            pg.base += int(len(hex_instr)/2)
    else: 
        #since some overlapping nodes, need to check if the instr is already there
        # if not there, append everything
        # otherwise, return
        for pi in patch.instr:
            if pi.addr != None and pi.addr == asm.addr:
                # print(f'blocking {pi.addr}')
                return patch 

        # print(f"adding {asm.addr}")
        patch.instr.append(asm)
        patch.bin.append(b'')
        patch.hex.append('')

    return patch

def safe_loop_init_MSP430(patch, def_addr, param, base_reg, cfg, pg):
    # move initial value into resevred reg
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'{base_reg}, r9')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    # move into the base reg
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'r9, {param}')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    return patch

def safe_loop_mem_access_MSP430(patch, pg, def_addr, param, base_reg, full_arg, loopcount, cfg):
    # mov base reg into r10
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'{base_reg}, r10')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # sub r9 from r10, (init base from base) to get the offset/loop count
    asm = AssemblyInstruction(addr=None, instr='sub', arg=f'r9, r10')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # compare loop count (in r10) to max count from analysis
    asm = AssemblyInstruction(addr=None, instr='cmp', arg=f'#{loopcount}, r10')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    ## if eequal, we branch to the loop's exit
    asm = AssemblyInstruction(addr=None, instr='jge', arg=f'loop_exit')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    ## otherwise, we do the memory write
    print(f"base_reg : {base_reg}")
    print(f"param : {param}")
    print(f"full_arg : {full_arg}")
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'{param}, {full_arg}')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    return patch

def find_patch_variable_MSP430(cfg, node_addr, expl_instr_addr, exp_func, tgt):
    tgt_param, tgt_full_arg, tgt_base_reg, tgt_def_addr, idx = tgt

    i=idx
    REG = 0
    MEM = 1
    type_label = ['REG', 'MEM']
    last_def_type = REG # mem write is of the form REG --> MEM

    addr = node_addr
    func_addr = cfg.label_addr_map[exp_func]
    first = True
    base_reg = tgt_base_reg
    full_arg = tgt_full_arg
    param = tgt_param
    def_addr = tgt_def_addr
    print(f"Starting from {addr} until {func_addr}")
    while addr != func_addr:
        
        if first:
            while cfg.nodes[addr].instr_addrs[i].addr != expl_instr_addr:
                i -= 1
            first = False
            print(f'First time: skipping ahead to start at exploited instr {expl_instr_addr}')
        else:
            i = len(cfg.nodes[addr].instr_addrs)-1

        while i >= 0:
            instr = cfg.nodes[addr].instr_addrs[i]

            parts = cfg.nodes[addr].instr_addrs[i].arg.split(',')
            if len(parts) == 2:
                src = parts[0]
                dest = parts[1]
                mem_dest = ('(' in dest or '@' in dest)
                mem_src = ('(' in src or '@' in src)
                reg_src = '#' not in src
                def_via_other = base_reg in dest and base_reg not in src and reg_src and 'mov' not in instr.instr
                def_via_mov = base_reg in dest and base_reg not in src and reg_src and not mem_dest and not mem_src and 'mov' in instr.instr
                def_via_ldr = base_reg in dest and mem_src and reg_src and base_reg not in src and 'mov' in instr.instr
                def_via_str = base_reg in dest and mem_dest and reg_src and base_reg not in src and 'mov' in instr.instr

                if last_def_type == REG:
                    if def_via_other:
                        if '@' in src or '(' in src:
                            param = base_reg
                            base_reg = src                        
                            def_addr = instr.addr
                            last_def_type = MEM

                    elif def_via_mov:
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr

                    elif def_via_ldr:
                        last_def_type = MEM
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr

                else:
                    if def_via_str:
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr

            i -= 1

        addr = [p for p in cfg.nodes[addr].parents if p != addr][0]
    return param, base_reg, def_addr

def rewrite_nodes_MSP430(pg, def_addr, param, base_reg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, exp_func, loop_end_addr, vul_mem_func_bounds):
    exp_func_addr = cfg.label_addr_map[exp_func]
    func_start_addr, func_end_addr = vul_mem_func_bounds

    pg.mode = 0
    patch_not_init = True
    # first rewrite node for init site
    for node_addr in sorted(cfg.nodes.keys()):
        node = cfg.nodes[node_addr]
        if int(node.start_addr, 16) <= int(def_addr, 16) and int(def_addr, 16) <= int(node.end_addr, 16):
            if patch_not_init:
                patch = Patch(node_addr)
                patch_not_init = False
            
            patch.type = 0
            node_instrs = node.instr_addrs
            for instr in node_instrs:
                if instr.addr == def_addr:
                    patch = safe_loop_init_MSP430(patch, def_addr, param, base_reg, cfg, pg)
                else:
                    instr.prev_addr = instr.addr
                    patch = add_instruction_MSP430(instr, cfg, patch, pg)
        
        elif int(node.start_addr, 16) <= int(expl_instr_addr, 16) and int(expl_instr_addr, 16) <= int(node.end_addr, 16):

            if patch_not_init:
                patch = Patch(node_addr)
                patch_not_init = False

            node_instrs = node.instr_addrs
            for instr in node_instrs:
                if instr.addr == expl_instr_addr:
                    loop_end_offest = int(loop_end_addr,16)-int(expl_instr_addr,16)+2 #plus 2 for msp430

                    if loop_end_offest > 0:
                        loop_exit = "$+"+str(loop_end_offest)
                    else:
                        loop_exit = "$"+str(loop_end_offest)

                    patch = safe_loop_mem_access_MSP430(patch, pg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, cfg)
                else:
                    instr.prev_addr = instr.addr
                    patch = add_instruction_MSP430(instr, cfg, patch, pg)
        
        elif int(func_start_addr, 16) <= int(node_addr, 16) and int(node_addr, 16) <= int(func_end_addr, 16):
            if patch_not_init:
                patch = Patch(node_addr)
                patch_not_init = False

            node_instrs = node.instr_addrs
            for instr in node_instrs:
                instr.prev_addr = instr.addr
                patch = add_instruction_MSP430(instr, cfg, patch, pg)
    
    patch.bytes = b''.join(patch.bin)
    
    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (loop_exit, i))

    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (loop_exit, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    pg.patches[patch.addr] = patch
    pg.total_patches += 1
    
def patch_nodes_MSP430(pg, cfg):
    patches = []
    patch_addrs = list(pg.patches.keys())
    # print(f'PATCH_ADDRS: {patch_addrs}')
    for unsafe_addr in patch_addrs:
        # print(f'UNSAFE_ADDR: {unsafe_addr}')
        for node_addr in cfg.nodes.keys():
            node = cfg.nodes[node_addr]
            if int(node.start_addr, 16) <= int(unsafe_addr, 16) <= int(node.end_addr, 16):
                print(f"PATCHING NODE WITH NODE_ADDR = {node_addr}")
                p = patch_node_MSP430(pg, node_addr, node.instr_addrs, cfg)
                patches.append(p)
    return patches

def patch_node_MSP430(pg, node_addr, node_instrs, cfg):
    patch = Patch(node_addr)
    patch.type = 1

    p = pg.patches[node_addr]
    target_addr = int(p.instr[0].addr, 16)
    print(f"patch_node() Target addr: {hex(target_addr)}")
    asm = AssemblyInstruction(addr=node_addr, instr='br', arg=f"#{target_addr}")
    for i in range(0, 2):
        pg.mode = i
        patch = add_instruction_MSP430(asm, cfg, patch, pg, (0, 0))
    patch.bytes = b''.join(patch.bin)
    return patch

def generate_patch_MSP430(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx, vul_mem_func_bounds, emulator):
    start = time.time()
    # print('------- Generating Patch ---------')
    instrs = [instr.addr for instr in cfg.nodes[node_addr].instr_addrs]
    idx = instrs.index(expl_instr_addr)
    print(idx)
    
    patch_base = cfg.arch.patch_base
    parts = cfg.nodes[node_addr].instr_addrs[idx].arg.split(',')
    tgt_param = parts[0]
    tgt_full_arg = ','.join(parts[1:])
    if '@' in tgt_full_arg:
        # is of the form @reg
        tgt_base_reg = tgt_full_arg.replace('@', '')
    else:
        # is of the form offset(reg)
        tgt_base_reg = tgt_full_arg.split('(')[1].replace('(','').replace(')','')
    tgt_def_addr = cfg.nodes[node_addr].instr_addrs[idx].addr

    tgt = (tgt_param, tgt_full_arg, tgt_base_reg, tgt_def_addr, idx)
    param, base_reg, def_addr = find_patch_variable_MSP430(cfg, node_addr, expl_instr_addr, exp_func, tgt)
    offset, reg = param.split('(')
    reg = reg.replace(')', '')
    stack_addr = emulator.evaluate_expression(emulator.get_reg(reg) + offset)
    buff_base_addr = emulator.get_mem(stack_addr)
    ctrl_data_stack_addr = emulator.get_reg(tgt_base_reg)
    new_loop_count = emulator.evaluate_expression(ctrl_data_stack_addr + ' - ('+buff_base_addr+')')

    pg = PatchGenerator(patch_base)
    pg.mode = 0
    print('PATCH GENERATOR')
    print(pg)
    
    ## replace the mem access with a branch to new loc
    ## checks mem access compared to the base and loop count
    loop_end_addr = cfg.nodes[node_addr].adj_instr

    ## use this info to rewrite the corrupted func
    rewrite_nodes_MSP430(pg, def_addr, param, base_reg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, new_loop_count, exp_func, loop_end_addr, vul_mem_func_bounds)

    ## replace unsafe ops in node with b's to the safe code
    patches = patch_nodes_MSP430(pg, cfg)

    print('NODE PATCHES: ')
    for p in patches:
        print(p)
        pg.patches['self'] = p
    
    ## iterate over the patches and add the 
    elf_file_path = 'patched.elf'
    count=0
    print("---- Updating ELF ----")
    start = time.time()
    for addr, patch in pg.patches.items():
        # print(f"\tAdding Patch {count}...")
        for i in range(0, len(patch.instr)):
            instr_addr = int(patch.instr[i].addr, 16)
            # print(f"Updating {patch.instr[i].addr} to {patch.bin[i]}")
            update_instruction(cfg.arch, elf_file_path, instr_addr, patch.bin[i])
        count += 1

    pg.dump_patch_bin()
    
    bash_cmd = "msp430-objdump -d patched.elf > patched.lst"
    os.system(bash_cmd)

    return pg
