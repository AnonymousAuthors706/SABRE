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
        # print(f"Arrived in instr_to_binary with asm.arg = {instr.arg}")
        # print(f"Instruction = {instruction}")
        # it is a branching instruction
        # need to replace addr with pc offset
        if ' ' in instr.arg:
            instr.arg = instr.arg.split(' ')[0]
        debug = True
        # print(f"addr: {instr.addr}")
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
        # if debug == True:
        #     print(encoding)
        # encoding = encoding[::-1]
        hex_instr = ''.join(['{:02x}'.format(byte) for byte in encoding])
        # print(hex_instr)
        bin_instr = bytes.fromhex(hex_instr)
        # print(bin_instr)
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
                            # print(f"!!!!!! FOUND {instr.prev_addr[2:]} in {asm.arg}")
                            # print(f"!!!!!! REPLACING {instr.prev_addr[2:]} with {instr.addr[2:]}")
                            # print(f"BEFORE: asm.arg = {asm.arg}")
                            asm.arg = asm.arg.replace(instr.prev_addr[2:], instr.addr[2:])
                            # print(f"AFTER: asm.arg = {asm.arg}")
                            # print(f"Calling instr_to_binary with asm.arg = {asm.arg}")
        bin_instr, hex_instr, debug = instr_to_binary_ARM(asm, cfg.arch)
        # if debug:
            # print(f"ASM AFTER RETURN  = {asm}")
        # patch.instr.append(asm)
        patch.instr[idx] = asm
        patch.bin[idx] = bin_instr
        patch.hex[idx] = hex_instr
        # print(f"{patch.instr[idx].addr}({patch.instr[idx].prev_addr})\t\t{patch.instr[idx].reconstruct()}\t{patch.hex[idx]}\t{patch.bin[idx]}")

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
    # for instr in node_instrs:
    #     if instr.addr in pg.patches.keys():
    #         p = pg.patches[instr.addr]
    #         print('GOT THIS PATCH: ')
    #         print(p)
    #         asm = AssemblyInstruction(addr=instr.addr, instr='b.n', arg=f"{p.instr[0].addr[2:]}")
    #         patch = add_instruction_ARM(asm, cfg, patch, pg)
        # else:
            # patch = add_instruction_ARM(instr, cfg, patch, pg)

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
    # next rewrite the node for vuln site
    # print('VULNERABILITY SITE: ')
    # print(f'{expl_instr_addr} {tgt_param}, {tgt_base_reg}, {tgt_full_arg}')
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
                    # print()
                    # print(f'node.start_addr: {node.start_addr}')
                    # print(f'loop_end_addr: {loop_end_addr}')
                    # print(f"loop_end_offest: {loop_end_offest}")
                    adj_loop_end_addr = hex(loop_end_offest+int(patch.instr[0].addr, 16))
                    # print(f"patch.instr[0].addr: {patch.instr[0].addr}")
                    # print(f"adj_loop_end_addr: {adj_loop_end_addr}")
                    # print()
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
    # # traverse back to function start until you find last read
    # print(f"param: {tgt_param}")
    # print(f"base_reg: {tgt_base_reg}")
    # print(f"full_arg: {tgt_full_arg}")
    # print(f"def_addr: {tgt_def_addr}")
    # a = input()

    i=idx
    REG = 0
    MEM = 1
    last_def_type = REG
    def_label = ['REG', 'MEM']
    ## ok next need to traverse back updating the def base until the we reach the function start
    ## how? who tf knows
    ## also track the instr address that is the last one to update the base
    ## ex: we know ldr r3 [r7, #0], need to find addr of --> ldr r7 [rx, #?], then ldr rx, [ry, #], etc
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
            
            # print(f"{instr.addr} {instr.instr} {instr.arg}")
            # print("\t"+def_label[last_def_type])
            # print(f"\t def_via_mov: {def_via_mov} --> {base_reg} in {instr.arg}")
            # print(f"\t def_via_ldr: {def_via_ldr} --> {base_reg} in {instr.arg}")
            # print(f"\t def_via_str: {def_via_str} --> {full_arg} in {instr.arg}")

            if last_def_type == REG:
                # print('trying reg mode...')
                if def_via_mov:
                    param = parts[0].replace(' ','')
                    full_arg = ''
                    base_reg = parts[1].replace(' ','')
                    def_addr = instr.addr
                    # print('\t\t def_via_ldr')
                    # print(f"\t\t param: {param}")
                    # print(f"\t\t full_arg: {full_arg}")
                    # print(f"\t\t base_reg: {base_reg}")
                    # print(f"\t\t def_addr: {def_addr}")

                    # continue
                elif def_via_ldr:
                    param = parts[0]
                    full_arg = ','.join(parts[1:])
                    base_reg = full_arg.split(',')[0].replace('[','').replace(' ','')
                    def_addr = instr.addr
                    # print('\t\t def_via_ldr')
                    # print(f"\t\t param: {param}")
                    # print(f"\t\t full_arg: {full_arg}")
                    # print(f"\t\t base_reg: {base_reg}")
                    # print(f"\t\t def_addr: {def_addr}")
                    if param != base_reg:
                        last_def_type = MEM #since def came from mem
                    # else --> don't change, since def came from itpg
            else: #last_def_type == MEM
                # print('trying mem mode...')
                if def_via_str:
                    last_def_type = REG #since def came from reg
                    param = parts[0]
                    full_arg = ','.join(parts[1:])
                    base_reg = full_arg.split(',')[0].replace('[','').replace(' ','')
                    def_addr = instr.addr
                    # print('\t\t def_via_str')
                    # print(f"\t\t param: {param}")
                    # print(f"\t\t full_arg: {full_arg}")
                    # print(f"\t\t base_reg: {base_reg}")
                    # print(f"\t\t def_addr: {def_addr}")
            i -= 1
        # print(f'parents: {cfg.nodes[addr].parents}')
        addr = [p for p in cfg.nodes[addr].parents if p != addr][0]
        # print(f'Trying next node {addr}')
        # print(' ')

    # print('BASE INIT DEFINITION: ')
    # print(f"param: {param}")
    # print(f"full_arg: {full_arg}")
    # print(f"base_reg: {base_reg}")
    # print(f"def_addr: {def_addr}")
    # print("-----")
    # a = input()
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

    # traverse back to find where the corrupted var is initialized
    # print(f"tgt_param: {tgt_param}")
    # print(f"tgt_base_reg: {tgt_base_reg}")
    # print(f"tgt_full_arg: {tgt_full_arg}")
    # print(f"tgt_def_addr: {tgt_def_addr}\n")
    param, full_arg, base_reg, def_addr = find_patch_variable_ARM(cfg, node_addr, expl_instr_addr, exp_func, tgt)
    # print(f"param: {param}")
    # print(f"base_reg: {base_reg}")
    # print(f"full_arg: {full_arg}")
    # print(f"def_addr: {def_addr}")

    # print()
    # print("---- Get bounds from emulator state ----")
    # get buffer base addr from param:
    reg, offset = full_arg.split(', ')
    reg = reg.replace('[', '').replace(' ', '')
    offset = offset.replace('#', '').replace(']', '')
    if '-' not in offset:
        offset = ' + '+offset
    # print(f"offset : {offset}, reg : {reg}")
    stack_addr = emulator.evaluate_expression(emulator.get_reg(reg) + offset)
    # print(f"buff base stack_addr : {stack_addr}")
    base_addr = emulator.get_mem(stack_addr)
    # print(f"buff base_addr : {base_addr}")
    # print(f'tgt_base_reg : {tgt_base_reg}')
    ctrl_data_stack_addr = emulator.get_reg(tgt_base_reg)
    # print(f"ctrl_data stack_addr : {ctrl_data_stack_addr}")
    new_loop_count = emulator.evaluate_expression(ctrl_data_stack_addr + ' - ('+base_addr+')')
    # print(f"new_loop_count: {new_loop_count}")
    # a = input()

    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"\tLocate addr_init part 2: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()

    # a = input()

    #okay now we found where the corrupted value is initialized
    #and we know how it is initialized (last_def_type)
    pg = PatchGenerator(patch_base)

    ##generate the patch by 
    ## replace the init site with branch to a new log
    # safe_loop_init(pg, def_addr, param, full_arg, cfg)

    print('PATCH GENERATOR')
    print(pg)

    ## replace the mem access with a branch to new loc
    ## checks mem access compared to the base and loop count
    loop_end_addr = cfg.nodes[node_addr].instr_addrs[-1].addr
    print(f'loop_end_addr: {loop_end_addr}')    
    
    ## use this info to rewrite the corrupted nodes
    start = time.time()
    rewrite_nodes_ARM(pg, def_addr, param, full_arg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, loop_end_addr)
    
    ## replace unsafe ops in node with b's to the safe code
    patches = patch_nodes_ARM(pg, cfg)
    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"Patch Generator", file=timingFile)
    print(f"\t Generate Patched Nodes: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()

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
        # break
    # a = input()
    print()
    pg.dump_patch_bin()
    
    bash_cmd = "arm-none-eabi-objdump -d ./patched.elf > ./patched.lst"
    os.system(bash_cmd)
    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"\t Update ELF: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()
    
    return pg