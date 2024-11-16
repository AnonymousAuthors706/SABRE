from structures import *
from utils import *
from keystone import *
import os
from parse_asm import *
from verify import *
from MSProbe.assemble import *
import time

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
    
    if instr.instr == 'call':
        hex_list[0] = int('0xb012',16)

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
    '''
    Needs three passes to add an instruction to the binary
    -- Mode 0: First pass to adds the instructions to the patch object
    -- Mode 1: Second pass that updates the instruction addresses 
    -- Mode 2: Third pass, updates the relative address used by any instructions and updates the bin/hex
    '''

    if pg.mode >= 1:
        if patch.type == 0:
            asm.addr = hex(pg.base)

        loop_exit, idx = mode_1_args

        
        if (asm.instr in cfg.arch.unconditional_br_instrs or asm.instr in cfg.arch.conditional_br_instrs) and idx != len(patch.instr)-1:
            if asm.arg == 'loop_exit':
                asm.arg = loop_exit
            if pg.mode == 2:
                # print(asm)
                #jumps are based on offsets, so need to update them
                do_something = 1
                #first have to calculate the old ref address --> offset + prev_addr
                if asm.prev_addr != None:
                    # print(f"asm.prev_addr: {asm.prev_addr}")
                    # print(f"asm.addr: {asm.addr}")
                    offset = asm.arg.replace('$', '')
                    # print(f"offset: {offset}")
                    old_ref_addr = hex(int(asm.prev_addr, 16)+int(offset))
                    # print(f"old_ref_addr: {old_ref_addr}")
                    #then, from old ref address get the curr ref address
                    cur_ref_addr = ''
                    for instr in patch.instr:
                        # print(instr.prev_addr)
                        if instr.prev_addr == old_ref_addr:
                            cur_ref_addr = instr.addr
                            break
                    # print(f"cur_ref_addr: {cur_ref_addr}")
                    #then, calculate the new offset from the cur_ref_addr-curr_addr
                    new_offset = int(cur_ref_addr, 16)-int(asm.addr, 16)
                    # print(f"new_offset: {new_offset}")
                    if new_offset > 0:
                        asm.arg = f"$+{new_offset}"
                    else:
                        asm.arg = f"${new_offset}"
                    # print(f"asm.arg: {asm.arg}")
                    # print()

        bin_instr, hex_instr, debug = instr_to_binary_MSP430(asm, cfg.arch)
        # if debug:
            # print(f"ASM AFTER RETURN  = {asm}")
        # patch.instr.append(asm)
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
    # traverse back to function start until you find last read

    # a = input()
    i=idx
    REG = 0
    MEM = 1
    type_label = ['REG', 'MEM']
    last_def_type = REG # mem write is of the form REG --> MEM

    ## ok next need to traverse back updating the def base until the we reach the function start
    ## how? who tf knows
    ## also track the instr address that is the last one to update the base
    ## ex: we know ldr r3 [r7, #0], need to find addr of --> ldr r7 [rx, #?], then ldr rx, [ry, #], etc
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
            # a = input()
        else:
            i = len(cfg.nodes[addr].instr_addrs)-1

        # print(f'i = {i}')
        while i >= 0:
            instr = cfg.nodes[addr].instr_addrs[i]
            # print(f"{instr.addr} {instr.instr} {instr.arg}")
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
                '''
                print(f"{instr.addr} {instr.instr} {instr.arg}")
                # if instr.addr == "0xe11a":
                print(f"\t def_via_other = {def_via_other}")
                print(f"\t def_via_mov = {def_via_mov}")
                print(f"\t def_via_ldr = {def_via_ldr}")
                print(f"\t def_via_str = {def_via_str}")
                print(f"\t last_def_type = {type_label[last_def_type]}")
                # print(f"\t\t {base_reg} in {dest} = {base_reg in dest}")
                # print(f"\t\t {mem_dest} = {mem_dest}")
                # print(f"\t\t {base_reg} not in {src} = {base_reg not in src}")
                # print('trying reg mode...')
                '''
                if last_def_type == REG:
                    if def_via_other:
                        if '@' in src or '(' in src:
                            param = base_reg
                            base_reg = src                        
                            def_addr = instr.addr
                            last_def_type = MEM
                        # print('def_via_other')
                        # print(f"base_reg: {base_reg}")
                        # print(f"param: {param} {len(param)}")
                        # print(f"def_addr: {def_addr}")
                        # a = input()
                    elif def_via_mov:
                    # if def_via_mov:
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print('def_via_mov')
                        # print(f"base_reg: {base_reg}")
                        # print(f"param: {param} {len(param)}")
                        # print(f"def_addr: {def_addr}")
                        # a = input()
                    elif def_via_ldr:
                        last_def_type = MEM
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print('def_via_ldr')
                        # print(f"base_reg: {base_reg}")
                        # print(f"param: {param} {len(param)}")
                        # print(f"def_addr: {def_addr}")
                        # a = input()
                else: #last_def_type == MEM
                    # print('trying mem mode...')
                    if def_via_str:
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print('def_via_str')
                        # print(f"base_reg: {base_reg}")
                        # print(f"param: {param} {len(param)}")
                        # print(f"def_addr: {def_addr}")
                        # a = input() 
            i -= 1
        # print(f'parents: {cfg.nodes[addr].parents}')
        addr = [p for p in cfg.nodes[addr].parents if p != addr][0]
        # print(f'Trying next node {addr}')
        # print(' ')
    # print("-------------------------------------")
    # print('BASE INIT DEFINITION: ')
    # print(f"base_reg: {base_reg}")
    # print(f"param: {param}")
    # print(f"def_addr: {def_addr}")
    # print("-------------------------------------")
    # a = input()
    return param, base_reg, def_addr

def rewrite_nodes_MSP430(pg, def_addr, param, base_reg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, exp_func, loop_end_addr, vul_mem_func_bounds):
    # 16-bit jump instruction doesn't give us much range for dr branching to the patch... 
    # so instead we'll move the whole function
    exp_func_addr = cfg.label_addr_map[exp_func]
    func_start_addr, func_end_addr = vul_mem_func_bounds
    # print()
    # print('INIT SITE: ')
    # print(f'{def_addr}, {base_reg}')
    # print()
    # next rewrite the node for vuln site
    # print('VULNERABILITY SITE: ')
    # print(f'{expl_instr_addr} {tgt_base_reg}')
    # print()
    pg.mode = 0
    patch_not_init = True
    # first rewrite node for init site
    for node_addr in sorted(cfg.nodes.keys()):
        node = cfg.nodes[node_addr]
        if int(node.start_addr, 16) <= int(def_addr, 16) and int(def_addr, 16) <= int(node.end_addr, 16):
            # print(f'def_addr {def_addr} is within node')
            if patch_not_init:
                # print("Init new patch")
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
            # print(f'expl_instr_addr {expl_instr_addr} is within node')
            if patch_not_init:
                # print("Init new patch")
                patch = Patch(node_addr)
                patch_not_init = False

            node_instrs = node.instr_addrs
            for instr in node_instrs:
                if instr.addr == expl_instr_addr:
                    loop_end_offest = int(loop_end_addr,16)-int(expl_instr_addr,16)+2 #plus 2 for msp430
                    # print()
                    # print(f'expl_instr_addr: {expl_instr_addr}')
                    # print(f'loop_end_addr: {loop_end_addr}')
                    # print(f"loop_end_offest: {loop_end_offest}")
                    # loop_end_offest+=10 # since patch is 5 instruction
                    if loop_end_offest > 0:
                        loop_exit = "$+"+str(loop_end_offest)
                    else:
                        loop_exit = "$"+str(loop_end_offest)
                    # print(f"patch.instr[0].addr: {patch.instr[0].addr}")
                    # print(f"loop_exit: {loop_exit}")
                    # a = input()
                    print()
                    patch = safe_loop_mem_access_MSP430(patch, pg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, loopcount, cfg)
                else:
                    instr.prev_addr = instr.addr
                    patch = add_instruction_MSP430(instr, cfg, patch, pg)
        
        elif int(func_start_addr, 16) <= int(node_addr, 16) and int(node_addr, 16) <= int(func_end_addr, 16):
            # print(f'node {node_addr} is within func')
            if patch_not_init:
                # print("Init new patch")
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

def quick_ret_patch_start_block(patch, pg, cfg, old_push_asm, explt_func_start_addr):
    ## At the push location
    pg.mode = 0

    # gets the return address from stack, saves into r10, 
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'@r1, r10') 
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # add back in the first push instruction 
    asm = AssemblyInstruction(addr=None, instr=old_push_asm.instr, arg=old_push_asm.arg)
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # branch back to the func's start
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'#{int(explt_func_start_addr,16)+2}, pc')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    patch.bytes = b''.join(patch.bin)
    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))

    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    patch.bytes = b''.join(patch.bin)
    pg.patches[patch.addr] = patch
    pg.total_patches += 1

    return patch

def quick_ret_patch_exit_block(patch, pg, cfg):
    ## At the push location
    # gets the return address from stack, saves into r10, 
    pg.mode = 0

    asm = AssemblyInstruction(addr=None, instr='add', arg=f'#4, r1') 
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # branch back to the func's start
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'r10, pc')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    patch.bytes = b''.join(patch.bin)

    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))

    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    patch.bytes = b''.join(patch.bin)
    pg.patches[patch.addr] = patch
    pg.total_patches += 1

    return patch


def save_stack_frame(patch, pg, start_addr, def_addr, cfg, old_push_asm):
    ## At the push location
    # gets the return address from stack, saves into r10, 
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'@r1, r10') 
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    # add back in the first push instruction 
    patch = add_instruction_MSP430(old_push_asm, cfg, patch, pg)
    
    # branch back to the func's start
    asm = AssemblyInstruction(addr=None, instr='br', arg=f'#{explt_func_start_addr+4}')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    ### Patch the return location
    # increment the stack pointer, since we no longer using 'ret' instruction
    asm = AssemblyInstruction(addr=None, instr='add', arg=f'#4, r1')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    ### 'return' by moving from r10 into pc
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'r10, r0')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    return patch

#---------------------------------------------------------#
def patch_nodes_MSP430(pg, cfg, trampoline_node):
    ## Given where patches should be applied,
    ##traverse cfg nodes and patch the nodes
    ## find node that needs a patch by checking if unsafe addr is in the node bounds
    patches = []
    first = True
    patch_addrs = list(pg.patches.keys())
    print(f'PATCH_ADDRS: {patch_addrs}')
    for unsafe_addr in patch_addrs:
        print(f'UNSAFE_ADDR: {unsafe_addr}')
        for node_addr in cfg.nodes.keys():
            node = cfg.nodes[node_addr]
            if int(node.start_addr, 16) <= int(unsafe_addr, 16) <= int(node.end_addr, 16):
                p = pg.patches[node_addr]
                if first:
                    print(f"PATCHING NODE WITH NODE_ADDR = {trampoline_node.instr_addrs[-1].addr}")
                    ptch = patch_node_MSP430(pg, trampoline_node.instr_addrs[-1].addr, trampoline_node.instr_addrs[-1], cfg, p)
                    patches.append(ptch)
                    first = False
                else:
                    print(f"PATCHING NODE WITH NODE_ADDR = {node_addr}")
                    ptch = patch_node_MSP430(pg, node_addr, node.instr_addrs, cfg, p)
                    patches.append(ptch)
        a = input()
    return patches

#---------------------------------------------------------#
def patch_node_MSP430(pg, node_addr, node_instrs, cfg, p):
    patch = Patch(node_addr)
    patch.type = 1
    
    target_addr = int(p.instr[0].addr, 16)
    print(f"Creating patch instr: Addr={node_addr}, 'call', arg: {hex(target_addr)}")
    asm = AssemblyInstruction(addr=node_addr, instr='call', arg=f"#{hex(target_addr)}")
    for i in range(0, 2):
        pg.mode = i
        patch = add_instruction_MSP430(asm, cfg, patch, pg, (0, 0))
    patch.bytes = b''.join(patch.bin)
    return patch

#---------------------------------------------------------#
def quick_patch_msp430(cfg, cflog, exp_func, exp_func_start_addr, func_start_cflog_idx, corrupt_br_instr, offending_cflog_index):
    # make the patch generator object
    pg = PatchGenerator(cfg.arch.patch_base)
    pg.mode = 0 # start each patch in first mode

    ## generate the new funciton start block
    patch_entry = Patch(exp_func_start_addr)
    old_push_asm = cfg.nodes[exp_func_start_addr].instr_addrs[0]
    print(f"Old push: {old_push_asm}")
    patch_entry = quick_ret_patch_start_block(patch_entry, pg, cfg, old_push_asm, exp_func_start_addr)
    
    ## generate the new return block
    pg.mode = 0 # start each patch in first mode
    patch_exit = Patch(corrupt_br_instr.addr)
    old_push_asm = cfg.nodes[exp_func_start_addr].instr_addrs[0]
    patch_exit = quick_ret_patch_exit_block(patch_exit, pg, cfg)
    
    # trampolines from old addrs to new addrs (patch location)
    tr_patches = []
    print(list(pg.patches.keys()))
    a = input()
    
    # iterate through the patch dict, make a trampoline from the old addr to the new addr. 
    for old_addr in pg.patches.keys():
        pg.mode = 0 # start each patch in first mode
        new_addr = pg.patches[old_addr].instr[0].addr
        print(f"Making tr_patch as Patch({old_addr})")
        tr_patch = Patch(old_addr)
        tr_asm = AssemblyInstruction(addr=old_addr, instr='mov', arg=f'#{int(new_addr, 16)}, pc')
        tr_patch = add_instruction_MSP430(tr_asm, cfg, tr_patch, pg)
        tr_patches.append(tr_patch)
    
    ## add the new patch to the dict, make a custom label to denote trampoline '-tr'
    for tr_patch in tr_patches:
        # pg.mode = 1
        # for i in range(0, len(tr_patch.instr)):
            # instr = tr_patch.instr[i]
            # tr_patch = add_instruction_MSP430(instr, cfg, tr_patch, pg, (None, i))

        tr_patch.type = 1
        pg.mode = 2
        for i in range(0, len(tr_patch.instr)):
            instr = tr_patch.instr[i]
            tr_patch = add_instruction_MSP430(instr, cfg, tr_patch, pg, (None, i))
        tr_patch.instr = sorted(tr_patch.instr, key=lambda x: int(x.addr, 16))

        tr_patch.bytes = b''.join(tr_patch.bin)
        pg.patches[tr_patch.addr+'-tr'] = tr_patch
        pg.total_patches += 1
    print('\n')
    
    ## printing
    for key in pg.patches.keys():
        print(f"Patch {key}: ")
        print(pg.patches[key])
        print("\n")


    ## iterate over the patches and add the bin to the elf
    elf_file_path = 'patched.elf'
    count=0
    print("---- Updating ELF ----")
    start = time.time()
    for addr, patch in pg.patches.items():
        # print(f"\tAdding Patch {count}...")
        for i in range(0, len(patch.instr)):
            instr_addr = int(patch.instr[i].addr, 16)
            print(f"Updating {patch.instr[i].addr} to {patch.bin[i]}")
            update_instruction(cfg.arch, elf_file_path, instr_addr, patch.bin[i])
        count += 1
        # break
    pg.dump_patch_bin()
    
    ## make the lst for debug and also used later on by patch validator
    bash_cmd = "msp430-objdump -d patched.elf > patched.lst"
    os.system(bash_cmd)
    return pg


def generate_patch_MSP430(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx_min, cflog_idx_max, vul_mem_func_bounds, emulator):
    start = time.time()
    # print('------- Generating Patch ---------')
    instrs = [instr.addr for instr in cfg.nodes[node_addr].instr_addrs]
    idx = instrs.index(expl_instr_addr)
    
    patch_base = cfg.arch.patch_base
    # print(f'patch_base: {patch_base}')

    print(f"cflog_idx_min: {cflog_idx_min} --> CFLOG: {cflog[cflog_idx_min]}")
    print(f"\tlast addr of dest node: {cfg.nodes[cflog[cflog_idx_min].dest_addr].instr_addrs[-1].addr}")

    print(f"Fixed return: {hex(int(cflog[cflog_idx_min].src_addr,16)+4)}")

    trampoline_node = cfg.nodes[cflog[cflog_idx_min].dest_addr]
    print(f"cflog_idx_max: {cflog_idx_max} --> CFLOG: {cflog[cflog_idx_max]}")
    a = input()
    ## get just the base reg, have to remove brackets and white space
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

    # traverse back to find where the corrupted var is initialized
    # print(f"tgt_param: {tgt_param}")
    # print(f"tgt_base_reg: {tgt_base_reg}")
    # print(f"tgt_full_arg: {tgt_full_arg}")
    # print(f"tgt_def_addr: {tgt_def_addr}\n")
    param, base_reg, def_addr = find_patch_variable_MSP430(cfg, node_addr, expl_instr_addr, exp_func, tgt)
    # print(f"param: {param}")
    # print(f"base_reg: {base_reg}")
    # print(f"def_addr: {def_addr}")
    # print()
    # print("---- Get bounds from emulator state ----")
    # get buffer base addr from param:
    offset, reg = param.split('(')
    reg = reg.replace(')', '')
    # print(f"offset : {offset}, reg : {reg}")
    stack_addr = emulator.evaluate_expression(emulator.get_reg(reg) + offset)
    # print(f"buff base stack_addr : {stack_addr}")
    buff_base_addr = emulator.get_mem(stack_addr)
    # print(f"buff base addr : {buff_base_addr}")
    # print(f'tgt_base_reg : {tgt_base_reg}')
    ctrl_data_stack_addr = emulator.get_reg(tgt_base_reg)
    # print(f"ctrl_data stack_addr : {ctrl_data_stack_addr}")
    new_loop_count = emulator.evaluate_expression(ctrl_data_stack_addr + ' - ('+buff_base_addr+')')
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
    pg.mode = 0
    ##generate the patch by 
    ## replace the init site with branch to a new log
    # safe_loop_init(pg, def_addr, param, full_arg, cfg)

    print('PATCH GENERATOR')
    print(pg)
    
    ## replace the mem access with a branch to new loc
    ## checks mem access compared to the base and loop count
    loop_end_addr = cfg.nodes[node_addr].adj_instr
    print(f'loop_end_addr: {loop_end_addr}') 

    ## use this info to rewrite the corrupted func
    start = time.time()
    rewrite_nodes_MSP430(pg, def_addr, param, base_reg, cfg, expl_instr_addr, tgt_param, tgt_base_reg, tgt_full_arg, new_loop_count, exp_func, loop_end_addr, vul_mem_func_bounds)
    # a = input()

    ## replace unsafe ops in node with b's to the safe code
    patches = patch_nodes_MSP430(pg, cfg, trampoline_node)
    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"Patch Generator", file=timingFile)
    print(f"\t Generate Patched Nodes: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()

    
    

    print('NODE PATCHES: ')
    for p in patches:
        print(p)
        pg.patches['self'] = p
    
    ### printing
    #'''    

    print()
    print("---- Generated Patches ----")
    print(f'vul_mem_func_bounds: {vul_mem_func_bounds}')
    count = 0
    for addr, patch in pg.patches.items():
        print(f"Patch {count}: patches {patch.addr}")
        for i in range(0, len(patch.instr)):
            instr = patch.instr[i]
            print(f"{instr.addr}({instr.prev_addr})\t\t{instr.reconstruct()};\t{patch.hex[i]};\t{patch.bin[i]};")
        print()
        count += 1
    #'''
    a = input()

    ## iterate over the patches and add the bin
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
        # break
    # a = input()
    # print()
    pg.dump_patch_bin()
    
    bash_cmd = "msp430-objdump -d patched.elf > patched.lst"
    os.system(bash_cmd)
    # print(bash_cmd)
    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"\t Update ELF: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()
    return pg

# def locate_funcptr_exploit(cfg, cflog, func_entry_cflog_index, offending_cflog_index):
    
    

