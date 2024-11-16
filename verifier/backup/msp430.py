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

    # print("AAAAAAAAAAAAAAAAAAAAAAAAAA")
    # a = input()

    while cfg.arch.svr != base_reg or first: # todo- change be svr OR hvr
        
        if first:
            while cfg.nodes[addr].instr_addrs[i].addr != expl_instr_addr:
                i -= 1
            first = False
            print(f'First time: skipping ahead to start at exploited instr {expl_instr_addr}')
        else:
            i = len(cfg.nodes[addr].instr_addrs)-1

        while i >= 0 and cfg.arch.svr != base_reg:
            instr = cfg.nodes[addr].instr_addrs[i]
            # print(f'Trying  {instr.addr}  {instr.reconstruct()}')
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

                # print(f"\t\t base_reg: {base_reg}")
                # print(f"\t\t src: {src}")
                # print(f"\t\t dest: {dest}")
                # print(f"\t\t mem_src: {mem_src}")
                # print(f"\t\t mem_dest: {mem_dest}")
                # print(f"\t\t def_via_other: {def_via_other}")
                # print(f"\t\t def_via_mov: {def_via_mov}")
                # print(f"\t\t def_via_ldr: {def_via_ldr}")
                # print(f"\t\t def_via_str: {def_via_str}")

                if last_def_type == REG:
                    # print(f"\t\t last_def_type: REG")

                    if def_via_other:
                        if '@' in src or '(' in src:
                            # print(f"{instr.addr}  {instr.instr}  {instr.arg}")
                            # print('def_via_other')
                            param = base_reg
                            base_reg = src                        
                            def_addr = instr.addr
                            last_def_type = MEM
                            # print(f"\tparam = {param}")
                            # print(f"\tbase_reg = {base_reg}")
                            # print(f"\tdef_addr = {def_addr}")

                    elif def_via_mov:
                        # print(f"{instr.addr}  {instr.instr}  {instr.arg}")
                        # print('def_via_mov')
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print(f"\tparam = {param}")
                        # print(f"\tbase_reg = {base_reg}")
                        # print(f"\tdef_addr = {def_addr}")

                    elif def_via_ldr:
                        # print(f"{instr.addr}  {instr.instr}  {instr.arg}")
                        # print('def_via_ldr')
                        last_def_type = MEM
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print(f"\tparam = {param}")
                        # print(f"\tbase_reg = {base_reg}")
                        # print(f"\tdef_addr = {def_addr}")
                else:
                    # print(f"\t\t last_def_type: MEM")

                    if def_via_str:
                        # print(f"{instr.addr}  {instr.instr}  {instr.arg}")
                        # print('def_via_str')
                        param = base_reg
                        base_reg = src     
                        def_addr = instr.addr
                        # print(f"\tparam = {param}")
                        # print(f"\tbase_reg = {base_reg}")
                        # print(f"\tdef_addr = {def_addr}")
                        last_def_type = REG

            i -= 1
            # a = input()
        # print(f"({addr}) {cfg.arch.svr} not in {base_reg} = {cfg.arch.svr not in base_reg}")
        addr = [p for p in cfg.nodes[addr].parents if p != addr][0]
    return param, base_reg, def_addr

def find_buffer_lower_bound(cfg, param, base_reg, def_addr):
    #at this point, sp or hbp is in base_reg 
    #need to traverse backwards to see the last "variable" that was refernced using base_Reg
    #this will get us the true lowerbound

    #first get the node that has the instr defining our param via base_reg
    node_addr = cfg.get_node(def_addr)
    node = cfg.nodes[node_addr]

    #now traverse the instructions backwards until we reach another assignment to the stack/heap (via base_reg)
    i = 0
    found = False
    offset = None
    while not found and i < len(node.instr_addrs):
    # for instr in node.instr_addrs:
        instr = node.instr_addrs[i]
        args = instr.arg.split(',')
        if len(args) > 1:
            dest = args[1]
            if base_reg in dest and '(' in dest:
                print(f'{instr.addr} -- dest={dest}')
                found = True
                offset = dest.split('(')[0]
        if not found:
            i += 1

    #if we exited and could not find something, that means we need to place at the top of the function 
    ##instead of somewhere later
    if not found:
        offset = 0
        instr = node.instr_addrs[0]

    return instr.addr, offset
                
def find_buffer_upper_bound(cfg, param, base_reg, def_addr):
    # info about the buffer's lower bound
    print(f"param: {param}")
    print(f"base_reg: {base_reg}")
    print(f"def_addr: {def_addr}")

    #first get the node that contains the def_addr
    node_addr = cfg.get_node(def_addr)
    print(f"----------------\nNode: {node_addr}")
    
    node = cfg.nodes[node_addr]
    while node.type != 'call':
        node = cfg.nodes[node.successors[0]]

    print(f"Arrived at {node.start_addr}")
    print(f"Returning {node.instr_addrs[-1]}")
    # a = input()

    # since the upper bound instr will be replaced by a br, need to know the instruction and the adjacent one too
    ##since br is 32 bit

    #we also need to return the distance between the last instr that will be replaced and the remaining insttrr
    #instrs at -2 and -1, to see if we also need to add back a nop for alingment in the original func
    # if its not a 16-bit instr (spans more than 2 addr), we need the nop
    needNop = (int(node.instr_addrs[-1].addr, 16) - int(node.instr_addrs[-2].addr, 16) > 2)

    return node.instr_addrs[-3].addr, node.instr_addrs[-2].addr, needNop

def generate_bounds_patches_MSP430(pg, cfg, lower_bound_addr, lower_bound_offset, upper_bound_addr_1, upper_bound_addr_2, base_reg, param):
    #----- this is adding a new patch that inserts code between upper_bound_addr1 and upper_bound_addr2

    asm_list = []

    ##first add in the instruction that will be replaced by the trampoline (at upper_bound_addr_1)
    node = cfg.nodes[cfg.get_node(upper_bound_addr_1)]
    i = 0
    while i < len(node.instr_addrs) and node.instr_addrs[i].addr != upper_bound_addr_1:
        i += 1

    #found the instr so lets addd iti n
    instr = node.instr_addrs[i] # instructino replaced by trampoline

    patch = Patch(instr.addr)

    asm = AssemblyInstruction(addr=None, instr=instr.instr, arg=instr.arg, prev_addr=instr.addr)
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    ## now do it for the second one
    instr = node.instr_addrs[i+1] # instructino replaced by trampoline
    asm = AssemblyInstruction(addr=None, instr=instr.instr, arg=instr.arg, prev_addr=instr.addr)
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    ##LOWER BOUND
    ##first, need to check if offset is not zero. If its equal to zero thats easy- just reserve the base_reg
    ##if it is not equal to zero, we need two instructions: first move base_reg into reserve reg, then add offset to the reserve reg
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'{base_reg}, r9')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    
    asm_list.append(asm)
    if lower_bound_offset != '0':
        asm = AssemblyInstruction(addr=None, instr='add', arg=f'#{lower_bound_offset}, r9')
        patch = add_instruction_MSP430(asm, cfg, patch, pg)
        asm_list.append(asm)

    ### UPPER BOUND
    ## here, we should be able to move the param over, since it was defined at def_addr as the base addr
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'{param}, r10')
    asm_list.append(asm)
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    #finally, trampoline back to the instr we are replacoing
    asm = AssemblyInstruction(addr=None, instr='mov', arg=f'#{int(upper_bound_addr_2, 16)+2}, pc')
    asm_list.append(asm)
    patch = add_instruction_MSP430(asm, cfg, patch, pg)

    # print(f"======= INSTRS TO GRAB UPPER/LOWER BOUNDS ========")
    # for asm in asm_list:
    #     print(asm.reconstruct())
    
    # add the initial list of instructions to the patch and setup structs for asm+binary
    patch.bytes = b''.join(patch.bin)
    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        # print(f"Processing {instr.reconstruct()}")
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))

    ## set addresses of each instruction and correct the offests
    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    patch.bytes = b''.join(patch.bin)
    pg.patches[patch.addr] = patch
    pg.total_patches += 1
    pg.mode = 0
    patch.type = 0

    return patch

def trampoline_to_patch(pg, cfg, safe_patch, needNop):
    print(f"Adding trampoline for patch: addr={safe_patch.addr}")
    print(f"Patch first instr: {safe_patch.instr[0].addr}")
    
    patch = Patch(safe_patch.addr+'-tr')
    ### just one instructino -- jumping to the patched code
    asm = AssemblyInstruction(addr=safe_patch.addr, instr='mov', arg=f'#{int(safe_patch.instr[0].addr,16)}, pc')
    patch = add_instruction_MSP430(asm, cfg, patch, pg)
    print(f"Need nop == {needNop}")
    if needNop:
        #wee need to add a nop at the trampoline loc to account for alignment
        asm = AssemblyInstruction(addr=hex(int(safe_patch.addr,16)+4), instr='nop', arg='')
        patch = add_instruction_MSP430(asm, cfg, patch, pg)

    ## set addresses of each instruction and correct the offests
    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    patch.bytes = b''.join(patch.bin)
    pg.patches[patch.addr] = patch
    pg.total_patches += 1

    # a = input()
    return patch

def patch_function(pg, cfg, expl_instr_addr, vul_mem_func_bounds, tgt_base_reg):
    print(f"Vulnerable function memory bounds: {vul_mem_func_bounds}")
    print(f"Exploited memory instruction: {expl_instr_addr}")
    print(f"The targeted memory address is referneced in this reg: {tgt_base_reg} at the instruction ^")
    ## first we need to get all the nodes that are in the vuln vunfction
    (func_start_addr, func_end_addr) = vul_mem_func_bounds
    func_node_addrs = []
    for node_addr in cfg.nodes.keys():
        # print(f"checking {func_start_addr} <= {node_addr} <= {node_addr}")
        if int(node_addr, 16) >= int(func_start_addr, 16) and int(node_addr, 16) <= int(func_end_addr, 16):
            # print('\tadded!!')
            func_node_addrs.append(node_addr)
    func_node_addrs.sort()
    print(f"Func node addrs: {func_node_addrs}")

    pg.mode = 0
    ### okk now we need to iterate over the function nodes, adding its instrs into the patch
    patch = Patch(func_start_addr)
    patch.type = 0
    print("=====")
    added_instrs = []
    for node_addr in func_node_addrs:
        node = cfg.nodes[node_addr]
        for instr in node.instr_addrs:
            if instr.addr in added_instrs:
                # account for overlapping nodes
                continue

            added_instrs.append(instr.addr)

            if instr.addr == expl_instr_addr: ### we found the instruction that we need to wrap in the new bounds check
                print("-----")

                # OK wtf is the logic of th epatch?
                ## (1) IF the addr is lower than the minimum bound (r9), skip the mem write
                asm = AssemblyInstruction(addr=None, instr='cmp', arg=f'r9, {tgt_base_reg}')
                # print(asm.reconstruct())
                patch = add_instruction_MSP430(asm, cfg, patch, pg)

                asm = AssemblyInstruction(addr=None, instr='jlo', arg=f'#+14')
                # print(asm.reconstruct())
                patch = add_instruction_MSP430(asm, cfg, patch, pg)

                ## (2) IF the addr is higher than the maximum bound (r10), skip the mem write
                asm = AssemblyInstruction(addr=None, instr='cmp', arg=f'r10, {tgt_base_reg}')
                # print(asm.reconstruct())
                patch = add_instruction_MSP430(asm, cfg, patch, pg)

                asm = AssemblyInstruction(addr=None, instr='jhs', arg=f'#+6')
                # print(asm.reconstruct())
                patch = add_instruction_MSP430(asm, cfg, patch, pg)
                print("-----")
                ## (3) ELSE perform the mem write (captured outside of this if statement >>>)
                added_patch = True

            asm = AssemblyInstruction(addr=None, instr=instr.instr, arg=instr.arg, prev_addr=instr.addr)
            # print(asm.reconstruct())
            patch = add_instruction_MSP430(asm, cfg, patch, pg)

    print("=====")
    # print(f"Patch instrs: {patch.instr}")
    ## need to do the first and second passes on the patch for updating the offests and binary
    pg.mode = 1
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))

    ## set addresses of each instruction and correct the offests
    patch.type = 1
    pg.mode = 2
    for i in range(0, len(patch.instr)):
        instr = patch.instr[i]
        patch = add_instruction_MSP430(instr, cfg, patch, pg, (None, i))
    patch.instr = sorted(patch.instr, key=lambda x: int(x.addr, 16))
    
    patch.bytes = b''.join(patch.bin)
    pg.patches[patch.addr] = patch
    pg.total_patches += 1

    pg.mode = 0

    # a = input()
    return patch

def trampoline_to_new_func(pg, cfg, cflog_idx, cflog, vul_mem_func_bounds, func_patch_base_addr):
    print(f"func_patch_base_addr : {func_patch_base_addr}")
    
    func_start_addr = vul_mem_func_bounds[0]

    #We only need to patch the call that lead to the exploit
    i = cflog_idx    
    dest = cflog[cflog_idx].dest_addr
    while i >= 0 and dest != func_start_addr:
        i -= 1
        dest = cflog[i].dest_addr
    print(f"Found it : dest = {dest}")
    ## minus one more to get the node that calls it
    i -= 1
    dest = cflog[i].dest_addr
    node = cfg.nodes[dest]
    print(f"Got the node that calls it: {node.start_addr}")
    print(f"Instruction in the node that calls it: {node.instr_addrs[-1].addr}")
    caller_addr = node.instr_addrs[-1].addr
    
    tr_func_patch = Patch(caller_addr+'-tr')
    
    asm = AssemblyInstruction(addr=caller_addr, instr=node.instr_addrs[-1].instr, arg=f"&{func_patch_base_addr}")
    add_instruction_MSP430(asm, cfg, tr_func_patch, pg)

    ## set addresses of each instruction and correct the offests
    tr_func_patch.type = 1
    pg.mode = 2
    for i in range(0, len(tr_func_patch.instr)):
        instr = tr_func_patch.instr[i]
        tr_func_patch = add_instruction_MSP430(instr, cfg, tr_func_patch, pg, (None, i))
    tr_func_patch.instr = sorted(tr_func_patch.instr, key=lambda x: int(x.addr, 16))
    
    tr_func_patch.bytes = b''.join(tr_func_patch.bin)
    pg.patches[tr_func_patch.addr] = tr_func_patch
    pg.total_patches += 1

    pg.mode = 0

    a = input()
    return tr_func_patch

def generate_patch_MSP430(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx, vul_mem_func_bounds):
    '''
    Lets add some description bc my brain is fried and i will forget
    -- cfg       : the CFG object
    -- node_addr : the start address of the CFG node containing the exploited memory instruction
    -- expl_instr_addr : the address of the exploited memoery instruction
    -- exp_func : the function label that contains the definition of the exploited memory address
    -- cflog_idx : the index in cflog identifying the node of expl_instr_addr
    '''

    print("----------- Inputs to generate_patch_MSP430 --------------")
    print(f"node_addr : {node_addr}")
    print(f"expl_instr_addr : {expl_instr_addr}")
    print(f"loopcount : {loopcount}")
    print(f"exp_func : {exp_func}")
    print(f"cflog_idx : {cflog_idx}")
    print(f"vul_mem_func_bounds : {vul_mem_func_bounds}")
    print("----------------------------------------------------------")
    # a = input()

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

    ## target instruction info: instruction parameter/src reg, the full argument, base reg or memory_addr_target !!!, tgt_addr, index in the instr list
    tgt = (tgt_param, tgt_full_arg, tgt_base_reg, tgt_def_addr, idx)
    print(f"TARGET == {tgt}")
    param, base_reg, def_addr = find_patch_variable_MSP430(cfg, node_addr, expl_instr_addr, exp_func, tgt)
    print("----------- DONE   find_patch_variable_MSP430()   --------------")
    print(f"param: {param}")
    print(f"base_reg: {base_reg}")
    print(f"def_addr: {def_addr}")
    # a = input()
    
    print(f"Now we need to find the next place where sp changes")
    # lower_bound_addr = def_addr
    #the def sometimes is reached through increment, cant trust it.
    #need to go backwards until to see IF something else was pushed onto the stack first
    lower_bound_addr, lower_bound_offset = find_buffer_lower_bound(cfg, param,base_reg, def_addr)

    #need to move down paths until first sp-changing value is reached (for each path)
    ## nede to know two addresses since they both will be removed by the trampoline
    upper_bound_addr_1, upper_bound_addr_2, needNop = find_buffer_upper_bound(cfg, param, base_reg, def_addr)

    print(f"-----------------------\n Found bounds info")
    print(f"\t lower_bound_addr : {lower_bound_addr}")
    print(f"\t lower_bound_offset : {lower_bound_offset}")
    print(f"\t upper_bound_addr_1 : {upper_bound_addr_1}")
    print(f"\t upper_bound_addr_2 : {upper_bound_addr_2}")
    a = input()

    pg = PatchGenerator(patch_base)
    pg.mode = 0
    print('PATCH GENERATOR')
    print(pg)

    #### PHASE 1 --- 
    ### copy the vulnerable function to the patch region, 
    ### add in the bounds check using reserved registers, 
    ### replace the vulnerable call with a calll to the safe version AT ONLY the location that was corrupted
   
    func_patch = patch_function(pg, cfg, expl_instr_addr, vul_mem_func_bounds, tgt_base_reg)
    print("Function patch")
    print(func_patch)

    ##now need to replace the old call with the patched func
    func_patch_base_addr = func_patch.instr[0].addr
    tr_func_patch = trampoline_to_new_func(pg, cfg, cflog_idx, cflog, vul_mem_func_bounds, func_patch_base_addr)    
    print("Trampoline to function patch")
    print(tr_func_patch)

    #### PHASE 2 --- patch the binary to record the bounds of the variable
    # param is the bound base address, 
    ##base_reg is where it gets its definition from
    patch = generate_bounds_patches_MSP430(pg, cfg, lower_bound_addr, lower_bound_offset, upper_bound_addr_1, upper_bound_addr_2, base_reg, param)
    print("Get-bounds patch")
    print(patch)

    #add trampoline to this patch
    tr_patch = trampoline_to_patch(pg, cfg, patch, needNop)
    print("Trampoline for get-bounds patch")
    print(tr_patch)
    a = input()

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
    
    a = input()
    return pg