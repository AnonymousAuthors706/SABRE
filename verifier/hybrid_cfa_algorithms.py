def parse_bitstream(cfg, bitstream_file_name):
    f = open(bitstream_file_name, 'r')
    hexstream = '0x'+f.read()
    bitstream = bin(int(hexstream,16))[2:]
    print(bitstream)

    verifyFile = open("logs/verify.log", "w")
    current_node = cfg.head
    idx = 0
    while idx < len(bitstream):
        print(f"idx: {idx}")
        print(f'Next 64: {hex(int(bitstream[idx:idx+64], 2))}')
        if cfg.arch.type == 'armv8-m33':
            # print("Entered elif armv8-m33")
            if current_node.type == 'uncond':
                dest = current_node.successors[0]
                print(f"uncond, changing node {current_node.start_addr} --> {dest}")
                current_node = cfg.nodes[dest]
                # continue

            # If its a call, we need to push adj addr to shadow stack
            elif current_node.type == 'call': 
                # shadow_stack.append(current_node.adj_instr)
                # print("PUSH to shadow stack: "+str(current_node.adj_instr), file=verifyFile)
                if cfg.arch.instrumentation_handle not in current_node.instr_addrs[-1].arg:
                    # print(f"SECURE not in {current_node.instr_addrs[-1].arg}")
                    dest = current_node.successors[0]
                    print(f"call, changing node {current_node.start_addr} --> {dest}")
                    current_node = cfg.nodes[dest]
                    # continue
                else: #indirect call, so validate by checking shadow stack later
                    call_target = bitstream[idx:idx+32]
                    print(f"call_target: {call_target}")
                    dest = hex(int(call_target, 2))
                    thumb_target = hex(int(dest, 16)+1) # odd number addrs for thumb
                    if thumb_target in current_node.successors:
                        print(f"indr call, changing node {current_node.start_addr} --> {dest}")
                        current_node = cfg.nodes[dest]
                        idx += 32
                        print(f"idx += 32")
                        # continue
                    else:
                        print(f"dest ({dest}) not in successors ({current_node.successors})")
                    # a = input()

            # Check destinations
            elif current_node.type == 'cond':
                taken = int(bitstream[idx])
                print(f'taken: {taken}')
                idx += 1
                print(f"idx += 1")
                print(f'current_node.successors: {current_node.successors}')
                # print(f'checking {bitstream[idx:idx+16]}')
                if bitstream[idx:idx+16] == '0000000000000000':
                    # loop
                    loop_count = int(bitstream[idx:idx+32], 2)
                    print(f'repeated for {loop_count} ({bitstream[idx:idx+32]})')
                    dest = current_node.successors[0]
                    print(f"cond, changing node {current_node.start_addr} --> {dest}")
                    current_node = cfg.nodes[dest]
                    print(f'skipping exit loop {bitstream[idx+33]}')
                    idx += 33 #32 for the count, 1 for the loop exit
                    print(f"idx += 33")
                else:
                    dest = current_node.successors[taken]
                    print(f"cond, changing node {current_node.start_addr} --> {dest}")
                    current_node = cfg.nodes[dest]
                # a = input()

            elif current_node.type == 'ret': 
                ## If return is the special return from NS-SW, continue
                ret_addr = hex(int(bitstream[idx:idx+32], 2))
                print(f"ret_addr = {ret_addr} ({bitstream[idx:idx+32]})")
                idx += 32
                print(f"idx += 32")
                if ret_addr == "0xfefffffe":
                    continue
                else:
                    print(f"ret, changing node {current_node.start_addr} --> {ret_addr}")
                    current_node = cfg.nodes[ret_addr]
                    # shadow_stack_addr = shadow_stack.pop()
                    # print("POP from shadow stack: "+str(shadow_stack_addr), file=verifyFile)
                    # if ret_addr == shadow_stack_addr:
                        # current_node = cfg.nodes[ret_addr]
                        # log_idx += 32
                        # continue
                    # else:
                    #     shadow_stack_violation = True
                # a = input()
