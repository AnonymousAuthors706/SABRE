from collections import deque
import pickle
from structures import *
from utils import *
from patch_generator import *
import os
from hash_based_cfa_algorithms import *
import time

def verify(cfg, cflog, cflog_startaddr=None):
    '''
    Function verifies whether given CFLog is valid.
    Returns True if log is valid, else returns False
    '''
    # Instantiate shadow stack
    # index = -1

    shadow_stack = deque()

    app_entry = 0
    verifyFile = open("logs/verify.log", "w")
    current_node = cfg.head
    log_idx = 0
    while log_idx < len(cflog):
        print(" ", file=verifyFile)
        log_node = cflog[log_idx]
        # index += 1
        print("Current node", file=verifyFile)
        current_node.printNode(verifyFile)
        print("log_idx: "+str(log_idx), file=verifyFile)
        print("log_node.dest_addr: "+str(log_node.dest_addr), file=verifyFile)
        
        if cflog_startaddr == log_node.dest_addr and app_entry == 0:
            app_entry = 1
            current_node = cfg.nodes[log_node.dest_addr]
            continue

        if cfg.arch.type == 'elf32-msp430':
            # print("Entered elif armv8-m33")
            # Check destinations
            if current_node.type == 'cond':
                if log_node.dest_addr in current_node.successors or log_node.dest_addr == current_node.adj_instr:
                    current_node = cfg.nodes[log_node.dest_addr]
                    log_idx += 1
                    continue
            elif current_node.type == 'uncond':
                # print(f"{log_node.dest_addr} vs {current_node.successors}")
                # if log_node.dest_addr in current_node.successors:
                current_node = cfg.nodes[log_node.dest_addr]
                log_idx += 1
                continue
            # If its a call, we need to push adj addr to shadow stack
            elif current_node.type == 'call': 
                shadow_stack.append(current_node.adj_instr)
                if log_node.dest_addr in current_node.successors:
                    current_node = cfg.nodes[log_node.dest_addr]
                    log_idx += 1
                    continue
            elif current_node.type == 'ret': 
                ret_addr = shadow_stack.pop()
                if log_node.dest_addr == ret_addr:
                    current_node = cfg.nodes[log_node.dest_addr]
                    log_idx += 1
                    continue
                else:
                    print(f"popped {ret_addr}")
                    print(f"logged {log_node.dest_addr}")
                    #TODO: Raise a Return Address Violation
                    pass
                    #err = raise(custom exception)

        elif cfg.arch.type == 'armv8-m33':
            # print("Entered elif armv8-m33")
            if current_node.type == 'uncond':
                if current_node.start_addr in cfg.indr_jumps:
                    if log_node.dest_addr in current_node.successors:
                        current_node = cfg.nodes[log_node.dest_addr]
                        log_idx += 1
                        continue
                else:
                    current_node = cfg.nodes[current_node.successors[0]]
                    print("-----", file=verifyFile)
                    print("changed node", file=verifyFile)
                    current_node.printNode(verifyFile)
                    print("-----", file=verifyFile)
                    continue

            # If its a call, we need to push adj addr to shadow stack
            if current_node.type == 'call': 
                shadow_stack.append(current_node.adj_instr)
                print("PUSH to shadow stack: "+str(current_node.adj_instr), file=verifyFile)
                if current_node.start_addr not in cfg.indr_calls:
                    print(f"Call: { current_node.start_addr} not in indr calls: {cfg.indr_calls:}", file=verifyFile)
                    # print(f"SECURE not in {current_node.instr_addrs[-1].arg}")
                    current_node = cfg.nodes[current_node.successors[0]]
                    continue
                else: #indirect call, so validate by checking shadow stack later
                    if log_node.dest_addr in current_node.successors:
                        print(f"Indirect call: checking if {log_node.dest_addr} in {current_node.successors}", file=verifyFile)
                        current_node = cfg.nodes[log_node.dest_addr]
                        log_idx += 1
                        continue

            # Check destinations
            if current_node.type == 'cond':
                if log_node.dest_addr in current_node.successors or log_node.dest_addr == current_node.adj_instr:
                    current_node = cfg.nodes[log_node.dest_addr]
                    log_idx += 1
                    continue

            elif current_node.type == 'ret': 
                ## If return is the special return from NS-SW, continue
                
                if log_node.dest_addr == "0xfefffffe":
                    log_idx += 1
                    continue
                else:
                    shadow_stack_addr = shadow_stack.pop()
                    print("POP from shadow stack: "+str(shadow_stack_addr), file=verifyFile)
                    if log_node.dest_addr == shadow_stack_addr:
                        current_node = cfg.nodes[log_node.dest_addr]
                        log_idx += 1
                        continue
                    else:
                        shadow_stack_violation = True

        return False, current_node, log_node, log_idx
    return True, current_node, None, log_idx

def parse_cflog(cflog_file, arch):
    # To make this more generalized, we may need to add a delimeter
    
    with open(cflog_file,'r') as f :
        lines = f.readlines()
    cflog_lines = [x.replace('\n','') for x in lines if x != '\n']

    stop = time.time()
    sizeFile = open("./logs/sizes.log", "a")
    print(f"CFLog Size: {4*len(lines)} bytes", file=sizeFile)
    sizeFile.close()

    cflog = []
    if arch.type == 'elf32-msp430':
        for line in cflog_lines:
            line = line.split(':')
            if line[0] == "dffe" or line[1] == "a000":
                continue
            elif len(line) > 1:
                if line[1][0] != '0': #Check if the line is a loop counter
                    s = '0x' + line[0]
                    d = '0x' + line[1]
                    cflog.append(CFLogNode(s,d))
                else: # add loop counter value to prev LogNode
                    cflog[-1].loop_count = int(line[1],16)
    elif arch.type == 'armv8-m33':
        for line in cflog_lines:
            if line[:4] != 'ffff': #Check if the line is a loop counter
                if 'fefffffe' not in line:
                    s = None
                    d = '0x' + line
                    cflog.append(CFLogNode(s,d))
                else:
                    # fefffffe is special char for return to SW, denotes end of cflog
                    break
            else: # add loop counter value to prev LogNode
                cflog[-1].loop_count = int(line[4:],16)
                # print(f"Setting loop_count={cflog[-1].loop_count} for entry={cflog[-1].dest_addr}")
                
    
    f = open("./logs/cflog_nodes.log", "w")
    for log_node in cflog:
        print(log_node, file=f)
    f.close()

    return cflog

def path_verifier(cfgfile, cflog, funcname): 

    # Load cfg
    cfg = load(cfgfile)
    asm_func_file = cfgfile.replace("cfg", "asm_func")
    asm_funcs = load(asm_func_file)

    ##start timing after the pickle.load because its incredibly inconsistent...    
    start = time.time()

    # Load and parse CFLog
    cflog = parse_cflog(cflog, cfg.arch)
    
    # If start addr not provided, lookup addr of function (or label) instead
    start_addr = cfg.label_addr_map[funcname]

    # Set the cfg head to the start address of where we want to attest
    cfg = set_cfg_head(cfg, start_addr)
    # parse_bitstream(cfg, "../TRACES/cflogs/oat.cflog")

    # Verify the cflog against the CFG
    valid, current_node, offending_node, offending_cflog_index = verify(cfg, cflog)

    if valid:
        print(bcolors.GREEN + '[+] CFLog is VALID!' + bcolors.END)
    else:
        print(bcolors.RED + '[-] CFLog is INVALID!' + bcolors.END)
        print("Offending CFLog entry: "+str(offending_cflog_index))
        print("Valid destinations: "+str(current_node.successors))
        print("Logged destination: "+str(offending_node.dest_addr))
        print("Corrupted br. Instruction: "+str(current_node.instr_addrs[-1]))
        print()
    
    stop = time.time()
    timingFile = open("./logs/timing.log", "a")
    print(f"\tVerify CFLog: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()
    dataFile = open("./logs/timingdata.log", "a")
    dataFile.write(f'{1000*(stop-start)}, ')
    dataFile.close()

    return cfg, cflog, asm_funcs, valid, current_node, offending_node, offending_cflog_index

if __name__ == "__main__":
    cfg, cflog, asm_funcs, valid, current_node, offending_node, offending_cflog_index = path_verifier()