from hashlib import sha256
from collections import deque
import argparse
import pickle
from structures import *
from utils import *
from verify import *
import time

def arg_parser():
    '''
    Parse the arguments of the program
    Return:
        object containing the arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--cfgfile', metavar='N', type=str, default='cfg.pickle',
                        help='Path to input file to load serialized CFG. Default is cfg.pickle')
    parser.add_argument('--funcname', metavar='N', type=str, default='main',
                        help='Name of the function to be tracked in the attestation. Set to "main" by default.')
    parser.add_argument('--cflog', metavar='N', type=str,
                        help='File where the cflog to be attested is.')
    parser.add_argument('--startaddr', metavar='N', type=str,
                        help='Address at which to begin verification. Address MUST begin with "0x"')
    parser.add_argument('--endaddr', metavar='N', type=str,
                        help='Address at which to end verification')

    args = parser.parse_args()
    return args

def emulate_hash_chain(cfg, cflog):
    print("emulating hash chain...")
    hash_chain = 0
    count = 0
    f = open('./logs/emulate_hash_chain.log', 'w')
    loop_hashes = {}
    last_addr = None
    loop_entry = None
    loop_exit = None
    isLoop = False
    loop_starts = []
    loop_paths = []
    loop_path = []
    loop_stack = []

    for ln in cfg.loop_nodes:
        print(ln)


    for i in range(0, len(cflog)):
        cflog_node = cflog[i]
        if last_addr is not None:
            # if cfg.nodes[last_addr].type == 'cond':
            #     print(f"{cfg.nodes[cflog_node.dest_addr].type}\t{cflog_node.dest_addr} < {last_addr} ---> {int(cflog_node.dest_addr, 16) < int(last_addr,16) and cfg.nodes[cflog_node.dest_addr].type == 'cond'}")
            # else:
            #     print(f"{cfg.nodes[cflog_node.dest_addr].type}\t{cflog_node.dest_addr}")
            # print(f"processing {last_addr}")
            if isLoop:
                loop_path.append(last_addr)
                if last_addr == loop_entry:
                    # print(f"appending {loop_path}")
                    if loop_path == ['0xe176', '0xe172']:
                        print("STOP")
                        a = input()
                    loop_paths.append(loop_path)
                    # a  = input()
                    loop_path = []

            if int(cflog_node.dest_addr, 16) < int(last_addr,16) and cfg.nodes[last_addr].type == 'cond':
                loop_entry = cflog_node.dest_addr
                loop_exit = cfg.nodes[last_addr].adj_instr  

            elif int(cflog_node.dest_addr, 16) < int(last_addr,16) and cfg.nodes[last_addr].type == 'uncond':
                loop_entry = cflog_node.dest_addr
                loop_exit = cfg.nodes[last_addr].adj_instr  

            if last_addr == loop_entry and isLoop == False:
                loop_stack.append((loop_entry, loop_exit, isLoop))
                print(f"{last_addr}\tloop_entry\texit={loop_exit}")
                # a = input()
                hash_chain ^= int(last_addr, 16)
                hash_chain_encoded = str(hash_chain).encode()
                hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                loop_hashes[hash_chain] = loop_entry
                loop_entry = None
                isLoop = True
                print(f"{last_addr}  {hash_chain}", file=f)

            elif last_addr == loop_exit:
                print(f"{last_addr}\tloop exit")
                # print(f"non-loop {cflog_node.dest_addr}")
                # print(f"\t{last_addr}\tloop_exit")
                hash_chain ^= int(last_addr, 16)
                hash_chain_encoded = str(hash_chain).encode()
                hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                # print(f"{last_addr}  {hash_chain}")
                try:
                    loop_entry, loop_exit, isLoop = loop_stack[0]
                except IndexError:
                    print(f"No loop metadata at {last_addr}")
                    a = input()
                # print(f"\t\tpopped {(loop_entry, loop_exit, isLoop)} from loop stack")
                loop_stack = loop_stack[1:]
                print(f"{last_addr}  {hash_chain}", file=f)

            elif isLoop == False:
                # print(f"\rnon-loop")
                print(f"{last_addr}\tnon-loop")
                hash_chain ^= int(last_addr, 16)
                hash_chain_encoded = str(hash_chain).encode()
                hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                print(f"{last_addr}  {hash_chain}", file=f)

            # else:
                # print(f"\tnon-loop")
        # else:
            # print(f"non-loop {cflog_node.dest_addr}")
        #     hash_chain ^= int(cflog_node.dest_addr, 16)
        #     hash_chain_encoded = str(hash_chain).encode()
        #     hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
        #     # print(f"{cflog_node.dest_addr}  {hash_chain}")

        last_addr = cflog_node.dest_addr
        # a = input()

    print(f"last one:")
    hash_chain ^= int(cflog_node.dest_addr, 16)
    hash_chain_encoded = str(hash_chain).encode()
    hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
    print(f"{last_addr}  {hash_chain}", file=f)
    f.close()

    print("Path Hash:", hash_chain)
    print("Loop Entry Hashes:")
    for loop_entry, h in loop_hashes.items():
        print(f"  Loop Entry {loop_entry}: {h} {type(h)}")


    print()
    # print("Loop paths: ")
    final_loop_paths = []

    unique = []
    for lp in loop_paths:
        if lp not in unique:
            # print(f"unique.append {lp}")
            unique.append(lp)
    loop_paths = unique

    for lp in loop_paths:
        toAdd = True
        for lp2 in loop_paths:
            if isSublist(lp2, lp):
                toAdd = False
        if toAdd:
            final_loop_paths.append(lp)

    hash_to_loop_path = {}
    for lp in final_loop_paths:
        loop_hash = 0
        
        for addr in lp:
            loop_hash ^= int(addr, 16)
            loop_hash_encoded = str(loop_hash).encode()
            loop_hash = int(sha256(loop_hash_encoded).hexdigest(),16)

        if loop_hash not in hash_to_loop_path.keys():
            hash_to_loop_path[loop_hash] = lp

    f = open('hash_evidence.cflog', 'w')
    f.write(f"{hash_chain}\n")
    
    print(len(hex(hash_chain)[2:]))
    size = (len(hex(hash_chain)[2:])/2) # divide by 2 to get number of bytes
    # a = input()

    print("Hash to loop mapping: ")
    for loop_hash, loop_path in hash_to_loop_path.items():
        print(f"{loop_hash} : {loop_path}")
        for entry_hash, loop_entry in loop_hashes.items():
            if loop_entry == loop_path[-1]:
                size += (len(hex(entry_hash)[2:])/2) + (len(hex(loop_hash)[2:])/2)
                size += 3 # plus 3 for the '<', '>', ','
                size += 16 # assume a 16-bit counter '1'
                f.write(f"{entry_hash}<{loop_hash},1>\n")
    f.close()

    sizeFile = open("./logs/sizes.log", "a")
    print(f"Hash evidence size: {size} bytes", file=sizeFile)
    sizeFile.close()

    return hash_chain, loop_hashes

def isSublist(test_list, sublist):
    if test_list == sublist:
        return False

    #source: https://www.geeksforgeeks.org/python-check-for-sublist-in-list/
    res = False
    for idx in range(len(test_list) - len(sublist) + 1):
        if test_list[idx: idx + len(sublist)] == sublist:
            # print(f"{sublist} isSublist of {test_list}:")
            res = True
            break
    return res

def dfs(cfg, addr, end, path=None, ss=None, file=None):
    # print(f"starting {addr}")
    # a = input()
    
    if path == None:
        path = []
    else:
        path.append(addr)

    if addr == end:
        return [path]

    if addr not in cfg.nodes.keys():
        return []

    if ss == None:
        ss = []

    # print(f"({addr}) path = {len(path)}")
    # a = input()
    paths = []
    if cfg.nodes[addr].type == 'ret':
        # for normal returns that had function before it
        if len(ss) > 0:
            successor_addr = ss[0]
            print(f"(ret) {addr} --> {successor_addr}\t ss({len(ss)}) ", file=file)
            new_paths = dfs(cfg, successor_addr, end, path[:], ss[1:][:], file=file)
            # print(f"{addr} : new_paths {len(new_paths)}")
            for np in new_paths:
                paths.append(np)
        #else --> return
        # special case when loop exit is a return node, we ignore in this case since there is no associaed call

    elif cfg.nodes[addr].type == 'call':
        successor_addr = cfg.nodes[addr].successors[0]
        print(f"({cfg.nodes[addr].type}) {addr} --> {successor_addr}", file=file)
        # add to stack if call    
        # debug = f"\t ss({len(ss)}) --> appending {cfg.nodes[addr].adj_instr} -- > "
        ss = [cfg.nodes[addr].adj_instr] + ss
        # debug += f"ss({len(ss)})"
        # print(debug)
        # a = input()
        new_paths = dfs(cfg, successor_addr, end, path[:], ss[:], file=file)
        # print(f"{addr} : new_paths {len(new_paths)}")
        for np in new_paths:
            paths.append(np)

    elif cfg.nodes[addr].type == 'uncond':
        for successor_addr in cfg.nodes[addr].successors:
            if int(successor_addr, 16) <= int(addr, 16): #loop using dir jump
                print(f"(uncond) (loop-enter) {addr} --> {successor_addr}\t ss({len(ss)}) ", file=file)
                path.append(successor_addr) #add loop entry once
                print(f"\tappending {successor_addr} --> path : {path}", file=file)
                paths.append(path)
                
                # now continue dfs with 'loop exit'
                successor_addr = cfg.nodes[addr].adj_instr
                if successor_addr not in path:
                    new_paths = dfs(cfg, successor_addr, end, path[:], ss[:], file=file) # follow loop exit
                    for np in new_paths:
                        paths.append(np)

            else: #forward dir jump
                print(f"({cfg.nodes[addr].type}) {addr} --> {successor_addr}", file=file)
                new_paths = dfs(cfg, successor_addr, end, path[:], ss[:], file=file)
                # print(f"{addr} : new_paths {len(new_paths)}")
                for np in new_paths:
                    paths.append(np)

    else:
        # need to check if successor 0 or 1 is a loop dest
        if int(cfg.nodes[addr].successors[0], 16) <= int(addr, 16):
            #successor 0 is loop, successor 1 is loop exit
            print(f"(cond) (loop-enter) {addr} --> {cfg.nodes[addr].successors[0]}\t ss({len(ss)}) ", file=file)
            path.append(cfg.nodes[addr].successors[0]) #add loop entry once
            if cfg.nodes[addr].successors[1] not in path:
                print(f"(cond) (loop-exit) {addr} --> {cfg.nodes[addr].successors[1]}\t ss({len(ss)}) ", file=file)
                # a = input()
                new_paths = dfs(cfg, cfg.nodes[addr].successors[1], end, path[:], ss[:], file=file) # follow loop exit
                for np in new_paths:
                    paths.append(np)
            else:
                paths.append(path)

        elif int(cfg.nodes[addr].successors[1], 16) <= int(addr, 16):
            #successor 1 is loop, successor 0 is loop exit
            print(f"(cond) (loop-enter) {addr} --> {cfg.nodes[addr].successors[1]}\t ss({len(ss)}) ", file=file)
            path.append(cfg.nodes[addr].successors[1]) #add loop entry once
            if cfg.nodes[addr].successors[0] not in path:
                print(f"(cond) (loop-exit) {addr} --> {cfg.nodes[addr].successors[0]}\t ss({len(ss)}) ", file=file)
                # a = input()                
                new_paths = dfs(cfg, cfg.nodes[addr].successors[0], end, path[:], ss[:], file=file) # follow loop exit
                for np in new_paths:
                    paths.append(np)
            else:
                paths.append(path)

        else: #neither --> this is a normal if-else
            for successor_addr in cfg.nodes[addr].successors:
                print(f"({cfg.nodes[addr].type}) {addr} --> {successor_addr}\t ss({len(ss)}) ", file=file)
                new_paths = dfs(cfg, successor_addr, end, path[:], ss, file=file)
                # print(f"{addr} : new_paths {len(new_paths)}")
                for np in new_paths:
                    paths.append(np)

    # print(f"{addr} : returning {len(paths)}")
    return paths

def get_loop_hashes(cfg, asm_funcs, start, end):
    debugFile = open('./logs/get_loop_hashes.log', 'w')
    loop_hashes = {}
    loop_paths = {}
    ln_count = 1
    for node_addr in cfg.loop_nodes:
        if int(node_addr,16) >= int(start, 16) and int(node_addr,16) <= int(end, 16):
            if cfg.nodes[node_addr].type == 'cond':
                loop_start = cfg.nodes[node_addr].successors[0]
                loop_end = cfg.nodes[node_addr].successors[1]
            elif cfg.nodes[node_addr].type == 'uncond':
                loop_start = cfg.nodes[node_addr].successors[0]
                loop_end = cfg.nodes[node_addr].adj_instr #insturciion before will jump over the br
            # loop start should be smaller than loop_end
            print(f"loop_start: {loop_start} {type(loop_start)}", file=debugFile)
            print(f"loop_end: {loop_end} {type(loop_end)}", file=debugFile)
            if int(loop_start, 16) >= int(loop_end, 16):
                tmp = loop_start
                loop_start = loop_end
                loop_end = tmp

            print(f"Loop start = {loop_start}, Loop ends = {loop_end}", file=debugFile)
            # a = input()
            print("Starting Loop DFS..")
            lp = dfs(cfg, loop_start, loop_end, ss=None, file=None)
            for l in lp:
                print(l, file=debugFile)
            print("Done")
            # a = input()
            # print(f"loop paths = {lp}")
            # lp = get_valid_paths(cfg, lp)
            # print(len(lp))       
            hashes = []
            path_count = 1
            for path in lp:
                print(f"Getting path {path_count}/{len(lp)} in loop {ln_count}/{len(cfg.loop_nodes)}", end='\r')
                # if len(path) > 1:
                #     p = path[1:]
                # else:
                print(len(path), file=debugFile)
                p = path
                loop_hash = 0
                for i in range(0, len(p)-1): # remove loop enter and exit
                    addr = p[i]
                    loop_hash ^= int(addr, 16)
                    encoded = str(loop_hash).encode()
                    loop_hash = int(sha256(encoded).hexdigest(),16)
                    print(f"{addr}   {loop_hash}", file=debugFile)
                print("", file=debugFile)
                # print(f"{p} --> {loop_hash}")
                hashes.append(loop_hash)
                path_count += 1
            loop_hashes[loop_start] = hashes
            loop_paths[loop_start] = lp[1:] #first is redundant
            print("")
        ln_count += 1

    # for loops that go 
    #           cond --> uncond (loop continue) --> cond --> (loop_exit) 
    # need to remove the redundant entry from the loop paths:
    for key in loop_paths:
        ls = loop_paths[key] #loop set
        for i in range(0, len(ls)):
            lp = ls[i]
            if len(lp) > 1:
                if lp[0] != key:
                    loop_paths[key][i] = lp[1:]

    print("Done")

    print("", file=debugFile)
    for key in loop_paths.keys():
        print(f"{key} : {loop_paths[key]}", file=debugFile)
    print("", file=debugFile)
    debugFile.close()
    
    return loop_hashes, loop_paths

def get_valid_hashes(cfg, asm_funcs, hash_set):
    debugFile = open('./logs/get_valid_hashes.log', 'w')

    start = cfg.head.start_addr # either "main" or "application"
    if cfg.arch.type == 'elf32-msp430':
        end = cfg.label_addr_map['__stop_progExec__']
    else:
        end = asm_funcs[start].end_addr

    print("Getting loop_hashes")
    loop_hashes, loop_paths = get_loop_hashes(cfg, asm_funcs, start, end)
    # loop_paths is a dict --> key is the loop start address, elt is a list of hashes for all internal loop paths

    print(f"\nDFS search range: ({start}, {end})", file=None)
    print("DFS Start...")
    program_paths = dfs(cfg, start, end, ss=None, file=debugFile)
    print(f"Done. {len(program_paths)} paths")
    # a = input()
    print(len(program_paths), file=debugFile)
    for p in program_paths:
        print("------", file=debugFile)
        for addr in p:
            print(addr, file=debugFile)
    print("", file=debugFile)
    # program_paths = get_valid_paths(cfg, program_paths)
    path_count = 1
    print(len(program_paths), file=debugFile)
    for p in range(0, len(program_paths)):
        ppath = program_paths[p]
        # print(ppath)
        ppath_str = str(ppath).replace("[", "").replace("]", "").replace("\'", "")
        # print(ppath_str)
        # print(f"[{ppath_str}]", file=debugFile)
        ln_count = 1
        print(f"Processing path {path_count}\tof {len(program_paths)}", end='\r')
        for ls, lps in loop_paths.items():
            # ls --> addr
            # lps --> 2d list'
            lp_count = 1
            for lp in lps:
                #lp --> list
                lp_str = str(lp).replace("[", "").replace("]", "").replace("\'", "")
                # print(lp_str)
                # print(f"[{lp_str}] in ppath_str: {lp_str in ppath_str}", file=debugFile)
                if ',' in lp_str: # if it has more than one xfer
                    print(f"[{ppath_str}]", file=debugFile)
                    print(f'replacing {lp_str} with {f"{lp[0]}, {lp[-1]}"}', file=debugFile)
                    ppath_str = ppath_str.replace(lp_str, f"{lp[0]}, {lp[-1]}")
                    print(f"[{ppath_str}]\n", file=debugFile)
                # a = input()
                lp_count += 1
            ln_count += 1
        program_paths[p] = ppath_str.split(', ')
        path_count += 1
        # print("\n", file=debugFile)
        # program_paths[p] = [z.replace('\'', '') for z in program_paths[p]]
    print("")

    # get loop starts from the loop nodes
    loop_starts = []
    for addr in cfg.loop_nodes:
        ln = cfg.nodes[addr]
        # loop start should be smaller than loop_end
        if ln.type == 'cond':
            # print(f"{addr} is 'cond'", file=debugFile)
            if int(ln.successors[0], 16) <= int(ln.successors[1], 16):
                loop_starts.append(ln.successors[0])
            else:
                loop_starts.append(ln.successors[1])
        elif ln.type == 'uncond':
            loop_starts.append(ln.successors[0])
    debugFile.close()
    # print(f"\nloop_starts: {loop_starts}")
    ### traverse loop paths, when reaching a start address, save the tmp value to the mapping
    loop_start_hash_val_mapping = {}
    valid_program_hashes = []
    f = open('./logs/program_paths.log', 'w')
    print("---", file=f)
    print("")
    path_count = 1
    for path in program_paths:
        print(f"Hashing path\t{path_count}\tof {len(program_paths)}", end='\r')
        hash_val = 0
        # path = path[1:]
        print(f"{len(path)}", file=f)
        for addr in path:
            # print(f"{addr}")
            hash_val ^= int(addr, 16)
            encoded = str(hash_val).encode()
            hash_val = int(sha256(encoded).hexdigest(),16)
            if addr in loop_starts: #found it so save the tmp value to the mapping
                if addr in loop_start_hash_val_mapping.keys():
                    loop_start_hash_val_mapping[addr].append(hash_val)
                else:
                    loop_start_hash_val_mapping[addr] = [hash_val]
            print(f"{addr}  {hash_val}", file=f)        
        print("---", file=f)
        path_count += 1
        # a = input()
            # print(f"{addr} : {hash_val}")
        valid_program_hashes.append(hash_val)
        # print("------------------")
    print("")
    print("")
    f.close()

    hash_set.valid_program_hashes = valid_program_hashes
    hash_set.loop_start_hash_value_mapping = loop_start_hash_val_mapping
    hash_set.loop_path_hashes = loop_hashes

    return hash_set

def verify_hash_evidence(cflog, cfg, hash_set):
    print("\nStarting to verify the hash evidence...")
    f = open('hash_evidence.cflog', 'r')
    lines = [x.replace('\n', '') for x in f.readlines()]
    f.close()

    hash_chain = int(lines[0])
    print(f"\nhash_chain : {hash_chain}")
    print(hash_set.valid_program_hashes)
    print(hash_chain in hash_set.valid_program_hashes)
    valid_final_hash = hash_chain in hash_set.valid_program_hashes
    occurring_loop_paths = {}
    for x in lines[1:]:
        loop_metadata = x.split('<')
        occurring_loop_paths[int(loop_metadata[0])] = []
        for lm in loop_metadata[1:]:
            occurring_loop_paths[int(loop_metadata[0])].append(int(lm.split(',')[0]))
    
    print()
    valid_loops = True
    for mapping_key, evidence_path_hashes in occurring_loop_paths.items():
        print(f"{mapping_key} : {evidence_path_hashes}")
        loop_addr = None
        for addr,valid_tokens in hash_set.loop_start_hash_value_mapping.items():
            # print(f"trying {mapping_key}")
            if mapping_key in valid_tokens:
                loop_addr = addr
                # print(f"Mapping key found for {addr}")
                break
        if loop_addr != None:
            for path_hash in evidence_path_hashes:
                if path_hash not in hash_set.loop_path_hashes[loop_addr]:
                    # print(f"{path_hash} Not in set!")
                    valid_loops = False
                # else:
                    # print(f"{path_hash} found in evidence")
        # print(key in hash_set.valid_program_hashes)
    valid = valid_final_hash and valid_loops
    if valid:
        print("\nVerification Passed!")
    else:
        print(f"\nVerification Failed!\n\tFinal Hash:\t{valid_final_hash}\n\tLoop Hash:\t{valid_loops}")

def get_hybrid_evidence(cfg, cflog):
    bits = []
    hash_ret = 0
    current_node = cfg.head
    for log_node in cflog:
        if current_node.type == 'cond':
            if log_node.dest_addr == current_node.adj_instr:
                bits.append("0")
            else:
                bits.append("1")
                
        elif current_node.type == 'uncond':
            # print(f"{log_node.dest_addr} vs {current_node.successors}")
            if current_node.start_addr in cfg.indr_jumps:
                addr_bits = bin(int(log_node.dest_addr, 16))[2:]
                addr_bits = "0"*(16-len(addr_bits))+addr_bits
                bits.append(addr_bits)
            else:
                bits.append("1")
                
        # If its a call, we need to push adj addr to shadow stack
        elif current_node.type == 'call': 
            if current_node.start_addr in cfg.indr_calls:
                addr_bits = bin(int(log_node.dest_addr, 16))[2:]
                addr_bits = "0"*(16-len(addr_bits))+addr_bits
                bits.append(addr_bits)
            else:
                bits.append("1")

        elif current_node.type == 'ret': 
            hash_ret ^= int(log_node.dest_addr, 16)
            hash_ret_encoded = str(hash_ret).encode()
            hash_ret = int(sha256(hash_ret_encoded).hexdigest(),16)

        current_node = cfg.nodes[log_node.dest_addr]

    print(f"hash_ret: {hash_ret}")
    bitstream = ''
    for b in bits:
        bitstream += b
    # print(f"bits : {bits}")
    print(f"bitstream: {bitstream}")

    f = open("./hybrid_evidence.cflog", "w")
    print(f"{hex(int(bitstream, 2))[2:]}", file=f)
    print(f"{hex(hash_ret)[2:]}", file=f)
    f.close()

    size = len(hex(hash_ret)[2:])/2 + len(hex(int(bitstream, 2))[2:])/2

    sizeFile = open("./logs/sizes.log", "a")
    print(f"Hybrid evidence size: {size} bytes", file=sizeFile)
    sizeFile.close()


def verify_hybrid_evidence(cfg):
    print("\nStarting to verify the hybrid evidence...")
    f = open("./hybrid_evidence.cflog", "r")
    lines = [x.replace('\n', '') for x in f.readlines()]
    f.close()    
    bitstream = bin(int(lines[0], 16))[2:]
    hash_ret = int(lines[1], 16)
    print(f"\nhash_ret: {hash_ret}")
    print(f"bitstream: {bitstream}")

    shadow_stack = deque()

    app_entry = 0
    current_node = cfg.head
    print(f"Current node: {current_node.start_addr}")
    a = input()
    bit_idx = 0

    addr_bit_len = 8*cfg.arch.regular_instr_size
    hash_ret_prv = 0
    while bit_idx < len(bitstream):

        if current_node.type == 'cond':
            if bitstream[bit_idx] == '0':
                current_node = cfg.nodes[current_node.adj_instr]
            else:
                adj_idx = current_node.successors.index(current_node.adj_instr) # take branch could be 0 or 1
                current_node = cfg.nodes[current_node.successors[adj_idx ^ 1]] # go to the opposite
            bit_idx += 1

        elif current_node.type == 'uncond':
            # print(f"{log_node.dest_addr} vs {current_node.successors}")
            if current_node.start_addr in cfg.indr_jumps:
                indr_target = bitstream[bit_idx : bit_idx+addr_bit_len]
                # print(f"indr_target: {indr_target}")
                indr_target = hex(int(indr_target, 2))
                # print(f"indr_target: {indr_target}")
                # a = input()
                if indr_target in current_node.successors:
                    current_node = cfg.nodes[current_node.adj_instr]
                    bit_idx += addr_bit_len
                else:
                    print(f"FAILED AT INDR JUMP TO: {indr_target}")
                    return False
            else:
                current_node = cfg.nodes[current_node.successors[0]]
                bit_idx += 1

        # If its a call, we need to push adj addr to shadow stack
        elif current_node.type == 'call': 
            shadow_stack.append(current_node.adj_instr)

            if current_node.start_addr in cfg.indr_calls:
                indr_target = bitstream[bit_idx : bit_idx+addr_bit_len]
                if indr_target in current_node.successors:
                    current_node = cfg.nodes[current_node.adj_instr]
                    bit_idx += addr_bit_len
                else:
                    print(f"FAILED AT INDR CALL TO: {indr_target}")
                    return False
            else:
                current_node = cfg.nodes[current_node.successors[0]]
                bit_idx += 1

        elif current_node.type == 'ret': 
            ret_addr = shadow_stack.pop()
            
            hash_ret_prv ^= int(ret_addr, 16)
            hash_ret_encoded = str(hash_ret_prv).encode()
            hash_ret_prv = int(sha256(hash_ret_encoded).hexdigest(),16)

            current_node = cfg.nodes[ret_addr]

    print(f"hash_ret_prv: {hash_ret_prv}")
    return hash_ret_prv == hash_ret

def main():
    start = time.perf_counter()
    args = arg_parser()

    # Load cfg
    cfg = load(args.cfgfile)
    asm_func_file = args.cfgfile.replace("cfg", "asm_func")
    asm_funcs = load(asm_func_file)
    
    # If start addr not provided, lookup addr of function (or label) instead
    if not args.startaddr:
        try:
            start_addr = cfg.label_addr_map[args.funcname]
        except KeyError:
            print(f'{bcolors.RED}[!] Error: Invalid Function Name [{args.funcname}]{bcolors.END}')
            exit(1)
    else:
        start_addr = args.startaddr

    # Set the cfg head to the start address of where we want to attest
    cfg = set_cfg_head(cfg, start_addr)

    hash_set = HashSets()

    hash_set = get_valid_hashes(cfg, asm_funcs, hash_set)

    print("Built hash set.")
    stop = time.perf_counter()
    timingFile = open("./logs/timing.log", "a")
    print(f"Build Hash Set: {1000*(stop-start)} ms", file=timingFile)

    # a = input()

    print("Starting to verify hash...")
    # print(f"parsing {args.cflog}")
    cflog = parse_cflog(args.cflog, cfg.arch)
    # print(f"parsing {args.cflog} --> cflog size = {len(cflog)}")
    emulate_hash_chain(cfg, cflog)

    start = time.perf_counter()
    verify_hash_evidence(cfg, cflog, hash_set)
    stop = time.perf_counter()
    print(f"Verify Hash: {1000*(stop-start)} ms", file=timingFile)
    

    f = open("./logs/hash_set.log", "w")
    print('---------------------------------------------------', file=f)
    print("HASH SETS FOR CFA", file=f)
    print("Loop paths:", file=f)
    for loop_start_addr in hash_set.loop_path_hashes.keys():
        print(f"{loop_start_addr} : ", file=f)
        for loop_hash in hash_set.loop_path_hashes[loop_start_addr]:
            print(f"\t{loop_hash}", file=f)

    print("\nLoop Start --> Hash Value Mappping: ", file=f)
    for ls in hash_set.loop_start_hash_value_mapping.keys():
        print(f"{ls} : ", file=f)
        for hash_val in hash_set.loop_start_hash_value_mapping[ls]:
            print(f"\t{hash_val}", file=f)

    print("\nValid Progarm Hashes: ", file=f)
    for h in hash_set.valid_program_hashes:
        print(h, file=f)
    print('---------------------------------------------------', file=f)
    f.close()

    get_hybrid_evidence(cfg, cflog)
    
    start = time.perf_counter()
    valid = verify_hybrid_evidence(cfg)
    stop = time.perf_counter()
    print(f"Verify Hybrid: {1000*(stop-start)} ms", file=timingFile)
    timingFile.close()

    if valid:
        print("Verification Passes!")
    else:
        print("Verification Failed!")


if __name__ == '__main__':
    main()

