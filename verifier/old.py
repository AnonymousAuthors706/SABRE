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
    earlyLoopDetect = False
    loop_stack = []
    for i in range(0, len(cflog)):
        cflog_node = cflog[i]
        if last_addr is not None:
            # if cfg.nodes[last_addr].type == 'cond':
            #     print(f"{cfg.nodes[cflog_node.dest_addr].type}\t{cflog_node.dest_addr} < {last_addr} ---> {int(cflog_node.dest_addr, 16) < int(last_addr,16) and cfg.nodes[cflog_node.dest_addr].type == 'cond'}")
            # else:
            #     print(f"{cfg.nodes[cflog_node.dest_addr].type}\t{cflog_node.dest_addr}")

            if int(cflog_node.dest_addr, 16) < int(last_addr,16) and (cfg.nodes[last_addr].type == 'cond' or cfg.nodes[last_addr].type == 'uncond'):
                loop_entry = cflog_node.dest_addr
                loop_exit = cfg.nodes[last_addr].adj_instr  
                loop_hashes[last_addr] = []

            # special (unoptimized) case of loop
            elif int(cflog_node.dest_addr, 16) > int(last_addr,16) and cfg.nodes[last_addr].type == 'cond' \
                and int(cflog[i+1].dest_addr,16) < int(cflog_node.dest_addr, 16) and cfg.nodes[cflog_node.dest_addr].type == 'uncond': 
                print(i)
                print(f"last_addr --> {last_addr}")
                print(f"cflog_node.dest_addr --> {cflog_node.dest_addr}")
                print(f"cflog[i+1] --> {cflog[i+1].dest_addr}")
                loop_entry = cflog[i+1].dest_addr
                loop_exit = cfg.nodes[cflog_node.dest_addr].adj_instr  
                loop_hashes[last_addr] = []
                print(f"loop_exit --> {loop_exit}")
                print(f"loop_entry --> {loop_entry}")
                print(f"isLoop --> {isLoop}")
                a = input()
                continue

            if last_addr == loop_entry and isLoop == False:
                loop_stack.append((loop_entry, loop_exit, isLoop))
                # print(f"\t{last_addr}\tloop_entry\texit={loop_exit}")
                # print(f"\t\tpushing {(loop_entry, loop_exit, isLoop)} onto loop stack")
                hash_chain ^= int(last_addr, 16)
                hash_chain_encoded = str(hash_chain).encode()
                hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                loop_hashes[loop_entry] = hash_chain
                loop_entry = None
                isLoop = True
                print(f"{last_addr}  {hash_chain}", file=f)

            elif last_addr == loop_exit:
                print(f"loop exit : {cflog_node.dest_addr}")
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
                # print(f"non-loop {cflog_node.dest_addr}")
                # print(f"\t{last_addr}\tnon-loop")
                hash_chain ^= int(last_addr, 16)
                hash_chain_encoded = str(hash_chain).encode()
                hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                print(f"{last_addr}  {hash_chain}", file=f)
            # else:
                # print(f"{cflog_node.dest_addr}")
        # else:
        #     print(f"{cflog_node.dest_addr}\tnon-loop")
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
    print("Loop Hashes:")
    for loop_entry, loop_path in loop_hashes.items():
        print(f"  Loop Entry {loop_entry}: {sha256(str(loop_path).encode()).hexdigest()}")

    f = open('hash_evidence.cflog', 'w')
    f.write(str(hash_chain))
    f.close()
    # return hash_chain, loop_hashes

# def get_valid_paths(cfg, paths):
#     valid_paths = []
#     for path in paths:
#         print("----")
#         valid = True
        
#         for i in range(0, len(path)):
#             # print(path)
#             addr = path[i]
#             node = cfg.nodes[addr]
#             print(addr)
#             if cfg.nodes[addr].type == 'call':
#                 print(f"\tat {addr} pushing {node.adj_instr}")
#                 stack.append(node.adj_instr)
#             elif cfg.nodes[addr].type == 'ret':
#                 try:
#                     valid_addr = stack.pop()
#                     if valid_addr != path[i+1]:
#                         print(f"{valid_addr} != {path[i+1]}")
#                         valid = False
#                         break
#                 except IndexError:
#                     # if we cannot pop from the shadow stack, we reached a return place in the middle of the loop. Return valid and break
#                     valid = True
#                     break

#         if valid:
#             valid_paths.append(path)

#     return valid_paths


def emulate_hash_chain(cfg, cflog):
    print("emulating hash chain...")
    loops = {}
    node = cfg.head
    start_idx = 0
    loop_started = False
    loop_path = ''
    hash_chain = 0
    count = 0
    f = open('./logs/emulate_hash_chain.log', 'w')
    for i in range(0, len(cflog)):
        # print(f'{node.start_addr}')
        if node.type == 'cond' and (int(node.successors[0],16) < int(node.end_addr,16) or int(node.successors[1],16) < int(node.end_addr,16)):
            print(f"\t{cflog[i].dest_addr} {loop_started} 0")
            # print(f"x {cflog[i].dest_addr} {node.type}")
            # print("this is looping back")
            if int(cflog[i].dest_addr, 16) < int(node.end_addr, 16):
                print(f"\t{cflog[i].dest_addr} {loop_started} 1")
                # print(f"LOOPS CONT ({i}): {node.end_addr} --> {cflog[i].dest_addr}")
                if node.end_addr+'-'+str(start_idx) in loops.keys():
                    loops[node.end_addr+'-'+str(start_idx)]['count'] += 1
                    print(f"\t{cflog[i].dest_addr} {loop_started} 2")
                    if 'loop_paths' in loops[node.end_addr+'-'+str(start_idx)].keys():
                        # l = len(loops[node.end_addr+'-'+str(start_idx)]['loop_paths'])
                        if loop_path in loops[node.end_addr+'-'+str(start_idx)]['loop_paths'].keys():
                            print(f"\t{cflog[i].dest_addr} {loop_started} 3")
                            loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path] += 1
                            # print(f"\t\tincrementing loop_path: loops[{node.end_addr+'-'+str(start_idx)}]['loop_paths'][{loop_path}] = {loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path]}")
                        else:
                            loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path] = 1
                            # print(f"\t\tloop has paths but not this one: loops[{node.end_addr+'-'+str(start_idx)}]['loop_paths'][{loop_path}] = {loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path]}")
                    else:
                        print(f"\t{cflog[i].dest_addr} {loop_started} 4")
                        loops[node.end_addr+'-'+str(start_idx)]['loop_paths'] = {}
                        loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path] = 1
                        # print(f"\t\tfirst loop path for this loop: loops[{node.end_addr+'-'+str(start_idx)}]['loop_paths'][{loop_path}] = {loops[node.end_addr+'-'+str(start_idx)]['loop_paths'][loop_path]}")
                    loop_path = ''

                else:
                    print(f"\t{cflog[i].dest_addr} {loop_started} 5")
                    loop_path = ''
                    start_idx = i
                    loop_started = True
                    # print("\tsetting loop_started == True")
                    print(f"accumulating {cflog[i].dest_addr} into hash")
                    loops[node.end_addr+'-'+str(start_idx)] = {}
                    loops[node.end_addr+'-'+str(start_idx)]['dest'] = node.start_addr
                    loops[node.end_addr+'-'+str(start_idx)]['count'] = 0
                    # hash_chain ^= int(cflog[i].dest_addr, 16)
                    # hash_chain_encoded = str(hash_chain).encode()
                    # a = input()
                    # hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
                    loops[node.end_addr+'-'+str(start_idx)]['H_enter'] = hash_chain
                    count += 1
                    print(f"{cflog[i].dest_addr}   {hash_chain}", file=f)
            else:
                try:
                    print(f"\t{cflog[i].dest_addr} {loop_started} 6")
                    loop_started = False
                    # print("\tsetting loop_started == False")
                    loops[node.end_addr+'-'+str(start_idx)]['exit'] = node.start_addr
                    # print(f"LOOPS EXIT ({i})]: {node.end_addr} --> {cflog[i].dest_addr}")
                    start_idx = i
                except KeyError:
                    print(f"\t{cflog[i].dest_addr} {loop_started} 7")
                    start_idx = i
                    # this is reached if the loop only exits
                continue

        if loop_started:
            print(f"\t{cflog[i].dest_addr} {loop_started} 8")
            # print(f"\tadding {cflog[i].dest_addr} to loop_path")
            if loop_path == '':
                loop_path += cflog[i].dest_addr
            else:
                loop_path += '-'+cflog[i].dest_addr
        else:
            print(f"\t{cflog[i].dest_addr} {loop_started} 9")
            print(f"accumulating {cflog[i].dest_addr} into hash")
            hash_chain ^= int(cflog[i].dest_addr, 16)
            hash_chain_encoded = str(hash_chain).encode()
            # a = input()
            hash_chain = int(sha256(hash_chain_encoded).hexdigest(),16)
            count += 1
            print(f"{cflog[i].dest_addr}   {hash_chain}", file=f)
            # print(f"({cflog[i].dest_addr}) hash_chain value: {hex(hash_chain)}")

        node = cfg.nodes[cflog[i].dest_addr]
        # print()
    print(f"{count}", file=f)
    
    print(f"hash_chain value: {hash_chain}")
    print()
    ff = open('hash_evidence.cflog', 'w')
    ff.write(f"{hash_chain}\n")
    for br_addr in loops.keys():
        loop_encoding = ''
        # print(f"{br_addr} :")
        # print(f"\tloop[dest]\t{loops[br_addr]['dest']}")
        # print(f"\tloop[count]\t{loops[br_addr]['count']}")
        # print(f"\tloop[H_enter]\t{hex(loops[br_addr]['H_enter'])}")
        loop_encoding += str(loops[br_addr]['H_enter'])
        try:
            # print(f"\tloop[exit]\t{loops[br_addr]['exit']}")
            # print(f"\tloop[loop_paths]: ")
            for path in loops[br_addr]['loop_paths'].keys():
                # print(f"\t {path} : {loops[br_addr]['loop_paths'][path]}")
                # # now lets make the hash of the loop path
                loop_addrs = path.split('-')
                loop_addrs = loop_addrs[1:]
                hash_val = 0
                print(f"loop path {br_addr}", file=f)
                for addr in loop_addrs:
                    print(f"{addr}")
                    hash_val ^= int(addr, 16)
                    hash_val_encoded = str(hash_val).encode()
                    # a = input()
                    hash_val = int(sha256(hash_val_encoded).hexdigest(),16)
                    # print(f"\t\thash_digest : {hash_val}")
                    # a = input()
                    # hash_val = int(, 16)
                    print(f"{addr}   {hash_val}", file=f)
                print( )
                loop_encoding += f"<{hash_val},{loops[br_addr]['loop_paths'][path]}> "

            ff.write(loop_encoding+'\n')
            # a = input()
        except KeyError:
            # print("\tno exit")
            # print("\tno loop_path")
            continue
    print(f"Full evidence written to 'hash_evidence.cflog'")
    ff.close()
    f.close()

# def get_valid_paths(cfg, paths):
#     valid_paths = []
#     for path in paths:
#         print("----")
#         valid = True
        
#         for i in range(0, len(path)):
#             # print(path)
#             addr = path[i]
#             node = cfg.nodes[addr]
#             print(addr)
#             if cfg.nodes[addr].type == 'call':
#                 print(f"\tat {addr} pushing {node.adj_instr}")
#                 stack.append(node.adj_instr)
#             elif cfg.nodes[addr].type == 'ret':
#                 try:
#                     valid_addr = stack.pop()
#                     if valid_addr != path[i+1]:
#                         print(f"{valid_addr} != {path[i+1]}")
#                         valid = False
#                         break
#                 except IndexError:
#                     # if we cannot pop from the shadow stack, we reached a return place in the middle of the loop. Return valid and break
#                     valid = True
#                     break

#         if valid:
#             valid_paths.append(path)

#     return valid_paths


def step():
    if 'mov' in instr:
        src,dest = arg.split(",")
        if '@r' in src and 'r' in dest: #move from dereferenced reg to reg
            try:
                src_from_mem = self.mem[self.reg[src.replace('@','')]]
            except KeyError:
                # self.mem[self.reg[src.replace('@','')]] = 'y_'+src.replace('@','')+'_'+addr
                self.mem[self.reg[src.replace('@','')]] = 'y_'+str(self.symbolic_count)
                self.symbolic_count+=1
                src_from_mem = self.mem[self.reg[src.replace('@','')]]
            self.reg[dest] = src_from_mem

        elif 'r' in src and 'r' in dest and '(' not in src and '(' not in dest: #write reg to reg
            conditional_print("case 1: write reg to reg", file=self.debugFile, flag=self.debug)
            self.reg[dest] = src

        elif '(' in dest and '(' not in src: #write imm/reg to reg-mem
            conditional_print("case @: write imm/reg to mem", file=self.debugFile, flag=self.debug)
            idx,b = dest[:-1].split('(')
            if '-' not in idx:
                idx = '+'+idx
                
            mem_addr = self.evaluate_expression(self.reg[b]+idx)
            
            if '#' in src: #imm
                src = src.replace('#', '')        
                self.mem[mem_addr] = src 
            else: #reg
                self.mem[mem_addr] = self.reg[src]
            valid = self.compare_to_base(mem_addr)
            

        elif '(' in src and '(' not in dest: #write mem to reg
            conditional_print("case 3: write mem to reg", file=self.debugFile, flag=self.debug)
            idx,b = src[:-1].split('(')
            if '-' not in idx:
                idx = '+'+idx
            print()
            mem_addr = self.evaluate_expression(self.reg[b]+idx)
            self.reg[dest] = self.mem[mem_addr]

        elif '#' in src:
            # mov imm into reg
            imm = src.replace("#", '')                     
            self.reg[dest] = imm

        elif '&' in src:
            # mov hex imm into reg
            imm = str(int(src.replace("&", ''),16))
            self.reg[dest] = imm

def update_idr_call_sites(cfg, idr_call_node_addr):
    # get all paths to the idr call
    paths = find_paths(cfg, idr_call_node_addr)
    debugFile = open('./logs/rda.log', 'w')
    rda_emulator = Emulator(cfg.arch, 'rda', debugFile)
    print(" ")
    print(rda_emulator)
    count = 1
    r3 = []
    _ = system('clear')
    print('-------------------------------------------')
    print(' Emulating paths to determine call sites ' )
    print('-------------------------------------------')
    for path in paths:
        n = 1
        i = 1
        total = 0
        for addr in path:
            total += len(cfg.nodes[addr].instr_addrs)
            for instr in cfg.nodes[addr].instr_addrs:
                # print(instr)
                print(f"Path {count}; Node {n}/{len(path)}; Instruction {i}/{total}   {instr}   ", end='\r')
                i += 1
                rda_emulator.step(instr)
            n += 1
        r3.append(hex(int(rda_emulator.reg['r3'])))
        print(f"------------------------- Done path {count} --------------------- ", file=debugFile)
        count += 1
        print('')
        # a = input()
    debugFile.close()

    print('Possible values of r3:')
    for i in range(0, len(r3)):
        print(r3[i])


def function():
    rda_emulator = Emulator(cfg.arch, 'rda')
    print(" ")
    print(rda_emulator)
    node = cfg.nodes[cfg.head]
    toVisit = node.successors[:]
    visited = []
    c = 0
    first = True
    while len(toVisit) != 0:
        print()
        print(f"Node: {node.start_addr} {len(node.parents)}")
        #if node has no parents
        if len(node.parents) == 0 or first:
            # step through instructions
            for asm_inst in node.instr_addrs:
                print(f"stepping through {asm_inst.addr}: {asm_inst.instr} {asm_inst.arg}")
                rda_emulator.step(asm_inst)

            ## udpate definitions
            for r in rda_emulator.reg.keys():
                node.definitions[r] = {}
                node.definitions[r][node.start_addr] = rda_emulator.reg[r]
            print(f"definitions: {node.definitions}")

            # remove from toVisit; add to visited
            visited.append(node.start_addr)
            # if running for the first time
            if first:
                first = False
            else:
                toVisit = toVisit[1:]
                # toVisit.remove(node.start_addr)
            print(f"visited: {len(visited)}")
            node = cfg.nodes[toVisit[0]]
            for addr in node.successors:
                if addr != node.start_addr:
                    toVisit.append(addr)
            print(f"toVisit: {len(toVisit)}")

        #if node has parents but they have all been visited
        elif len(node.parents) > 0:# and (False not in [addr in visited for addr in node.parents]):
            print("Case 1")
            # set node definitions as union of parent definitions
            print(node.parents)
            for p in node.parents:
                if p == node.start_addr:
                    continue

                pnode = cfg.nodes[p]
                # initialize it by setting to the first parent
                if len(node.definitions.keys()) == 0:
                    for r in pnode.definitions.keys():
                        node.definitions[r] = pnode.definitions[r]
                # if already initialized, iterate through parent to create union of definitions
                else:
                    print(f"ELSE")
                    print("Parent definitions: ")
                    for r in pnode.definitions.keys():
                        print(f"{r} : {pnode.definitions[r]}")
                        if r not in node.definitions.keys():
                            node.definitions[r] = pnode.definitions[r]
                        else:
                            for addr in pnode.definitions[r].keys():
                                if addr not in node.definitions[r].keys():
                                    node.definitions[r][addr] = pnode.definitions[r][addr]
                    # for r in pnode.definitions.keys():
                    #     try:
                    #         node.definitions[r][pnode.start_addr] = pnode.definitions[r]
                    #     except KeyError:
                    #         #means reg is not currently in node.definitions
                    #         node.definitions[r] = {}
                    #         node.definitions[r][pnode.start_addr] = pnode.definitions[r]

                    # print(f"{key} : {pnode.definitions[key]}")
            print("Node definitions: ")
            for r in node.definitions.keys():
                print(f"{r} : {node.definitions[r]}")
            ##step through instructions
            for asm_inst in node.instr_addrs:
                print(f"stepping through {asm_inst.addr}: {asm_inst.instr} {asm_inst.arg}")
                rda_emulator.step(asm_inst)

            # #update definitions
            for r in rda_emulator.reg.keys():
                if r in node.definitions.keys():
                    print(f"{r} in {node.definitions.keys()}")
                    needsUpdate = True
                    for def_addr in node.definitions[r].keys():
                        if rda_emulator.reg[r] == node.definitions[r][def_addr]:
                            needsUpdate = False
                            break
                    if needsUpdate:
                        node.definitions[r] = {node.start_addr : rda_emulator.reg[r]}
                else:
                    print(f"{r} not in {node.definitions.keys()}")
                    node.definitions[r] = {node.start_addr : rda_emulator.reg[r]}

            # remove from toVisit; add to visited
            visited.append(node.start_addr)
            # toVisit.remove(node.start_addr)
            toVisit = toVisit[1:]
            print(f"visited: {len(visited)}")
            node = cfg.nodes[toVisit[0]]
            for addr in node.successors:
                if addr != node.start_addr:
                    toVisit.append(addr)
            print(f"toVisit: {len(toVisit)}")

        #if node has parents but they all have not been visited yet...
        #traverse UPWARDS by setting next node as one of the parents
        else:
            print("Case 2")
            a = input()
            # for addr in node.parents:
            #     if addr not in visited:
            #         next_addr = addr
            #         break
            # print(f'Next node: {next_addr}')
            # node = cfg.nodes[next_addr]
            # a = input()

        print("Node definitions: ")
        for r in node.definitions.keys():
            print(f"{r} : {node.definitions[r]}")
        c += 1

def find_all_paths(graph, start, end, path=[]):
    """
    Find all paths from start to end node in the graph.
    
    Args:
    - graph: dictionary representing the graph where keys are nodes and values are lists of successor nodes.
    - start: starting node.
    - end: target node.
    - path: list representing the current path (used in recursion).

    Returns:
    - List of all paths from start to end node.
    """
    path = path + [start]
    if start == end:
        return [path]
    if start not in graph:
        return []
    paths = []
    for node in graph[start]:
        if node not in path:
            new_paths = find_all_paths(graph, node, end, path)
            for new_path in new_paths:
                paths.append(new_path)
    return paths

import multiprocessing

def traverse_path(args):
    cfg, path = args
    # Function to traverse a single path in the CFG
    # Implement your path traversal logic here

    # Example logic: Return the path
    return f"Traversing path: {path}"

if __name__ == "__main__":
    # Define your CFG object
    cfg = {
        'A': ['B', 'C'],
        'B': ['D'],
        'C': ['D'],
        'D': ['E'],
        'E': []
    }

    # Define the list of paths
    paths = [['A', 'B', 'D', 'E'], ['A', 'C', 'D', 'E']]

    # Create a multiprocessing Pool with the desired number of processes
    num_processes = multiprocessing.cpu_count()  # Use the number of CPU cores
    pool = multiprocessing.Pool(processes=num_processes)

    # Map the traverse_path function to the pool of processes and pass each path as an argument
    results = pool.map(traverse_path, [(cfg, path) for path in paths])

    # Close the pool to release resources
    pool.close()
    pool.join()

    # Merge all outputs into a list
    all_outputs = results

    print(all_outputs)

