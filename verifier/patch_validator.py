from structures import *
from utils import *
from elftools.elf.elffile import ELFFile
from keystone import *
import os
from parse_asm import *
from verify import *
from MSProbe.assemble import *
import time

def build_patched_cfg(cfg):
    # build patched CFG
    patched_asmfile = 'patched.lst'

    # Parse asm file to python object
    lines = read_file(patched_asmfile, cfg.arch.type)

    # Set arch if provided
    arch = cfg.arch

    # Create the CFG from the asm file
    patched_cfg, asm_funcs = create_cfg(arch, lines)

    patched_cfg.head = cfg.head

    return patched_cfg

def translate_cflog_ARM(pg, cflog, func_start_cflog_idx, offending_cflog_index, arch):
    '''
    Translates the old cflog to a new one based on the generated patches
    Doesn't depend on the cfg, just the patches and the log slice
    ARM edition :-)
    '''

    print("------------------------------------------")
    print(" Translating CFLOG ")
    print("------------------------------------------")

    start = func_start_cflog_idx * int(func_start_cflog_idx >= 0)

    modified_targets = []
    for key, patch in pg.patches.items():
        for instr in patch.instr:
            if instr.instr in arch.all_br_insts:
                if instr.prev_addr != None:
                    print(f"adding {instr.arg} to modified_targets")
                    modified_targets.append('0x'+instr.arg)
                else:
                    pg.new_targets.append('0x'+instr.arg)
                    print(f"adding {instr.arg} to new_targets")
                    if instr.instr in arch.conditional_br_instrs:
                        adj_instr = hex(int(instr.addr,16) + arch.regular_instr_size)
                        pg.new_targets.append(adj_instr)

    target_mapping = {}
    for key, patch in pg.patches.items():
        for instr in patch.instr:
            if instr.addr in modified_targets:
                target_mapping[instr.prev_addr] = instr.addr
                
    translated_cflog = []
    if len(target_mapping.keys()) > 0:
        for log_node in cflog:
            if log_node.dest_addr in target_mapping.keys():
                new_log_node = CFLogNode(log_node.src_addr, target_mapping[log_node.dest_addr], log_node.loop_count)
                translated_cflog.append(new_log_node)
                # print(f"Change: {log_node.dest_addr} --> {new_log_node.dest_addr}")
            else:
                translated_cflog.append(log_node)
    else:
        translated_cflog = cflog[:]

    # a = input()
    return translated_cflog

def translate_cflog_MSP430(pg, cflog, slice_start, slide_end, arch):
    '''
    Translates the old cflog to a new one based on the generated patches
    Doesn't depend on the cfg, just the patches and the log slice
    '''

    # print("------------------------------------------")
    # print(" Translating CFLOG ")
    # print("------------------------------------------")

    start = slice_start * int(slice_start >= 0)
    
    # get modified targets (targets that were rewritten to a new dest w.i patch)
    # get new targets (targets due to branch instructions added by the patch)
    modified_targets = []
    modified_srcs = []
    modified_dests = []
    new_srcs = []
    new_dests = []
    # for key in pg.patches.keys():
        # print(f"{key} : {pg.patches[key]}")

    # a = input()

    for key, patch in pg.patches.items():
        for instr in patch.instr:
            if instr.instr in arch.conditional_br_instrs or instr.instr in arch.unconditional_br_instrs:
                # print(f"{instr.addr}\t{instr.reconstruct()}\t prev_addr={instr.prev_addr}")
                ### this instr is a prev br instruction moved into the patch region
                if instr.prev_addr != None:
                    if '#' in instr.arg: ## in the case of a jump via offset 
                        new_target = instr.arg.replace("#", "")
                        new_target = hex(int(new_target))
                    else: ## case of a direct address
                        offset = instr.arg.replace("$", "")
                        new_target = hex(int(instr.addr,16) + int(offset))

                    modified_targets.append(instr.addr)
                    modified_targets.append(new_target)
                    modified_srcs.append(instr.addr)
                    modified_dests.append(new_target)
                    
                    if instr.instr in arch.conditional_br_instrs:
                        adj = hex(int(instr.addr, 16)+2)
                        modified_targets.append(adj)
                        modified_dests.append(adj)
                else: # this is a new br custom to the patch
                    if '#' in instr.arg:
                        new_target = instr.arg.replace("#", "")
                        if '0x' not in new_target:
                            new_target = hex(int(new_target))
                    else:
                        offset = instr.arg.replace("$", "")
                        new_target = hex(int(instr.addr,16) + int(offset))

                    # print(f'adding {instr.addr}')
                    # modified_targets.append(instr.addr)
                    new_dests.append(new_target)
                    new_srcs.append(instr.addr)

            elif instr.instr in arch.call_instrs:
                new_target = instr.arg.replace("&","")
                
                if instr.prev_addr != None:
                    modified_targets.append(instr.addr)
                    modified_targets.append(new_target)
                    modified_srcs.append(instr.addr)
                    modified_dests.append(new_target)
                else:
                    new_dests.append(new_target)
                    new_srcs.append(instr.addr)

            elif instr.instr in arch.return_instrs:
                # print(f"{instr.addr}\t{instr.reconstruct()}\t prev_addr={instr.prev_addr}")

                ##since its a return, we just account for the source addr
                modified_targets.append(instr.addr)
                modified_srcs.append(instr.addr)

    '''
    print('\nModified sources: ')
    for addr in modified_srcs:
        print(addr)
    print()
    print('\nModified destinations: ')
    for addr in modified_dests:
        print(addr)
    print()
    print('\nNew sources: ')
    for addr in new_srcs:
        print(addr)
    print()
    print('\nNew destinations: ')
    for addr in new_dests:
        print(addr)
    print()
    print('\nModified targets: ')
    for addr in modified_targets:
        print(addr)
    print()
    '''

    # '''
    # find which instr use to be theirs
    # key : old addr, elt: new_addr
    target_mapping = {}
    for key, patch in pg.patches.items():
        for instr in patch.instr:
            if instr.addr in modified_targets and instr.prev_addr != None:
                target_mapping[instr.prev_addr] = instr.addr

    # print("Target Mapping: ")
    # for old, new in target_mapping.items():
        # print(f"{old} : {new}")

    # a = input()
    # '''
    translated_cflog = []
    # '''
    for log_node in cflog:
        if log_node.dest_addr in target_mapping.keys():
            if log_node.src_addr in target_mapping.keys():
                new_log_node = CFLogNode(target_mapping[log_node.src_addr], target_mapping[log_node.dest_addr], log_node.loop_count)
            else:
                new_log_node = CFLogNode(log_node.src_addr, target_mapping[log_node.dest_addr], log_node.loop_count)
            translated_cflog.append(new_log_node)
            # print(f"Change: {log_node.dest_addr} --> {new_log_node.dest_addr}")
        else:
            if log_node.src_addr in target_mapping.keys():
                new_log_node = CFLogNode(target_mapping[log_node.src_addr], log_node.dest_addr, log_node.loop_count)
                translated_cflog.append(new_log_node)
            else:
                translated_cflog.append(log_node)
    # '''

    return translated_cflog
