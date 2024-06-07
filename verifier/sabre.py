from collections import deque
import argparse
import pickle
import os
from structures import *
from utils import *
import argparse
from verify import *
from exploit_locator import *
from patch_generator import *
from patch_validator import *
import time

'''
Main SABRE file that calls other modules
'''
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


def main():
	args = arg_parser()

	cfg, cflog, asm_funcs, valid, current_node, offending_node, offending_cflog_index = path_verifier(args.cfgfile, args.cflog, args.funcname)

	expl_type = current_node.type

	if expl_type == 'ret':
	    exp_func, exp_addr, func_start_cflog_idx, exploited_ctrl = backwards_trace(cfg, cflog, current_node, asm_funcs, offending_cflog_index, expl_type)

	    node_addr, expl_instr_addr, loopcount, cflog_idx_mem_instr, emulator = locate_exploit(cfg, cflog, func_start_cflog_idx, offending_cflog_index, current_node.type)
	    mem_accesses = emulator.mem_accesses
	    emul_instrs = emulator.total_instrs
    
	    if cfg.arch.type == 'armv8-m33':
	        pg = generate_patch_ARM(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx_mem_instr, emulator)

	        translated_cflog = translate_cflog_ARM(pg, cflog, func_start_cflog_idx, offending_cflog_index, cfg.arch)
	        
	        f = open("translated.cflog", "w")
	        for log_node in translated_cflog:
	            f.write(f"{log_node.dest_addr[2:]}\n")
	            if log_node.loop_count != None:
	                f.write(f'{log_node.loop_count}\n')
	        f.close()

	        print('New targets: ')
	        for addr in pg.new_targets:
	            print(addr)

	        patched_cfg = build_patched_cfg(translated_cflog, cfg, func_start_cflog_idx, offending_cflog_index, pg)
	        cflog_verify_patch_idx = cflog_idx_mem_instr+1
	        node_addr, instr_addr, _, _, emulator = locate_exploit(patched_cfg, translated_cflog, func_start_cflog_idx, cflog_verify_patch_idx, current_node.type, None, pg.new_targets)
	        mem_accesses = emulator.mem_accesses
	        emul_instrs = emulator.total_instrs

	    elif cfg.arch.type == 'elf32-msp430':
	        print('func of expl. mem instr:')
	        
	        vul_mem_func_bounds = ("","")
	        for func_addr in asm_funcs.keys():
	            func = asm_funcs[func_addr]
	            if int(func.start_addr, 16) <= int(expl_instr_addr, 16) <= int(func.end_addr, 16):
	                vul_mem_func_bounds = (func.start_addr, func.end_addr)
	        	        
	        pg = generate_patch_MSP430(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx_mem_instr, vul_mem_func_bounds, emulator)

	        translated_cflog = translate_cflog_MSP430(pg, cflog, func_start_cflog_idx, offending_cflog_index, cfg.arch)
	        
	        f = open("translated.cflog", "w")
	        for log_node in translated_cflog:
	            f.write(f"{log_node.src_addr[2:]}:{log_node.dest_addr[2:]}\n")
	            if log_node.loop_count != None:
	                f.write(f'0000:{log_node.loop_count}\n')
	        f.close()

	        print('New targets: ')
	        for addr in pg.new_targets:
	            print(addr)

	        patched_cfg = build_patched_cfg(translated_cflog, cfg, func_start_cflog_idx, offending_cflog_index, pg)

	        cflog_verify_patch_idx = cflog_idx_mem_instr+1
	        node_addr, instr_addr, _, _, emulator = locate_exploit(patched_cfg, translated_cflog, func_start_cflog_idx, cflog_verify_patch_idx, current_node.type, None, pg.new_targets)
	        mem_accesses = emulator.mem_accesses
	        emul_instrs = emulator.total_instrs

	elif expl_type == 'call':
	    exp_func, exp_addr, func_start_cflog_idx, exploited_ctrl = backwards_trace(cfg, cflog, current_node, asm_funcs, offending_cflog_index, expl_type)

	    node_addr, expl_instr_addr, loopcount, cflog_idx_mem_instr, emulator = locate_exploit(cfg, cflog, func_start_cflog_idx, offending_cflog_index, current_node.type, exploited_ctrl)
	    mem_accesses = emulator.mem_accesses
	    emul_instrs = emulator.total_instrs
	    
	    if cfg.arch.type == 'elf32-msp430':
	    
	        vul_mem_func_bounds = ("","")
	        for func_addr in asm_funcs.keys():
	            func = asm_funcs[func_addr]
	            if int(func.start_addr, 16) <= int(expl_instr_addr, 16) <= int(func.end_addr, 16):
	                vul_mem_func_bounds = (func.start_addr, func.end_addr)
	    
	        pg = generate_patch_MSP430(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx_mem_instr, vul_mem_func_bounds)

	        translated_cflog = translate_cflog_MSP430(pg, cflog, func_start_cflog_idx, offending_cflog_index, cfg.arch)
	    
	        f = open("translated.cflog", "w")
	        for log_node in translated_cflog:
	            f.write(f"{log_node.src_addr[2:]}:{log_node.dest_addr[2:]}\n")
	            if log_node.loop_count != None:
	                f.write(f'0000:{log_node.loop_count}\n')
	        f.close()

	        print('New targets: ')
	        for addr in pg.new_targets:
	            print(addr)

	        patched_cfg = build_patched_cfg(translated_cflog, cfg, func_start_cflog_idx, offending_cflog_index, pg)

	        node_addr, instr_addr, _, _, emulator = locate_exploit(patched_cfg, translated_cflog, func_start_cflog_idx, offending_cflog_index, current_node.type, None, pg.new_targets)
	        mem_accesses = emulator.mem_accesses
	        emul_instrs = emulator.total_instrs

	    else: #arm         
	        pg = generate_patch_ARM(cfg, node_addr, expl_instr_addr, loopcount, exp_func, cflog, cflog_idx_mem_instr, emulator)

	        translated_cflog = translate_cflog_ARM(pg, cflog, func_start_cflog_idx, offending_cflog_index, cfg.arch)	        

	        f = open("translated.cflog", "w")
	        for log_node in translated_cflog:
	            f.write(f"{log_node.dest_addr[2:]}\n")
	            if log_node.loop_count != None:
	                f.write(f'{log_node.loop_count}\n')
	        f.close()

	        print('New targets: ')
	        for addr in pg.new_targets:
	            print(addr)

	        patched_cfg = build_patched_cfg(translated_cflog, cfg, func_start_cflog_idx, offending_cflog_index, pg)
	        node_addr, instr_addr, _, _, emulator = locate_exploit(patched_cfg, translated_cflog, func_start_cflog_idx, offending_cflog_index, current_node.type, None, pg.new_targets)
	        mem_accesses = emulator.mem_accesses
	        emul_instrs = emulator.total_instrs
	#'''   

if __name__ == '__main__':
	main()