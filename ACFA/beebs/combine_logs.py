import argparse

def arg_parser():
    '''
    Parse the arguments of the program
    Return:
        object containing the arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar='N', type=str, default='.',
                        help='base directory of cflogs')

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = arg_parser()

    # Set directories
    print(f"Writing to {args.dir}")
    BASE_DIR = args.dir
    BASE_CFLOG_DIR = BASE_DIR+"/logs/"

    #--------------------------------------------------
    # Read baseline cflogs into one list
    #--------------------------------------------------
    print("----------")
    print("Processing unoptimized logs")
    baseline_cflog = []
    more_cflogs = True
    log_num = 1
    er_exit = ''
    er_enter = ''
    while more_cflogs:
        try:
            file_path = BASE_CFLOG_DIR+str(log_num)+".cflog"
            f = open(file_path)
            print("\tProcessing \'"+file_path+"\'")
            for x in f:
                elt = x.replace("\n","")
                if elt[5:] == "a000":
                    er_exit = elt[:4]
                    # print(f"er_exit: {er_exit}")
                elif elt[:4] == "dffe":
                    er_enter = elt[5:]
                    # print(f"er_exit: {er_enter}")
                    if er_enter != er_exit and er_enter != 'e040':
                        # print(f"appending: {er_exit+':'+er_enter}")
                        baseline_cflog.append(er_exit+":"+er_enter) # need to reconstruct this way when triggered on a branch
                else:
                    baseline_cflog.append(elt)
            log_num += 1
        except FileNotFoundError:
            print(f"Done reading {log_num} cflogs")
            more_cflogs = False

    #--------------------------------------------------
    # Write lists to files
    #--------------------------------------------------
    print(f"Writing to {BASE_DIR+'/combined.cflog'}")
    f = open(BASE_DIR+'/combined.cflog', 'w')
    for line in baseline_cflog:
        f.write(f"{line}\n")
    f.close()
    print(f"cflog bytes: {4*len(baseline_cflog)}")