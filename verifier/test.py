import multiprocessing
import sys
from MSProbe.assemble import *
'''
def init_process(counter, lock):
    # Initialize the process ID counter and the lock
    global process_counter
    process_counter = counter
    global print_lock
    print_lock = lock

def traverse_path(args):
    cfg, path = args
    global process_counter
    global print_lock

    # Get the current process ID
    process_id = process_counter.value
    
    # Increment the process ID counter for the next process
    with print_lock:
        process_counter.value += 1
    
    # Function to traverse a single path in the CFG
    # Implement your path traversal logic here

    # Example logic: Print the progress counter on a new line for the current process
    total = len(path)
    with print_lock:
        sys.stdout.write(f"Process {process_id}: {total}/{total}\n")
        sys.stdout.flush()
    
    # Example logic: Return the path along with the process ID
    return f"Process {process_id}: Traversing path: {path}"
'''

if __name__ == "__main__":
    asmMain("test.asm", None, False)
    '''
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

    # Create a multiprocessing manager to manage the process ID counter and the lock
    manager = multiprocessing.Manager()
    process_counter = manager.Value('i', 1)  # Start process IDs from 1
    print_lock = multiprocessing.Lock()

    # Create a multiprocessing Pool with the desired number of processes
    num_processes = multiprocessing.cpu_count()  # Use the number of CPU cores
    pool = multiprocessing.Pool(processes=num_processes, initializer=init_process, initargs=(process_counter, print_lock))

    # Map the traverse_path function to the pool of processes and pass each path as an argument
    results = pool.map(traverse_path, [(cfg, path) for path in paths])

    # Close the pool to release resources
    pool.close()
    pool.join()

    # Merge all outputs into a list
    all_outputs = results

    print("\n\nAll outputs:")
    for output in all_outputs:
        print(output)
    '''