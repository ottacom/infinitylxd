import sys, time
import multiprocessing
DELAY = 0.1
DISPLAY = [ '|', '/', '-', '\\' ]
def spinner_func(before='', after=''):
    write, flush = sys.stdout.write, sys.stdout.flush
    pos = -1
    while True:
        pos = (pos + 1) % len(DISPLAY)
        msg = before + DISPLAY[pos] + after
        write(msg); flush()
        write('\x08' * len(msg))
        time.sleep(DELAY)
def long_computation():
    # emulate a long computation
    time.sleep(2)
