import sys
import os
import asyncio
from asyncio import TimeoutError
from asyncio.subprocess import PIPE, STDOUT

async def run_cmd_async(cmd, cmd_msg, timeout=None, cwd=None):
    cmd_str = ' '.join([str(v) for v in cmd])
    print('** Running %s -- executing: %s' % (cmd_msg, cmd_str))
    if cwd is not None:
        print('** where CWD=(%s)...' % cwd)
    p = await asyncio.create_subprocess_exec(*cmd, cwd=cwd,
            stdout=PIPE, stderr=STDOUT)

    # Read line (sequence of bytes ending with b'\n') asynchronously
    while True:
        try:
            line = await asyncio.wait_for(p.stdout.readline(), timeout)
        except TimeoutError:
            pass
        else:
            if not line: # EOF
                break
            else:
                os.write(sys.stdout.fileno(), line)
                continue # While some criterium is satisfied
        p.kill() # Timeout or some criterion is not satisfied
        break
    return await p.wait()

def run_cmd(cmd, cmd_msg, timeout=None, cwd=None):
    # Wait for the process to exit
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop() # For subprocess' pipes on Windows
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()

    # Check the return code and either True (on success) or False (on failure)
    returncode = loop.run_until_complete(run_cmd_async(cmd, cmd_msg,
        timeout=timeout, cwd=cwd))
    if returncode != 0:
        print('ERROR: Unable to run %s [return_code=%d]' %
                (cmd_msg, returncode), file=sys.stderr)
        return False
    return True
