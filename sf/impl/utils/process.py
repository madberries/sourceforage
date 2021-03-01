import asyncio
import os
import subprocess
import sys

if sys.platform == "win32":
    from asyncio import ProactorEventLoop

from asyncio import TimeoutError
from asyncio import create_subprocess_exec, get_event_loop, set_event_loop, \
                    wait_for
from subprocess import Popen, run

from .logging import EXEC_COLOR

async def run_cmd_async(cmd, cmd_msg, log, timeout=None, cwd=None):
    cmd_str = ' '.join([str(v) for v in cmd])
    log.log('** Running %s -- executing: %s' % (cmd_msg, cmd_str),
            text_color=EXEC_COLOR)
    if cwd is not None:
        log.log('** where CWD=(%s)...' % cwd, text_color=EXEC_COLOR)
    p = await create_subprocess_exec(*cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

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

def run_cmd(cmd, cmd_msg, log, timeout=None, cwd=None):
    # Wait for the process to exit
    if sys.platform == "win32":
        loop = ProactorEventLoop() # For subprocess' pipes on Windows
        set_event_loop(loop)
    else:
        loop = get_event_loop()

    # Check the return code and either True (on success) or False (on failure)
    returncode = loop.run_until_complete(run_cmd_async(cmd, cmd_msg, log,
        timeout=timeout, cwd=cwd))
    if returncode != 0:
        log.error(f"ERROR: Unable to run {cmd_msg} [return_code={returncode}]")
        return False
    return True

def stop_docker(container_id, image_name, log):
    log.debug('Stopping docker container (%s) of image \'%s\'... ' %
              (container_id, image_name))
    run(['docker', 'stop', container_id], stdout=subprocess.DEVNULL)
    log.debug(f"Successfully docker container({container_id})")

def get_running_dockers(name=None):
    running_dockers = []
    cmd = ['docker', 'container', 'ls']
    if name is not None:
        cmd = cmd + ['-f', 'ancestor=' + name]
    out, _ = Popen(cmd, stdout=subprocess.PIPE).communicate()
    out = out.splitlines()[1:]  # grab only the relevant lines
    for line in out:
        split_line = line.decode('utf-8').split()
        running_dockers.append(split_line[0])
    return running_dockers
