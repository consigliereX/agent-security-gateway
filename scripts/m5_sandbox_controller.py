"""Real OMP process trial INSIDE M4 Bubblewrap, driven by a local deterministic model.

The controller's own stdin/stdout is exclusively MCP JSON lines to the trusted
host gateway. A Unix-socket relay lets the real OMP process request those same
MCP tools. The mock model resides in the sandbox (no host model/API access).
"""
from __future__ import annotations
import json
import re
import os
import socket
import sys
import time
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MCP_SOCKET = '/tmp/asg-m5-mcp.sock'
HTTP_PORT = 18552
MARKER = 'ASG_M5_AGENT_ONLY'


def transmit_mcp(sock: socket.socket, errors: list[str]) -> None:
    try:
        with sock:
            with sock.makefile('rb') as reader:
                while True:
                    line = reader.readline(131074)
                    if not line:
                        return
                    if len(line) > 131073 or not line.endswith(b'\n'):
                        raise ValueError('invalid MCP request frame')
                    message = json.loads(line)
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                    if 'id' in message:
                        answer = sys.stdin.buffer.readline(131074)
                        if not answer or len(answer) > 131073 or not answer.endswith(b'\n'):
                            raise ValueError('invalid MCP host reply')
                        if json.loads(answer).get('id') != message['id']:
                            raise ValueError('MCP request/reply id mismatch')
                        sock.sendall(answer)
    except Exception as exc:
        errors.append(exc.__class__.__name__)


class ModelState:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.tool_names = []
        self.scripted = []
        self.errors = []


STATE = ModelState()


class MockModel(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass

    def _send(self, status: int, blob: bytes, content_type: str = 'application/json') -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(blob)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(blob)

    def do_GET(self):
        if self.path != '/v1/models':
            return self._send(404, b'{}')
        self._send(200, json.dumps({'object':'list','data':[{'id':'probe','object':'model'}]}).encode())

    def do_POST(self):
        if self.path != '/v1/chat/completions':
            return self._send(404, b'{}')
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if length < 1 or length > 1048576:
                raise ValueError('bad content length')
            payload = json.loads(self.rfile.read(length))
            offered = [t.get('function',{}).get('name','') for t in payload.get('tools',[]) if isinstance(t,dict)]
            with STATE.lock:
                STATE.calls += 1
                step = STATE.calls
                STATE.tool_names = offered
            if step == 1:
                # Intentionally ask real OMP's shell to modify its read-only work mount.
                chosen = next((x for x in offered if x == 'bash'), None)
                arguments = {'command': "printf 'BYPASS' > /work/bypass-target.txt"}
            elif step == 2:
                # Preferred: OMP exposes MCP tools natively via tools.xdev=false.
                chosen = next((x for x in offered if 'asg_write_file' in x), None)
                arguments = {'path':'m5-mediated.txt','content': MARKER}
                # Compatibility: OMP may mount MCP as an xd:// device instead.
                # Discover device names through the actual OMP read tool.
                if not chosen and 'read' in offered:
                    chosen = 'read'
                    arguments = {'path':'xd://'}
            elif step == 3 and len(STATE.scripted) >= 2 and STATE.scripted[1]['tool'] == 'read':
                # Only use a device name returned by the real read(xd://) tool.
                history = json.dumps(payload.get('messages',[]), ensure_ascii=False)
                matches = re.findall(r'xd://[A-Za-z0-9_./-]*asg_write_file', history)
                chosen = 'write' if matches and 'write' in offered else None
                arguments = {'path':matches[-1], 'content':json.dumps({'path':'m5-mediated.txt','content':MARKER})} if chosen else {}
            else:
                chosen = None
                arguments = {}
            with STATE.lock:
                STATE.scripted.append({'step':step,'tool':chosen or '', 'offered_count':len(offered)})
            if chosen:
                message = {'role':'assistant','content':None,'tool_calls':[{'id':f'call_m5_{step}', 'type':'function','function':{'name':chosen,'arguments':json.dumps(arguments)}}]}
                finish = 'tool_calls'
            else:
                message = {'role':'assistant','content':'ASG_M5_PROBE_FINISHED','tool_calls':None}
                finish = 'stop'
            if payload.get('stream'):
                fragments = []
                if chosen:
                    fragments.append({'role':'assistant','tool_calls':[{'index':0,'id':f'call_m5_{step}','type':'function','function':{'name':chosen,'arguments':json.dumps(arguments)}}]})
                else:
                    fragments.append({'role':'assistant','content':'ASG_M5_PROBE_FINISHED'})
                out = []
                for delta in fragments:
                    frame = {'id':f'chatcmpl-m5-{step}', 'object':'chat.completion.chunk', 'created':1794250000,
                             'model':'probe', 'choices':[{'index':0, 'delta':delta, 'finish_reason':None}]}
                    out.append('data: '+json.dumps(frame,separators=(',',':'))+'\n\n')
                frame = {'id':f'chatcmpl-m5-{step}', 'object':'chat.completion.chunk', 'created':1794250000,
                         'model':'probe', 'choices':[{'index':0, 'delta':{}, 'finish_reason':finish}],
                         'usage':{'prompt_tokens':50,'completion_tokens':12,'total_tokens':62}}
                out.append('data: '+json.dumps(frame,separators=(',',':'))+'\n\n')
                out.append('data: [DONE]\n\n')
                return self._send(200, ''.join(out).encode(), 'text/event-stream')
            frame = {'id':f'chatcmpl-m5-{step}', 'object':'chat.completion', 'created':1794250000,
                     'model':'probe', 'choices':[{'index':0,'message':message,'finish_reason':finish}],
                     'usage':{'prompt_tokens':50,'completion_tokens':12,'total_tokens':62}}
            self._send(200, json.dumps(frame).encode())
        except Exception as exc:
            STATE.errors.append(type(exc).__name__)
            self._send(400, b'{}')



def _decode_capture(value) -> str:
    """Bounded UTF-8-safe diagnostic text, including TimeoutExpired bytes."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value[-8192:].decode('utf-8', errors='replace')
    return str(value)[-8192:]




def run_headless_omp(command, env, *, cwd='/work', timeout=70):
    """Separate OMP prompt stdin from the controller's live MCP stdio pipe.

    OMP 18.x reads non-TTY stdin to EOF while preparing the initial prompt.
    If the child inherits the controller's broker pipe, no EOF is delivered
    before the MCP session ends, causing a permanent readPipedInput stall.
    The controller still owns stdin/stdout for the MCP bridge; only the OMP
    subprocess is attached to the sandbox's /dev/null.
    """
    return subprocess.run(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout)


def install_profile() -> None:
    conf = Path('/tmp/m5-omp-agent')
    conf.mkdir(mode=0o700)
    (conf / 'models.yml').write_text('''providers:\n  asg-m5:\n    baseUrl: http://127.0.0.1:18552/v1\n    auth: none\n    api: openai-completions\n    models:\n      - id: probe\n        name: M5 deterministic local test\n        contextWindow: 16384\n        maxTokens: 512\n''')
    (conf / 'config.yml').write_text('tools:\n  xdev: false\n')
    (conf / 'mcp.json').write_text(json.dumps({'mcpServers': {'asg-m5': {
        'type':'stdio','command':'/usr/bin/python3','args':['/work/m5_mcp_relay.py']}}}))


def main() -> int:
    install_profile()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(MCP_SOCKET)
    listener.listen(1)
    listener.settimeout(85)
    errors = []
    relay_done = threading.Event()
    mcp_connected = threading.Event()
    def serve_mcp():
        try:
            conn, _ = listener.accept()
            mcp_connected.set()
            transmit_mcp(conn, errors)
        except Exception as exc:
            errors.append('mcp:'+type(exc).__name__)
        finally:
            relay_done.set()
    relay_thread = threading.Thread(target=serve_mcp, daemon=True)
    relay_thread.start()
    mock = ThreadingHTTPServer(('127.0.0.1', HTTP_PORT), MockModel)
    mock_thread = threading.Thread(target=mock.serve_forever,daemon=True)
    mock_thread.start()
    env = {'PATH':'/usr/bin:/bin:/work','HOME':'/tmp','TMPDIR':'/tmp',
           'LANG':'C.UTF-8','PI_CODING_AGENT_DIR':'/tmp/m5-omp-agent','NO_COLOR':'1',
           'PI_NO_TITLE':'1','OMP_AUTO_UPDATE':'0',
           'PI_NATIVES_DIR':'/opt/asg-omp-natives'}
    entry = ['/work/omp-executable']
    if Path('/work/omp-runtime').exists():
        entry = ['/work/omp-runtime','/work/omp-executable']
    if Path('/work/omp-launch.json').exists():
        entry = json.loads(Path('/work/omp-launch.json').read_text())
    command = [*entry,'-p','--no-session','--no-extensions','--no-skills',
               '--no-rules','--no-context-files','--no-pty','--approval-mode','yolo',
               '--model','asg-m5/probe','--max-time','60s', '--mode','json',
               'M5 security validation: follow the deterministic tool request.']
    # Keep the MCP accept budget longer than the agent run budget. Previously
    # both expired at 40 s, obscuring a slow OMP bootstrap as an MCP timeout.
    # Capture output even when the actual executable times out. subprocess.run
    # raises TimeoutExpired with *bytes* (even under text=True).
    agent_timed_out = False
    try:
        proc = run_headless_omp(command, env, cwd='/work', timeout=70)
    except subprocess.TimeoutExpired as exc:
        agent_timed_out = True
        proc = subprocess.CompletedProcess(command, 124,
                                           _decode_capture(exc.stdout),
                                           _decode_capture(exc.stderr))
    finally:
        mock.shutdown()
        mock.server_close()
        listener.close()
    observed = {
        'actual_agent_process':'omp', 'model_type':'deterministic_mock_inside_namespace',
        'omp_returncode':proc.returncode,'omp_timed_out':agent_timed_out,
        'mcp_client_connected':mcp_connected.is_set(),
        'model_requests':STATE.calls,'scripted_tool_calls':STATE.scripted,
        'relay_errors':errors,'model_errors':STATE.errors,
        'agent_stdout_tail':(proc.stdout[-2400:] if proc else ''),
        'agent_stderr_tail':(proc.stderr[-2400:] if proc else ''),
        'direct_write_modified':Path('/work/bypass-target.txt').read_text() != 'ORIGINAL',
    }
    # No host file was granted directly: only the trusted host MCP broker can
    # change /work/m5-mediated.txt. The host publisher validates its contents.
    mediated_route = (len(STATE.scripted) >= 2 and
                      ('asg_write_file' in STATE.scripted[1]['tool'] or
                       (len(STATE.scripted) >= 3 and STATE.scripted[1]['tool'] == 'read'
                        and STATE.scripted[2]['tool'] == 'write')))
    checks = {
        'omp_exit_zero': proc is not None and proc.returncode == 0,
        'model_at_least_three_requests': STATE.calls >= 3,
        'first_tool_is_bash': bool(STATE.scripted) and STATE.scripted[0]['tool'] == 'bash',
        'mediated_route_offered': mediated_route,
        'relay_clean': not errors and mcp_connected.is_set(),
        'model_stub_clean': not STATE.errors,
        'omp_not_timed_out': not agent_timed_out,
        'direct_write_blocked': not observed['direct_write_modified'],
    }
    observed['checks'] = checks
    # stderr is a SEPARATE diagnostic channel; stdout remains exclusively MCP.
    # The host, not this untrusted JSON, verifies the on-disk effects and audit.
    print('ASG_M5_DIAG=' + json.dumps(observed, separators=(',', ':')),
          file=sys.stderr, flush=True)
    return 0 if all(checks.values()) else 3


if __name__ == "__main__":
    raise SystemExit(main())
