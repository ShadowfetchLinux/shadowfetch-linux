#!/usr/bin/env python3
"""Installed Linux Mission Control acceptance; no mock model or fake results."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import wave

sys.path.insert(0, '/usr/lib/shadowfetch/missions')
import sf_missions as engine


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()==0:
        parser.error('Run as the desktop QA user')
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    workspace=Path.home()/'Workspaces'/('qa-engine-'+str(int(time.time())))
    workspace.mkdir(parents=True)
    (workspace/'invalid-media.txt').write_text('This is not media.\n')
    (workspace/'notes.md').write_text('Release QA is local.\n')
    with wave.open(str(workspace/'tone.wav'),'wb') as audio:
        audio.setparams((1,2,48000,0,'NONE','not compressed'))
        audio.writeframes(b'\0\0'*48000)
    env={**os.environ,'SHADOWFETCH_MISSIONS_STATE':str(output/'controller')}
    os.environ['SHADOWFETCH_MISSIONS_STATE']=env['SHADOWFETCH_MISSIONS_STATE']
    checks=[]
    sequence=0
    def record(name,condition,detail=''):
        row={'check':name,'pass':bool(condition),'detail':detail}
        checks.append(row)
        print(json.dumps(row),flush=True)
        if not condition:
            raise AssertionError(name+': '+str(detail))
    def cli(*values,expected=0):
        nonlocal sequence
        sequence+=1
        result=subprocess.run(['shadowfetch-missions','--json',*map(str,values)],capture_output=True,text=True,env=env,timeout=60)
        (output/f'command-{sequence:03d}.json').write_text(json.dumps({'args':values,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr},indent=2))
        if result.returncode!=expected:
            raise AssertionError(f'Unexpected CLI exit {result.returncode}: {result.stdout} {result.stderr}')
        return json.loads(result.stdout)
    def create(kind='media',input='tone.wav',**kwargs):
        values=['create','--kind',kind,'--workspace',workspace.name,'--title','Installed engine QA','--prompt','Validate the selected input','--network','none','--input',input]
        return cli(*values,**kwargs)
    try:
        first=create()
        record('fresh CLI sees persisted queue',cli('show',first['id'])['state']=='queued')
        record('queue list returns created mission',any(item['id']==first['id'] for item in cli('list')))
        record('events expose queued transition',cli('events',first['id'])[0]['event']=='queued')
        cli('cancel',first['id'])
        record('queued cancel persists',cli('show',first['id'])['state']=='cancelled')
        cli('retry',first['id'])
        result=cli('run',first['id'])
        record('explicit retry executes real media',result['state']=='waiting-review',result.get('error'))
        receipt=json.loads(Path(result['receipt']).read_text())
        record('receipt bytes and hashes match',all(Path(row['path']).stat().st_size==row['bytes'] and hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()==row['sha256'] for row in receipt['artifacts']))
        record('diff records actual output', 'mission-output' in cli('diff',first['id'])['diff'])
        (workspace/'manual-newer.txt').write_text('preserve this file')
        refusal=cli('review',first['id'],'--decision','undo',expected=1)
        record('undo refuses newer manual files','changed after' in refusal['error'] and (workspace/'manual-newer.txt').is_file())
        (workspace/'manual-newer.txt').unlink()
        record('undo restores after conflict removed',cli('review',first['id'],'--decision','undo')['state']=='undone')
        record('undo removes generated artifacts',not (workspace/'mission-output').exists())
        bad=create(input='invalid-media.txt')
        failed=cli('run',bad['id'],expected=1)
        record('invalid media fails with real receipt',failed['state']=='failed' and Path(failed['receipt']).is_file(),failed.get('error'))
        record('failure never claims success',json.loads(Path(failed['receipt']).read_text())['state']=='failed')
        cli('retry',bad['id'])
        record('bounded retry increments attempt',cli('run',bad['id'],expected=1)['attempt']==2)
        for relative in ('../outside','/etc/passwd'):
            refused=cli('create','--kind','report','--workspace',workspace.name,'--title','Scope check','--prompt','test','--input',relative,expected=1)
            record('scope refuses '+relative,'error' in refused)
        outside=output/'outside.txt'
        outside.write_text('private sentinel')
        (workspace/'escape.txt').symlink_to(outside)
        refused=create(kind='report',input='escape.txt',expected=1)
        record('symlink input escapes refused','Symbolic links' in refused['error'])
        (workspace/'escape.txt').unlink()
        # Use installed Executor against an actual sleeping sandboxed process.
        # This measures cancellation of execution, not a mocked successful workflow.
        running=create(kind='report',input='notes.md')
        store=engine.Store()
        store.update(running['id'],state='running')
        executor=engine.Executor(store,store.get(running['id']))
        marker=workspace/'cancel-should-not-write.txt'
        script="import time,pathlib;time.sleep(10);pathlib.Path("+repr(str(marker))+ ").write_text('bad')"
        timer=threading.Timer(.75,lambda:store.cancel(running['id']))
        timer.start()
        cancelled=False
        start=time.monotonic()
        try:
            executor.run_process(['python3','-c',script],'real-running-cancel')
        except engine.Cancelled:
            cancelled=True
        finally:
            timer.join()
        elapsed=time.monotonic()-start
        record('running sandbox process cancellation bounded',cancelled and elapsed<5 and not marker.exists(),{'seconds':elapsed})
        with store.lock():
            store.recover()
        recovered=store.get(running['id'])
        record('interrupted state requires explicit review',recovered['state']=='failed' and 'no automatic replay' in recovered['error'])
        # Parallel API writers use separate installed CLI processes/connections.
        def parallel(index):
            args=['shadowfetch-missions','--json','create','--kind','report','--workspace',workspace.name,'--title','Concurrent '+str(index),'--prompt','Summarize','--input','notes.md']
            result=subprocess.run(args,capture_output=True,text=True,env=env,timeout=30)
            if result.returncode: raise AssertionError(result.stdout)
            return json.loads(result.stdout)['id']
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            ids=list(pool.map(parallel,range(24)))
        known={row['id'] for row in cli('list')}
        record('24 concurrent CLI writes persist without loss',len(set(ids))==24 and set(ids)<=known)
        outcome={'status':'PASS','checks':checks,'workspace':str(workspace),'controller':env['SHADOWFETCH_MISSIONS_STATE'],'model_inference':False,'mocked_execution':False}
    except Exception as exc:
        outcome={'status':'FAIL','checks':checks,'error':str(exc),'workspace':str(workspace),'controller':env['SHADOWFETCH_MISSIONS_STATE']}
    (output/'result.json').write_text(json.dumps(outcome,indent=2)+'\n')
    print(json.dumps(outcome),flush=True)
    return 0 if outcome['status']=='PASS' else 1

if __name__=='__main__': raise SystemExit(main())
