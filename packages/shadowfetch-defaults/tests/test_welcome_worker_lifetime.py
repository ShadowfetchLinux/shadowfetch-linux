"""Exercise real Qt thread completion, including a delayed return from run()."""
import ast,os,pathlib,signal,subprocess,sys,threading,time,unittest
try:
 from PyQt6.QtCore import QCoreApplication,QThread,pyqtSignal,pyqtSlot
except ImportError:
 raise unittest.SkipTest("PyQt6 is required for real worker lifetime tests")
SOURCE=pathlib.Path(__file__).resolve().parents[3]/'packages/shadowfetch-welcome/src/shadowfetch-welcome'
nodes=[n for n in ast.parse(SOURCE.read_text()).body if isinstance(n,ast.ClassDef) and n.name in ('CommandWorker','StreamingCommandWorker')]
namespace=dict(globals(),strip_terminal_escapes=lambda s:s)
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),namespace)
class LifetimeTests(unittest.TestCase):
 def test_completion_only_after_thread_termination(self):
  app=QCoreApplication.instance() or QCoreApplication([])
  for name in ['CommandWorker','StreamingCommandWorker']:
   for exit_code in [0,7]:
    with self.subTest(worker=name,exit_code=exit_code):
     base=namespace[name]
     class DelayedReturn(base):
      def run(self):
       super().run()
       time.sleep(.08)
     command=[sys.executable,'-c','raise SystemExit('+str(exit_code)+')']
     worker=DelayedReturn([command] if name=='CommandWorker' else command)
     results=[]
     event=getattr(worker,'completed',worker.finished)
     event.connect(lambda code,w=worker:results.append((code,w.isRunning())))
     worker.start();deadline=time.monotonic()+5
     while (not results or worker.isRunning()) and time.monotonic()<deadline:
      app.processEvents();time.sleep(.001)
     worker.wait(1000);app.processEvents()
     self.assertEqual([(exit_code,False)],results)
if __name__=='__main__':unittest.main()
