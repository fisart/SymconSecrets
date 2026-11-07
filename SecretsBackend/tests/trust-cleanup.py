"""Inject partial trust-fixture failures as an unprivileged user, without touching module code."""
import os, pathlib, subprocess, tempfile, sys
root=pathlib.Path(__file__).resolve().parents[2]
php=sys.argv[1] if len(sys.argv)>1 else 'php'
if os.name!='posix':
 print('SKIP unprivileged cleanup injection: POSIX user isolation unavailable')
 sys.exit(0)
with tempfile.TemporaryDirectory(prefix='sec-cleanup-test-') as folder:
 parent=pathlib.Path(folder);parent.chmod(0o755)
 sentinel=parent/'outside-sentinel';sentinel.write_text('PRESERVE');sentinel.chmod(0o644)
 broken=parent/'broken.pem';broken.write_text('invalid certificate');broken.chmod(0o644)
 for case in ['missing','corrupt','after-directory']:
  temp=parent/case;temp.mkdir(mode=0o777);temp.chmod(0o777)
  env=dict(os.environ,TMPDIR=str(temp))
  env['SECB_TEST_CA_BUNDLE']=str(parent/'missing.pem') if case=='missing' else str(broken) if case=='corrupt' else str(root/'SecretsBackend/certificates/mozilla-ca.pem')
  if case=='after-directory': env['SECB_TEST_TRUST_FAIL_AFTER_DIRECTORY']='1'
  kwargs={'user':'nobody'} if os.geteuid()==0 else {}
  try:
   result=subprocess.run([php,str(root/'SecretsBackend/tests/native-trust.php')],env=env,text=True,capture_output=True,**kwargs)
  except OSError:
   print('NOTE host cannot create an unprivileged subprocess; using isolated current-user failure injection')
   result=subprocess.run([php,str(root/'SecretsBackend/tests/native-trust.php')],env=env,text=True,capture_output=True)
  assert result.returncode!=0,case+' did not fail'
  assert 'Undefined variable' not in result.stderr+result.stdout and 'unlink(' not in result.stderr+result.stdout,case+' unsafe cleanup attempt'
  assert sentinel.read_text()=='PRESERVE' and not list(temp.iterdir()),case+' cleanup escaped or left owned files'
print('PASS isolated cleanup: missing/corrupt bundles and failure after directory creation preserve outside sentinel and clean only owned trees')
