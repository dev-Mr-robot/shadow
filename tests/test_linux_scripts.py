import os
import shutil
import subprocess
import sys
from pathlib import Path
import pytest

pytestmark=pytest.mark.skipif(sys.platform!='linux',reason='Linux/Bash lifecycle checks')
ROOT=Path(__file__).resolve().parents[1]

def test_shell_scripts_parse_and_installer_help():
    scripts=[str(ROOT/name) for name in ['install.sh','run.sh','upgrade.sh','uninstall.sh']]
    subprocess.run(['bash','-n',*scripts],check=True,capture_output=True,timeout=5)
    result=subprocess.run(['bash',str(ROOT/'install.sh'),'--help'],capture_output=True,text=True,timeout=5)
    assert result.returncode==0 and '--no-link' in result.stdout

def test_uninstall_preserves_user_data_and_unrelated_launcher(tmp_path):
    checkout=tmp_path/'checkout';checkout.mkdir();shutil.copyfile(ROOT/'uninstall.sh',checkout/'uninstall.sh')
    venv=checkout/'.venv';venv.mkdir();(venv/'generated').write_text('generated dependency')
    data=tmp_path/'data';data.mkdir();database=data/'research.sqlite3';database.write_text('preserve evidence')
    config=tmp_path/'config.json';config.write_text('{}')
    bindir=tmp_path/'bin';bindir.mkdir();launcher=bindir/'shadow';launcher.write_text('unrelated launcher')
    env={**os.environ,'SHADOW_BIN_DIR':str(bindir),'SHADOW_DATA_DIR':str(data)}
    result=subprocess.run(['bash',str(checkout/'uninstall.sh')],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode==0,result.stderr
    assert not venv.exists() and database.read_text()=='preserve evidence' and config.exists()
    assert launcher.read_text()=='unrelated launcher'

def test_uninstall_refuses_symlink_environment(tmp_path):
    checkout=tmp_path/'checkout';checkout.mkdir();shutil.copyfile(ROOT/'uninstall.sh',checkout/'uninstall.sh')
    outside=tmp_path/'other-environment';outside.mkdir();(outside/'preserve').write_text('keep')
    (checkout/'.venv').symlink_to(outside,target_is_directory=True)
    result=subprocess.run(['bash',str(checkout/'uninstall.sh')],capture_output=True,text=True,timeout=5)
    assert result.returncode!=0 and (outside/'preserve').exists()
