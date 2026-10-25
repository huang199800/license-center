#!/usr/bin/env python3
"""Host deployment engine: Python standard library, Docker Engine + Compose v2+.

Shell entrypoints share this engine. It never sources a config as shell code, accepts
no plaintext credentials in argv, and does not forward raw subprocess stderr.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]


class OperationError(Exception):
    pass


def fail(code):
    raise OperationError(code)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name+'.'+secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=True, indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temp, path)


def protected(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or (os.name != 'nt' and path.stat().st_mode & 0o077):
        fail('CONFIG_OR_SECRET_REQUIRES_REGULAR_FILE_MODE_0600')
    if os.name != 'nt' and path.stat().st_uid not in [0, os.geteuid()]:
        fail('CONFIG_OR_SECRET_OWNER_INVALID')
    return path


def run(args, *, cwd=None, input=None, allow_failure=False, timeout=1800, env=None):
    clean_env = {k:v for k,v in os.environ.items() if k not in ['GIT_TRACE','GIT_CURL_VERBOSE','BASH_ENV','ENV','PYTHONPATH']}
    clean_env.update({'GIT_TERMINAL_PROMPT':'0','GCM_INTERACTIVE':'never'})
    if env:clean_env.update(env)
    result = subprocess.run([str(a) for a in args], cwd=cwd, input=input, text=True, capture_output=True, timeout=timeout, env=clean_env)
    if result.returncode and not allow_failure:
        # Never echo argv or tool output: they may contain secrets from external programs.
        fail('COMMAND_FAILED_'+Path(str(args[0])).name.upper())
    return result


def release(source=SOURCE):
    info = json.loads((Path(source)/'release.json').read_text())
    if not re.fullmatch(r'\d+\.\d+\.\d+', info['version']) or info['schema'] != 1:
        fail('RELEASE_METADATA_UNSUPPORTED')
    return info


def commit_of(source=SOURCE):
    # This exact directory already supplies the explicitly executed installer.
    # Do not add a global wildcard trust exception or execute a repository fsmonitor.
    git=['git','-c','safe.directory='+str(Path(source).resolve()),'-c','core.fsmonitor=false']
    result = run([*git,'rev-parse','HEAD'], cwd=source, allow_failure=True)
    value = result.stdout.strip() if result.returncode == 0 else ''
    if value:
        status=run([*git,'status','--porcelain'],cwd=source).stdout.strip()
        if status:fail('SOURCE_HAS_UNCOMMITTED_CHANGES')
    marker = Path(source)/'.source-commit'
    if not value and marker.exists():value=marker.read_text().strip()
    if not re.fullmatch('[0-9a-f]{40}',value):fail('PINNED_GIT_COMMIT_REQUIRED')
    return value


def read_config(path):
    raw = json.loads(protected(path).read_text())
    allowed = {'repo','domain','issuer','admin_username','port','http_port','https_port','secret_dir',
               'backup_password_file','key_password_file','admin_password_file','git_token_file','ssh',
               'python_image','gateway_image','auto_install_docker'}
    if not isinstance(raw,dict) or raw.keys()-allowed:fail('CONFIG_UNKNOWN_KEYS')
    config = {'repo':'huang199800/license-center','domain':'','issuer':'urn:license-center:production','admin_username':'admin',
              'port':18080,'http_port':80,'https_port':443,'ssh':False,'auto_install_docker':False,**raw}
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',config['repo']):fail('REPO_MUST_BE_OWNER_SLASH_NAME')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',config['admin_username']):fail('ADMIN_USERNAME_INVALID')
    if not isinstance(config['issuer'],str) or not 1<=len(config['issuer'])<=200 or any(ord(c)<32 for c in config['issuer']):fail('ISSUER_INVALID')
    for key in ['port','http_port','https_port']:
        if type(config[key]) is not int or not 1024<=config[key]<=65535:
            if key != 'port' and config[key] in [80,443]:continue
            fail('PORT_INVALID')
    if config['domain']:
        if not isinstance(config['domain'],str) or not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',config['domain']):fail('DOMAIN_ASCII_FQDN_REQUIRED')
        try:ipaddress.ip_address(config['domain']);fail('DOMAIN_MUST_NOT_BE_IP')
        except ValueError:pass
        if '.' not in config['domain'] or '..' in config['domain']:fail('DOMAIN_ASCII_FQDN_REQUIRED')
    for key in ['python_image','gateway_image']:
        if key in config and not re.fullmatch(r'[a-z0-9./:_@-]+',config[key]):fail('IMAGE_REFERENCE_INVALID')
    for key in ['ssh','auto_install_docker']:
        if type(config[key]) is not bool:fail('BOOLEAN_CONFIG_REQUIRED')
    for key in ['secret_dir','backup_password_file','key_password_file','admin_password_file','git_token_file']:
        if key in config and (not isinstance(config[key],str) or not Path(config[key]).is_absolute()):fail('SECRET_PATH_MUST_BE_ABSOLUTE')
    return config


def host_check(root, require_docker=True, installing=False, config=None):
    if platform.system()!='Linux':fail('HOST_REQUIRES_LINUX_DEBIAN_OR_UBUNTU')
    if os.geteuid()!=0:fail('RUN_AS_ROOT_OR_SUDO')
    os_release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);os_release[k]=v.strip('"')
    supported={'debian':['12','13'],'ubuntu':['22.04','24.04','26.04']}
    if os_release.get('VERSION_ID') not in supported.get(os_release.get('ID'),[]):fail('OS_VERSION_NOT_TARGETED')
    if platform.machine() not in ['x86_64','aarch64']:fail('CPU_ARCH_NOT_TARGETED')
    root=Path(root).resolve()
    if root in [Path('/'),Path('/etc'),Path('/var'),Path('/opt'),Path('/usr'),Path('/home')]:fail('UNSAFE_DEPLOYMENT_ROOT')
    parent=root
    while not parent.exists():parent=parent.parent
    if shutil.disk_usage(parent).free<3*1024**3:fail('AT_LEAST_3_GIB_FREE_REQUIRED')
    if require_docker:
        if not shutil.which('docker'):fail('DOCKER_MISSING_USE_AUTO_INSTALL_DOCKER_OR_INSTALL_OFFICIALLY')
        run(['docker','info'],timeout=30);run(['docker','compose','version'],timeout=30)
        endpoint=os.environ.get('DOCKER_HOST') or json.loads(run(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}'],timeout=30).stdout)
        if not endpoint.startswith('unix://'):fail('LOCAL_DOCKER_ENGINE_REQUIRED_REMOTE_CONTEXT_UNSUPPORTED')
        security=run(['docker','info','--format','{{json .SecurityOptions}}'],timeout=30).stdout
        if 'rootless' in security:fail('ROOTLESS_DOCKER_UID_MAPPING_NOT_SUPPORTED')
        version=run(['docker','version','--format','{{.Server.Version}}'],timeout=30).stdout.strip()
        if not re.match(r'^\d+\.',version) or int(version.split('.')[0])<28:fail('DOCKER_ENGINE_28_OR_NEWER_REQUIRED')
    if installing and config:
        ports=[('127.0.0.1',config['port'])]
        if config['domain']:ports += [('0.0.0.0',config['http_port']),('0.0.0.0',config['https_port'])]
        for host,port in ports:
            with socket.socket() as sock:
                try:sock.bind((host,port))
                except OSError:fail('REQUESTED_PORT_IN_USE')
    return {'os':os_release['ID'],'version':os_release['VERSION_ID'],'arch':platform.machine()}


def docker_install(config):
    if shutil.which('docker'):
        run(['docker','info'],timeout=30)
        if run(['docker','compose','version'],allow_failure=True,timeout=30).returncode==0:return
        fail('EXISTING_DOCKER_NEEDS_COMPOSE_PLUGIN_NO_AUTOMATIC_REPLACEMENT')
    if not config['auto_install_docker']:fail('DOCKER_MISSING_SET_auto_install_docker_TRUE')
    # Dedicated, reviewable script uses Docker's signed Debian/Ubuntu APT repository.
    run(['bash',str(SOURCE/'scripts/docker-engine.sh')])


@contextlib.contextmanager
def lock(root):
    import fcntl
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (root/'.operation.lock').open('a') as f:
        try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:fail('ANOTHER_OPERATION_RUNNING')
        yield


class Deployment:
    def __init__(self,root):
        self.root=Path(root).resolve()
        self.config_path=self.root/'config/config.json'
        self.meta_path=self.root/'deployment.json'
        self.compose_path=self.root/'compose.generated.json'

    def config(self):return read_config(self.config_path)
    def meta(self):return json.loads(self.meta_path.read_text())
    def dc(self,*args,**kwargs):
        return run(['docker','compose','--project-name','lc-'+hashlib.sha256(str(self.root).encode()).hexdigest()[:10],
                    '--file',self.compose_path,*args],**kwargs)

    def helper(self,command,*args,config=None,mounts=None):
        config=config or self.config()
        base=['run','--rm','--no-deps','--user','0:0','--cap-add','SETUID','--cap-add','SETGID','--env','LC_DROP_UID=10001','--entrypoint','python']
        for key,target in [('backup_password_file','/run/secrets/backup'),('key_password_file','/run/secrets/key'),('admin_password_file','/run/secrets/admin')]:
            if config.get(key):
                path=protected(config[key]);base += ['--volume',f'{path}:{target}:ro']
        for source,target,mode in mounts or []:base += ['--volume',f'{Path(source).resolve()}:{target}:{mode}']
        return self.dc(*base,'center','-m','center.deployment',command,*args)

    def render(self,config,source,image,info):
        root=self.root
        services={'center':{
            'image':image,'restart':'unless-stopped','read_only':True,'user':'10001:10001',
            'environment':{'LC_DATA':'/state/data','LC_VAULT':'/state/keys/vault.json','LC_HOST':'0.0.0.0'},
            'ports':[f'127.0.0.1:{config["port"]}:8000'],
            'volumes':[f'{root/"state"}:/state',f'{root/"exchange"}:/exchange',f'{root/"config"}:/deployment:ro'],
            'tmpfs':['/tmp:size=128m,mode=1777'],'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
            'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'5'}}}}
        volumes={}
        if config['domain']:
            caddy_path=root/'config/Caddyfile'
            caddy_path.write_text(config['domain']+' {\n request_body {\n max_size 64KB\n }\n reverse_proxy center:8000\n header Strict-Transport-Security "max-age=31536000"\n}\n')
            os.chmod(caddy_path,0o644)
            services['gateway']={'image':config.get('gateway_image',info['gateway_image']),'restart':'unless-stopped',
                'ports':[f'{config["http_port"]}:80',f'{config["https_port"]}:443'],
                'volumes':[f'{caddy_path}:/etc/caddy/Caddyfile:ro','gateway-data:/data','gateway-config:/config'],
                'depends_on':{'center':{'condition':'service_healthy'}},
                'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'5'}}}
            volumes={'gateway-data':{},'gateway-config':{}}
        write_json(self.compose_path,{'services':services,'volumes':volumes})

    def build(self,source,config,commit):
        info=release(source)
        image='license-center-local:'+commit
        base=config.get('python_image',info['python_image'])
        run(['docker','pull',base])
        digests=json.loads(run(['docker','image','inspect',base,'--format','{{json .RepoDigests}}']).stdout)
        if not digests:fail('BASE_IMAGE_HAS_NO_IMMUTABLE_DIGEST')
        config['python_image']=digests[0]
        if config['domain']:
            gateway=config.get('gateway_image',info['gateway_image'])
            run(['docker','pull',gateway])
            config['gateway_image']=json.loads(run(['docker','image','inspect',gateway,'--format','{{json .RepoDigests}}']).stdout)[0]
        write_json(self.config_path,config)
        print('正在构建固定依赖及固定基础镜像的授权中心……',flush=True)
        run(['docker','build','--build-arg','PYTHON_IMAGE='+config['python_image'],'-t',image,str(source)])
        self.render(config,source,image,info)
        return image

    def permissions(self):
        # Only known state subtrees are touched; never chmod another project's directories.
        for name in ['state','state/data','state/keys','exchange']:
            path=self.root/name
            path.mkdir(parents=True,exist_ok=True,mode=0o700)
            os.chown(path,10001,10001);os.chmod(path,0o700)
        for directory in [self.root/'state/data',self.root/'state/keys']:
            for path in directory.iterdir():
                if path.is_file() and not path.is_symlink():os.chown(path,10001,10001);os.chmod(path,0o600)

    def wait(self,config=None):
        config=config or self.config()
        base=f'http://127.0.0.1:{config["port"]}'
        for attempt in range(90):
            try:
                with urllib.request.urlopen(base+'/health/ready',timeout=3) as r:ready=json.load(r)
                with urllib.request.urlopen(base+'/',timeout=3) as r:page=r.read(200000).decode()
                with urllib.request.urlopen(base+'/v1/public-keys',timeout=3) as r:keys=json.load(r)
                if ready['schema']!=1 or '管理员登录' not in page or not keys['keys']:fail('LIVE_HEALTH_CONTENT_INVALID')
                return {'api':'ready','admin':'reachable','database_schema':ready['schema'],'issuer':keys['issuer']}
            except (OSError,ValueError,KeyError):time.sleep(1)
        fail('HEALTH_CHECK_TIMEOUT')

    def diagnostics(self):
        health=self.wait()
        self.helper('selftest')
        if self.config()['domain']:
            try:
                with urllib.request.urlopen('https://'+self.config()['domain']+'/health/ready',timeout=8) as r:
                    if r.status!=200:fail('PUBLIC_HTTPS_HEALTH_FAILED')
                health['https']='verified'
            except OSError:health['https']='pending_dns_or_certificate_see_docs'
        return health

    def backup(self,output=None):
        config=self.config()
        target=Path(output).resolve() if output else self.root/'backups'/('backup-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(3)+'.lcb2')
        if target.exists():fail('BACKUP_TARGET_EXISTS')
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        staged=self.root/'exchange'/('backup-'+secrets.token_hex(12)+'.lcb2')
        self.helper('backup','--root','/state/data','--output','/exchange/'+staged.name,
                    '--config','/deployment/config.json','--metadata','/deployment/version.json',
                    '--password-file','/run/secrets/backup','--key-password-file','/run/secrets/key')
        fd,temp_path=tempfile.mkstemp(prefix='.lc-backup-',dir=target.parent)
        try:
            with os.fdopen(fd,'wb') as dest, staged.open('rb') as source:
                shutil.copyfileobj(source,dest);dest.flush();os.fsync(dest.fileno())
            # Link a complete file atomically without ever replacing an existing target.
            # Temp and target are on the same filesystem, including external backup disks.
            os.link(temp_path,target)
            staged.unlink()
        finally:
            Path(temp_path).unlink(missing_ok=True)
        digest=hashlib.sha256(target.read_bytes()).hexdigest()
        target.with_suffix(target.suffix+'.sha256').write_text(digest+'  '+target.name+'\n')
        return str(target)


def prepare_config(args,dep):
    if args.config:return read_config(args.config)
    if args.non_interactive:fail('NON_INTERACTIVE_REQUIRES_PROTECTED_CONFIG')
    domain=input('生产域名（无域名直接回车，仅绑定本机SSH隧道）: ').strip().lower()
    issuer=input('稳定签发者身份 [urn:license-center:production]: ').strip() or 'urn:license-center:production'
    auto=False
    if not shutil.which('docker'):auto=input('未安装Docker，是否通过Docker官方签名APT仓库安装？[y/N]: ').lower()=='y'
    temp=dep.root/'config/initial.json'
    write_json(temp,{'domain':domain,'issuer':issuer,'auto_install_docker':auto})
    return read_config(temp)


def create_secrets(dep,config):
    directory=Path(config.get('secret_dir','/etc/license-center-secrets/'+hashlib.sha256(str(dep.root).encode()).hexdigest()[:12]))
    if directory.resolve().is_relative_to(SOURCE) or directory.resolve().is_relative_to(dep.root):fail('SECRET_DIRECTORY_MUST_BE_OUTSIDE_SOURCE_AND_DEPLOYMENT_ROOT')
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name!='nt':os.chmod(directory,0o700)
    for key,name in [('admin_password_file','admin-password'),('backup_password_file','backup-password'),('key_password_file','key-password')]:
        if config.get(key):protected(config[key]);continue
        path=directory/name
        if path.exists():fail('SECRET_FILE_ALREADY_EXISTS_REFUSING_REUSE_FOR_NEW_INSTALL')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(secrets.token_urlsafe(36)+'\n')
        config[key]=str(path)
    for key in ['admin_password_file','backup_password_file','key_password_file']:
        if len(Path(config[key]).read_text().strip())<16:fail('INJECTED_SECRET_MUST_HAVE_AT_LEAST_16_CHARACTERS')
        if Path(config[key]).resolve().is_relative_to(SOURCE):fail('SECRET_FILE_MUST_BE_OUTSIDE_SOURCE')
    if Path(config['backup_password_file']).read_text().strip()==Path(config['key_password_file']).read_text().strip():fail('BACKUP_AND_KEY_PASSWORDS_MUST_DIFFER')
    return config


def record(dep,source,config,image,commit,previous=None):
    meta={'version':release(source)['version'],'commit':commit,'schema':1,'source':str(Path(source).resolve()),'image':image,
          'image_id':run(['docker','image','inspect',image,'--format','{{.Id}}']).stdout.strip(),
          'python_image':config.get('python_image'),'gateway_image':config.get('gateway_image'),
          'installed_at':int(time.time()),'previous':previous}
    write_json(dep.meta_path,meta);write_json(dep.root/'config/version.json',meta)


def summary(dep,health):
    config=dep.config()
    url='https://'+config['domain'] if config['domain'] else f'http://127.0.0.1:{config["port"]} (仅本机；使用SSH隧道)'
    print(json.dumps({'url':url,'health':health,'version':dep.meta()['version'],'commit':dep.meta()['commit'],
        'data':str(dep.root/'state/data'),'keys':str(dep.root/'state/keys'),
        'config':str(dep.config_path),'admin_password_file':config.get('admin_password_file'),
        'mfa_enrollment_file':str(dep.root/'exchange/admin-enrollment.json') if (dep.root/'exchange/admin-enrollment.json').exists() else None,
        'manage':str(Path(dep.meta()['source'])/'scripts/manage.sh')+' --root '+str(dep.root)},ensure_ascii=False,indent=2))


def install(args,dep):
    if dep.meta_path.exists():
        config=dep.config();host_check(dep.root)
        if dep.meta()['commit']!=commit_of():fail('EXISTING_DEPLOYMENT_DIFFERENT_VERSION_USE_UPDATE')
        dep.dc('up','-d');summary(dep,dep.diagnostics());return
    if (dep.root/'state/data/center.db').exists():fail('EXISTING_DATA_WITHOUT_MANIFEST_USE_RECOVERY_NOT_INIT')
    if dep.root.exists() and any(p.name not in ['.operation.lock','config','releases'] for p in dep.root.iterdir()):fail('INSTALL_TARGET_NOT_EMPTY_OR_OWNED')
    config=prepare_config(args,dep)
    host_check(dep.root,False,True,config);docker_install(config);host_check(dep.root)
    commit=commit_of();config=create_secrets(dep,config)
    write_json(dep.config_path,config);dep.permissions()
    image=dep.build(SOURCE,config,commit)
    dep.helper('init','--root','/state/data','--password-file','/run/secrets/admin','--issuer',config['issuer'],
               '--username',config['admin_username'],'--enrollment','/exchange/admin-enrollment.json',config=config)
    dep.permissions();record(dep,SOURCE,config,image,commit)
    dep.dc('up','-d');summary(dep,dep.diagnostics())


def fetch_source(dep,repo,ref,expected,config):
    if not re.fullmatch('[0-9a-f]{40}',expected):fail('EXPECTED_COMMIT_MUST_BE_FULL_SHA')
    if not (re.fullmatch(r'v\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.-]+)?',ref) or ref==expected):fail('REF_MUST_BE_RELEASE_TAG_OR_EXPECTED_COMMIT')
    destination=dep.root/'releases'/expected
    if destination.exists():
        if commit_of(destination)!=expected:fail('EXISTING_RELEASE_COMMIT_MISMATCH')
        return destination
    destination.mkdir(parents=True,mode=0o700)
    remote=f'git@github.com:{repo}.git' if config.get('ssh') else f'https://github.com/{repo}.git'
    env={}
    helper_path=None
    if config.get('git_token_file'):
        token=protected(config['git_token_file'])
        fd,helper_path=tempfile.mkstemp(prefix='git-askpass-',dir=dep.root/'config')
        os.chmod(helper_path,0o700)
        with os.fdopen(fd,'w') as f:
            f.write('#!/bin/sh\nexec sh '+shlex.quote(str(SOURCE/'scripts/git-askpass.sh'))+' "$@"\n')
        env={'GIT_ASKPASS':helper_path,'LC_GIT_TOKEN_FILE':str(token)}
    run(['git','init','--quiet',destination]);run(['git','-C',destination,'remote','add','origin',remote])
    try:
        run(['git','-C',destination,'fetch','--quiet','--depth','1','origin',ref],env=env)
    finally:
        if helper_path:Path(helper_path).unlink(missing_ok=True)
    actual=run(['git','-C',destination,'rev-parse','FETCH_HEAD']).stdout.strip()
    if actual!=expected:fail('FETCHED_COMMIT_MISMATCH')
    run(['git','-C',destination,'checkout','--quiet','--detach',actual])
    return destination


def update(args,dep):
    host_check(dep.root);config=dep.config();old=dep.meta()
    source=fetch_source(dep,config['repo'],args.ref,args.commit,config)
    info=release(source)
    if old['schema'] not in info['upgrade_from_schemas'] or info['schema']!=old['schema']:
        fail('SCHEMA_CHANGE_REQUIRES_SEPARATE_MIGRATION_PLAN')
    # Build without altering the running deployment's generated compose.
    image='license-center-local:'+args.commit
    run(['docker','build','--pull','--build-arg','PYTHON_IMAGE='+config.get('python_image',info['python_image']),'-t',image,source])
    dep.dc('stop')
    backup=None
    try:
        backup=dep.backup()
        dep.render(config,source,image,info);dep.dc('up','-d');health=dep.diagnostics()
        record(dep,source,config,image,args.commit,previous={**old,'backup':backup})
        summary(dep,health)
    except BaseException:
        # Do not auto-restore an old DB after new clients may have written.
        print(json.dumps({'error':'UPGRADE_FAILED_SERVICE_MAY_BE_STOPPED','backup':backup,
            'recovery':'停止当前服务。若新服务已写入，先保全并备份当前数据；运行原版本恢复入口到新目录，再审查后切换。',
            'previous_version':old['version'],'previous_commit':old['commit']},ensure_ascii=False))
        raise


def recover(args,dep):
    if dep.meta_path.exists() or (dep.root/'state').exists():fail('RESTORE_REQUIRES_NEW_DEPLOYMENT_ROOT')
    if not args.accept_stale_state:fail('RESTORE_REQUIRES_ACCEPT_STALE_STATE')
    config=prepare_config(args,dep)
    for key in ['backup_password_file','key_password_file']:
        if not config.get(key):fail('RESTORE_REQUIRES_BOTH_PROTECTED_PASSWORD_FILES')
        protected(config[key])
    source=Path(args.bundle).resolve(strict=True)
    envelope=json.loads(source.read_text());header=envelope['header']
    if header['version']!=release()['version'] or header['commit']!=commit_of():fail('RESTORE_MUST_USE_BACKUP_EXACT_SOURCE_VERSION_AND_COMMIT')
    host_check(dep.root,False,True,config);docker_install(config);host_check(dep.root)
    print(json.dumps({'restore_target':str(dep.root),'scope':['database','licenses','codes','instances','revocations','audit','signing_keys'],
                      'backup_time':header['created_at'],'overwrites_existing_data':False},ensure_ascii=False))
    if not args.non_interactive and input('接受备份时间点回退并确认旧服务已隔离？输入 RESTORE: ')!='RESTORE':fail('RESTORE_CANCELLED')
    write_json(dep.config_path,config)
    # Do not create state/data: audited restore requires a nonexistent destination.
    (dep.root/'state').mkdir(parents=True,mode=0o700);(dep.root/'exchange').mkdir(mode=0o700)
    os.chown(dep.root/'state',10001,10001);os.chown(dep.root/'exchange',10001,10001)
    image=dep.build(SOURCE,config,header['commit'])
    dep.helper('restore','--input','/restore-input/bundle.lcb2','--destination','/state/data',
        '--config-output','/exchange/restored-config.json','--password-file','/run/secrets/backup','--key-password-file','/run/secrets/key',
        '--accept-stale-state',config=config,mounts=[(source,'/restore-input/bundle.lcb2','ro')])
    recovered=json.loads((dep.root/'exchange/restored-config.json').read_text())
    if recovered['header']!=header:fail('RESTORE_AUTHENTICATED_METADATA_MISMATCH')
    # Stable issuer follows authenticated backup; new machine network/secret paths follow explicit config.
    config['issuer']=header['issuer'];write_json(dep.config_path,config)
    (dep.root/'state/keys').mkdir(mode=0o700)
    os.replace(dep.root/'state/data/vault.json',dep.root/'state/keys/vault.json')
    dep.permissions();record(dep,SOURCE,config,image,header['commit'])
    dep.dc('up','-d');summary(dep,dep.diagnostics())


def logs(dep):
    # Strict allowlist of center structured request events. Unknown lines are suppressed.
    result=dep.dc('logs','--no-log-prefix','--no-color','--tail','300','center',allow_failure=True,timeout=30)
    count=0
    for line in result.stdout.splitlines():
        try:item=json.loads(line)
        except ValueError:continue
        if item.get('event')!='request':continue
        method=item.get('method');route=item.get('route');status=item.get('status');ms=item.get('ms')
        if method not in ['GET','POST','PUT','DELETE','PATCH'] or type(status) is not int or not isinstance(ms,(int,float)):continue
        if not isinstance(route,str) or not re.fullmatch(r'/[A-Za-z0-9_/{}/.-]*',route):continue
        print(json.dumps({'event':'request','method':method,'route':route,'status':status,'ms':ms}));count+=1
    if not count:print('无符合脱敏白名单的请求日志；未知日志行已隐藏。')


def main():
    p=argparse.ArgumentParser(description='License Center 部署运维（Linux宿主机）')
    p.add_argument('command',choices=['install','update','backup','restore','doctor','status','start','stop','restart','logs','version','uninstall'])
    p.add_argument('--root',default='/opt/license-center');p.add_argument('--config')
    p.add_argument('--non-interactive',action='store_true');p.add_argument('--ref');p.add_argument('--commit')
    p.add_argument('--bundle');p.add_argument('--output');p.add_argument('--accept-stale-state',action='store_true')
    args=p.parse_args();dep=Deployment(args.root)
    if args.command in ['update'] and (not args.ref or not args.commit):p.error('update requires --ref and --commit')
    if args.command=='restore' and not args.bundle:p.error('restore requires --bundle')
    # Validate before any mkdir or mutation, including lockfile creation.
    host_check(dep.root,require_docker=args.command not in ['install','restore'])
    with lock(dep.root):
        if args.command=='install':install(args,dep)
        elif args.command=='update':update(args,dep)
        elif args.command=='restore':recover(args,dep)
        elif args.command=='backup':print(json.dumps({'backup':dep.backup(args.output)}))
        elif args.command=='doctor':print(json.dumps(dep.diagnostics(),ensure_ascii=False,indent=2))
        elif args.command=='version':print(json.dumps(dep.meta(),indent=2))
        elif args.command=='status':print(dep.dc('ps','--format','json').stdout)
        elif args.command=='logs':logs(dep)
        elif args.command=='uninstall':
            dep.dc('down');print('容器已移除；全部业务数据、密钥、配置、备份及网关卷均保留。没有默认彻底清理操作。')
        elif args.command in ['start','restart']:
            dep.dc(*(['up','-d'] if args.command=='start' else ['restart']));summary(dep,dep.diagnostics())
        elif args.command=='stop':dep.dc('stop');print('服务已停止，数据保留。')


if __name__=='__main__':
    try:main()
    except (OperationError,FileNotFoundError,PermissionError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        # Only controlled error codes are exposed. Foreign error strings may contain credentials.
        print(json.dumps({'error':str(exc) if isinstance(exc,OperationError) else type(exc).__name__,
                          'hint':'检查部署文档及doctor；原始外部命令输出未打印以避免泄密。'},ensure_ascii=False),file=sys.stderr)
        raise SystemExit(1)
