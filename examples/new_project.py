"""New web application: authorization is enforced on the backend."""
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from sdk import LicenseClient, LicenseError


def client_from_env():
    trust = json.loads(Path(os.environ['LICENSE_TRUST_FILE']).read_text())
    return LicenseClient(os.environ['LICENSE_URL'], os.environ['LICENSE_PRODUCT'], trust['issuer'], trust['keys'],
                         os.environ.get('LICENSE_CACHE', 'business-state/license.json'),
                         allow_http=os.environ.get('LICENSE_DEV_HTTP') == '1').initialize()


@asynccontextmanager
async def lifespan(app):
    app.state.license = client_from_env()
    app.state.license.start_background_refresh()
    yield
    app.state.license.close()


app = FastAPI(title='新项目接入示例', lifespan=lifespan)


@app.get('/status')
def status():
    return app.state.license.getLicenseStatus()


@app.post('/reports')
def new_report():
    try:
        app.state.license.requireFeature('basic')
    except LicenseError as exc:
        raise HTTPException(403, detail={'code': exc.code}) from exc
    return {'report': '授权通过，本次任务可以创建。已开始的任务应在安全检查点完成或保存。'}


@app.get('/data-export')
def rescue_export():
    # Real systems must additionally authenticate the customer for their own data.
    return {'message': '授权故障时保留客户数据导出与修复入口。业务身份认证仍由业务系统负责。'}
