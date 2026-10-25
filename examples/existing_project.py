"""Existing CLI adaptation: guard the start of new jobs; leave repair/export available."""
import argparse
import getpass
import uuid

from examples.new_project import client_from_env
from sdk import LicenseError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['activate', 'run', 'status', 'renew', 'deactivate', 'export'])
    args = parser.parse_args()
    if args.action == 'export':
        print('现有项目的数据导出入口保持可用；仍需业务身份认证。')
        return
    client = client_from_env()
    try:
        if args.action == 'activate':
            result = client.activate(getpass.getpass('兑换码: '), input('客户标识: '))
        elif args.action == 'renew':
            result = client.renew(getpass.getpass('续费码: '), idempotency_key=str(uuid.uuid4()))
        elif args.action == 'deactivate':
            result = client.deactivate()
        elif args.action == 'run':
            try:
                client.refresh()
            except LicenseError as exc:
                if exc.code not in ['NETWORK_UNAVAILABLE', 'CENTER_UNAVAILABLE', 'RATE_LIMIT']:
                    raise
            client.requireFeature('basic')
            result = {'job': '现有业务函数在这里执行'}
        else:
            result = client.getLicenseStatus()
        print(result)
    except LicenseError as exc:
        print('授权拒绝或故障：' + exc.code)
        raise SystemExit(2)
    finally:
        client.close()


if __name__ == '__main__':
    main()
