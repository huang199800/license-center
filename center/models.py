from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Product(Model):
    id: str = Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,63}$')
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(default='1.0', max_length=40)


class Plan(Model):
    id: str = Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,63}$')
    product: str
    name: str = Field(min_length=1, max_length=80)
    days: int | None = Field(default=30, ge=1, le=36500)
    perpetual: bool = False
    features: list[str] = Field(default_factory=lambda: ['basic'], max_length=100)
    quotas: dict[str, int] = Field(default_factory=dict, max_length=100)
    max_devices: int = Field(default=1, ge=1, le=10000)
    max_online: int = Field(default=1, ge=1, le=10000)
    policy: Literal['online', 'periodic', 'offline'] = 'periodic'
    token_ttl: int = Field(default=900, ge=10, le=86400)
    refresh_interval: int = Field(default=300, ge=1, le=86400)
    offline_max: int = Field(default=900, ge=10, le=31536000)
    rebind_limit: int = Field(default=3, ge=0, le=1000)
    rebind_cooldown: int = Field(default=86400, ge=0, le=31536000)
    upgrade_days: int | None = Field(default=None, ge=1, le=36500)
    support_days: int | None = Field(default=None, ge=1, le=36500)

    @model_validator(mode='after')
    def consistent(self):
        if self.perpetual != (self.days is None):
            raise ValueError('永久套餐必须 days=null；有期套餐必须 days>=1')
        if self.refresh_interval >= self.token_ttl or self.token_ttl > self.offline_max:
            raise ValueError('需要 refresh_interval < token_ttl <= offline_max')
        if self.max_online > self.max_devices or any(v < 0 for v in self.quotas.values()):
            raise ValueError('在线数不得大于设备数，配额不得为负')
        return self


class CodeBatch(Model):
    plan: str
    count: int = Field(default=1, ge=1, le=500)
    kind: Literal['new', 'renew', 'upgrade'] = 'new'
    max_uses: int = Field(default=1, ge=1, le=10000)
    redeem_before: int | None = Field(default=None, ge=0)
    starts_at: int | None = Field(default=None, ge=0)
    note: str = Field(default='', max_length=300)


class Redeem(Model):
    product: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=20, max_length=100)
    customer: str = Field(min_length=1, max_length=120)
    instance: str = Field(min_length=16, max_length=200)


class Activate(Model):
    product: str
    license_id: str
    instance: str = Field(min_length=16, max_length=200)


class Renew(Model):
    product: str
    license_id: str
    code: str = Field(min_length=20, max_length=100)


class Refresh(Model):
    product: str
    activation_id: str


class Login(Model):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(pattern=r'^\d{6}$')


class Reauth(Model):
    otp: str = Field(pattern=r'^\d{6}$')


class Status(Model):
    status: Literal['active', 'paused', 'revoked']
    reason: str = Field(min_length=3, max_length=300)


class OfflineIssue(Model):
    plan: str
    customer: str = Field(min_length=1, max_length=120)
    instance: str = Field(min_length=16, max_length=200)
    reason: str = Field(min_length=3, max_length=300)
