import pytest
import asyncio
import pytest_asyncio
from grpclib.client import Channel
from typing import AsyncGenerator, Any
import time
import random
import string

from user_grpc import StealthIMUserStub
from user_pb2 import (
    PingRequest, Pong,
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    LogoutRequest, LogoutResponse,
    GetUserInfoRequest, GetUserInfoResponse,
    GetOtherUserInfoRequest, GetOtherUserInfoResponse,
    ChangePasswordRequest, ChangePasswordResponse,
    ChangeNicknameRequest, ChangeNicknameResponse,
    ChangeEmailRequest, ChangeEmailResponse,
    ChangePhoneNumberRequest, ChangePhoneNumberResponse,
)

from session_grpc import StealthIMSessionStub
from session_pb2 import (
    GetRequest, GetResponse,
)

fakeuser = f"testuser_{int(time.time())}"
userid = 0


@pytest_asyncio.fixture
async def stub() -> AsyncGenerator[StealthIMUserStub, Any]:
    """创建gRPC客户端"""
    async with Channel('localhost', 50055) as chan:
        stub = StealthIMUserStub(chan)
        yield stub


@pytest_asyncio.fixture
async def session() -> AsyncGenerator[StealthIMSessionStub, Any]:
    """创建Session gRPC客户端"""
    async with Channel('localhost', 50054) as chan:
        stub = StealthIMSessionStub(chan)
        yield stub


def generate_random_string(length=8):
    """生成随机字符串"""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


@pytest.mark.asyncio
async def test_ping(stub: StealthIMUserStub) -> None:
    """测试Ping方法"""
    response: Pong = await stub.Ping(PingRequest())
    assert type(response) == Pong


@pytest.mark.asyncio
async def test_register(stub: StealthIMUserStub) -> None:
    """测试Register方法"""
    global userid
    request: RegisterRequest = RegisterRequest(
        username=fakeuser,
        password="password123",
        nickname="Test User",
        email="test@example.com",
        phone_number="1234567890"
    )
    response: RegisterResponse = await stub.Register(request)
    assert response.result.code == 0


@pytest.mark.asyncio
async def test_login(stub: StealthIMUserStub, session: StealthIMSessionStub) -> None:
    """测试Login方法"""
    global userid
    request: LoginRequest = LoginRequest(
        username=fakeuser,
        password="password123"
    )
    response: LoginResponse = await stub.Login(request)
    assert response.result.code == 0
    assert response.session != ""
    assert response.user_info.username == fakeuser
    assert response.user_info.nickname != ""
    await asyncio.sleep(0.5)
    request: GetRequest = GetRequest(session=response.session)
    response: GetResponse = await session.Get(request)
    assert response.result.code == 0
    userid = response.uid
    # 验证用户ID是否大于等于0
    assert userid >= 0


@pytest.mark.asyncio
async def test_get_user_info(stub: StealthIMUserStub) -> None:
    """测试GetUserInfo方法"""
    request: GetUserInfoRequest = GetUserInfoRequest(user_id=userid)
    response: GetUserInfoResponse = await stub.GetUserInfo(request)
    assert response.result.code == 0
    assert response.user_info.username != ""
    assert response.user_info.nickname != ""


@pytest.mark.asyncio
async def test_get_other_user_info(stub: StealthIMUserStub) -> None:
    """测试GetOtherUserInfo方法"""
    request: GetOtherUserInfoRequest = GetOtherUserInfoRequest(
        username=fakeuser)
    response: GetOtherUserInfoResponse = await stub.GetOtherUserInfo(request)
    assert response.result.code == 0
    assert response.user_info.nickname != ""


@pytest.mark.asyncio
async def test_change_nickname(stub: StealthIMUserStub) -> None:
    """测试ChangeNickname方法"""
    new_nickname = f"NewName_{int(time.time())}"
    request: ChangeNicknameRequest = ChangeNicknameRequest(
        user_id=userid,
        new_nickname=new_nickname
    )
    response: ChangeNicknameResponse = await stub.ChangeNickname(request)
    assert response.result.code == 0

    # 验证昵称是否已更改
    info_request: GetUserInfoRequest = GetUserInfoRequest(user_id=userid)
    info_response: GetUserInfoResponse = await stub.GetUserInfo(info_request)
    assert info_response.result.code == 0
    assert info_response.user_info.nickname == new_nickname


@pytest.mark.asyncio
async def test_change_email(stub: StealthIMUserStub) -> None:
    """测试ChangeEmail方法"""
    new_email = f"new_email_{int(time.time())}@example.com"
    request: ChangeEmailRequest = ChangeEmailRequest(
        user_id=userid,
        new_email=new_email
    )
    response: ChangeEmailResponse = await stub.ChangeEmail(request)
    assert response.result.code == 0

    # 验证邮箱是否已更改
    info_request: GetUserInfoRequest = GetUserInfoRequest(user_id=userid)
    info_response: GetUserInfoResponse = await stub.GetUserInfo(info_request)
    assert info_response.result.code == 0
    assert info_response.user_info.email == new_email


@pytest.mark.asyncio
async def test_change_phone_number(stub: StealthIMUserStub) -> None:
    """测试ChangePhoneNumber方法"""
    new_phone = f"9876543210"
    request: ChangePhoneNumberRequest = ChangePhoneNumberRequest(
        user_id=userid,
        new_phone_number=new_phone
    )
    response: ChangePhoneNumberResponse = await stub.ChangePhoneNumber(request)
    assert response.result.code == 0

    # 验证手机号是否已更改
    info_request: GetUserInfoRequest = GetUserInfoRequest(user_id=userid)
    info_response: GetUserInfoResponse = await stub.GetUserInfo(info_request)
    assert info_response.result.code == 0
    assert info_response.user_info.phone_number == new_phone


@pytest.mark.asyncio
async def test_change_password(stub: StealthIMUserStub) -> None:
    """测试ChangePassword方法"""
    new_password = "Newpassword456."
    request: ChangePasswordRequest = ChangePasswordRequest(
        user_id=userid,
        new_password=new_password
    )
    response: ChangePasswordResponse = await stub.ChangePassword(request)
    assert response.result.code == 0
    await asyncio.sleep(0.5)

    # 使用新密码登录验证密码是否已更改
    login_request: LoginRequest = LoginRequest(
        username=fakeuser,
        password=new_password
    )
    login_response: LoginResponse = await stub.Login(login_request)
    assert login_response.result.code == 0
    assert login_response.session != ""


@pytest.mark.asyncio
async def test_logout(stub: StealthIMUserStub) -> None:
    """测试Logout方法"""
    request: LogoutRequest = LogoutRequest(user_id=userid)
    response: LogoutResponse = await stub.Logout(request)
    assert response.result.code == 0


# 以下是额外的测试用例

@pytest.mark.asyncio
async def test_register_duplicate_username(stub: StealthIMUserStub) -> None:
    """测试注册重复用户名"""
    # 尝试使用相同用户名再次注册
    request: RegisterRequest = RegisterRequest(
        username=fakeuser,
        password="password123",
        nickname="Duplicate User",
        email="duplicate@example.com",
        phone_number="9876543210"
    )
    response: RegisterResponse = await stub.Register(request)
    # 应该返回错误码，表示用户名已存在
    assert response.result.code != 0


@pytest.mark.asyncio
async def test_login_wrong_password(stub: StealthIMUserStub) -> None:
    """测试使用错误密码登录"""
    request: LoginRequest = LoginRequest(
        username=fakeuser,
        password="wrongpassword"
    )
    response: LoginResponse = await stub.Login(request)
    # 应该返回错误码，表示密码错误
    assert response.result.code != 0


@pytest.mark.asyncio
async def test_login_nonexistent_user(stub: StealthIMUserStub) -> None:
    """测试使用不存在的用户名登录"""
    nonexistent_user = f"nonexistent_{int(time.time())}"
    request: LoginRequest = LoginRequest(
        username=nonexistent_user,
        password="anypassword"
    )
    response: LoginResponse = await stub.Login(request)
    # 应该返回错误码，表示用户不存在
    assert response.result.code != 0


@pytest.mark.asyncio
async def test_get_user_info_invalid_id(stub: StealthIMUserStub) -> None:
    """测试获取不存在的用户信息"""
    invalid_id = -1  # 无效的用户ID
    request: GetUserInfoRequest = GetUserInfoRequest(user_id=invalid_id)
    response: GetUserInfoResponse = await stub.GetUserInfo(request)
    # 应该返回错误码，表示用户ID无效
    assert response.result.code != 0


@pytest.mark.asyncio
async def test_get_other_user_info_nonexistent(stub: StealthIMUserStub) -> None:
    """测试获取不存在的用户的公开信息"""
    nonexistent_user = f"nonexistent_{int(time.time())}"
    request: GetOtherUserInfoRequest = GetOtherUserInfoRequest(
        username=nonexistent_user)
    response: GetOtherUserInfoResponse = await stub.GetOtherUserInfo(request)
    # 应该返回错误码，表示用户不存在
    assert response.result.code != 0


@pytest.mark.asyncio
async def test_multiple_user_operations(stub: StealthIMUserStub, session: StealthIMSessionStub) -> None:
    """测试多用户操作，创建多个用户并验证UID都大于等于0"""

    # 创建3个不同的用户
    user_ids = []
    for i in range(3):
        # 随机生成用户名
        random_user = f"testuser_{generate_random_string()}"

        # 注册
        register_request = RegisterRequest(
            username=random_user,
            password="Password123.",
            nickname=f"Test User {i}",
            email=f"test{i}@example.com",
            phone_number=f"123456789{i}"
        )
        register_response = await stub.Register(register_request)
        assert register_response.result.code == 0

        # 登录
        login_request = LoginRequest(
            username=random_user,
            password="Password123."
        )
        login_response = await stub.Login(login_request)
        assert login_response.result.code == 0

        # 获取用户ID
        get_request = GetRequest(session=login_response.session)
        await asyncio.sleep(0.5)
        get_response = await session.Get(get_request)
        assert get_response.result.code == 0
        user_id = get_response.uid
        user_ids.append(user_id)

        # 验证用户ID都大于等于0
        assert user_id >= 0

        # 修改昵称
        new_nickname = f"NewName{generate_random_string()}"
        nickname_request = ChangeNicknameRequest(
            user_id=user_id,
            new_nickname=new_nickname
        )
        nickname_response = await stub.ChangeNickname(nickname_request)
        assert nickname_response.result.code == 0

        # 登出
        logout_request = LogoutRequest(user_id=user_id)
        logout_response = await stub.Logout(logout_request)
        assert logout_response.result.code == 0

    # 验证所有用户ID都不同
    assert len(set(user_ids)) == 3
