from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_network_asserts.accounts import AccountClients, validate_account_id
from aws_network_asserts.clients import AwsClients
from aws_network_asserts.errors import AccountMismatchError, NetworkAssertionError

REGION = "eu-west-2"
OTHER_REGION = "eu-west-1"
CENTRAL_ACCOUNT = "123456789012"
MEMBER_ACCOUNT = "210987654321"


def make_session(account_id):
    session = Mock(region_name=REGION)
    sts = Mock()
    sts.get_caller_identity.return_value = {"Account": account_id}
    session.client.side_effect = lambda service, **kwargs: sts if service == "sts" else object()
    return session, sts


def test_account_id_validation_preserves_valid_string():
    assert validate_account_id("000000000001") == "000000000001"


@pytest.mark.parametrize(
    "value",
    [
        None,
        123456789012,
        "",
        "12345678901",
        "1234567890123",
        "12345678901a",
        " 123456789012",
        "123456789012\n",
        "１２３４５６７８９０１２",
    ],
)
def test_account_id_validation_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="12 digits"):
        validate_account_id(value)


@pytest.mark.parametrize("profile", [None, 123, "", " \t"])
def test_profile_names_must_be_nonempty_strings(profile):
    with pytest.raises(ValueError, match="nonempty profile"):
        AccountClients(AwsClients(Mock()), account_profiles={MEMBER_ACCOUNT: profile})


@pytest.mark.parametrize("option", ["account_profiles", "account_sessions"])
def test_mapping_keys_must_be_account_ids(option):
    value = "member-profile" if option == "account_profiles" else Mock()
    with pytest.raises(ValueError, match="12 digits"):
        AccountClients(AwsClients(Mock()), **{option: {"not-an-account": value}})


def test_mapping_cannot_supply_profile_and_session_for_same_account():
    with pytest.raises(ValueError, match="both a profile and a session"):
        AccountClients(
            AwsClients(Mock()),
            account_profiles={MEMBER_ACCOUNT: "member"},
            account_sessions={MEMBER_ACCOUNT: Mock()},
        )


@pytest.mark.parametrize("session", [None, "member", object()])
def test_session_mapping_cannot_silently_create_a_default_session(session):
    with pytest.raises(TypeError, match="boto3 sessions"):
        AccountClients(AwsClients(Mock()), account_sessions={MEMBER_ACCOUNT: session})


def test_central_fallback_verifies_identity_and_reuses_client():
    central, sts = make_session(CENTRAL_ACCOUNT)
    accounts = AccountClients(AwsClients(central))

    client = accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
    assert accounts.client("ec2", REGION, CENTRAL_ACCOUNT) is client
    accounts.client("config", REGION, CENTRAL_ACCOUNT)

    sts.get_caller_identity.assert_called_once_with()
    assert [call.args[0] for call in central.client.call_args_list] == ["sts", "ec2", "config"]


def test_central_fallback_never_constructs_a_wrong_account_service_client():
    central, sts = make_session(CENTRAL_ACCOUNT)
    accounts = AccountClients(AwsClients(central))

    with pytest.raises(AccountMismatchError) as error:
        accounts.client("ec2", REGION, MEMBER_ACCOUNT)

    assert isinstance(error.value, NetworkAssertionError)
    assert CENTRAL_ACCOUNT in str(error.value)
    assert MEMBER_ACCOUNT in str(error.value)
    assert "account_profiles" in str(error.value)
    assert "account_sessions" in str(error.value)
    sts.get_caller_identity.assert_called_once_with()
    assert [call.args[0] for call in central.client.call_args_list] == ["sts"]


def test_cached_central_identity_is_compared_with_every_requested_account():
    central, sts = make_session(CENTRAL_ACCOUNT)
    accounts = AccountClients(AwsClients(central))
    accounts.client("ec2", REGION, CENTRAL_ACCOUNT)

    with pytest.raises(AccountMismatchError):
        accounts.client("config", REGION, MEMBER_ACCOUNT)

    sts.get_caller_identity.assert_called_once_with()
    assert [call.args[0] for call in central.client.call_args_list] == ["sts", "ec2"]


def test_member_session_is_selected_without_using_central_credentials():
    central, central_sts = make_session(CENTRAL_ACCOUNT)
    member, member_sts = make_session(MEMBER_ACCOUNT)
    accounts = AccountClients(AwsClients(central), account_sessions={MEMBER_ACCOUNT: member})

    client = accounts.client("ec2", REGION, MEMBER_ACCOUNT)
    assert accounts.client("ec2", REGION, MEMBER_ACCOUNT) is client

    central.client.assert_not_called()
    central_sts.get_caller_identity.assert_not_called()
    member_sts.get_caller_identity.assert_called_once_with()
    assert [call.args[0] for call in member.client.call_args_list] == ["sts", "ec2"]


def test_member_session_mismatch_is_not_cached_and_never_constructs_ec2_client():
    central, _ = make_session(CENTRAL_ACCOUNT)
    member, member_sts = make_session(CENTRAL_ACCOUNT)
    accounts = AccountClients(AwsClients(central), account_sessions={MEMBER_ACCOUNT: member})

    with pytest.raises(AccountMismatchError):
        accounts.client("ec2", REGION, MEMBER_ACCOUNT)
    assert [call.args[0] for call in member.client.call_args_list] == ["sts"]

    member_sts.get_caller_identity.return_value = {"Account": MEMBER_ACCOUNT}
    accounts.client("ec2", REGION, MEMBER_ACCOUNT)

    assert member_sts.get_caller_identity.call_count == 2
    assert [call.args[0] for call in member.client.call_args_list] == ["sts", "ec2"]
    central.client.assert_not_called()


def test_failed_sts_request_propagates_and_is_not_cached():
    central, sts = make_session(CENTRAL_ACCOUNT)
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetCallerIdentity"
    )
    sts.get_caller_identity.side_effect = [error, {"Account": CENTRAL_ACCOUNT}]
    accounts = AccountClients(AwsClients(central))

    with pytest.raises(ClientError) as raised:
        accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
    assert raised.value is error
    assert [call.args[0] for call in central.client.call_args_list] == ["sts"]

    accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
    assert sts.get_caller_identity.call_count == 2


def test_missing_sts_account_fails_closed():
    central, sts = make_session(CENTRAL_ACCOUNT)
    sts.get_caller_identity.return_value = {}
    accounts = AccountClients(AwsClients(central))

    with pytest.raises(AccountMismatchError):
        accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
    assert [call.args[0] for call in central.client.call_args_list] == ["sts"]


def test_profiles_are_lazy_and_use_boto3s_standard_credential_provider(monkeypatch):
    central, _ = make_session(CENTRAL_ACCOUNT)
    member, member_sts = make_session(MEMBER_ACCOUNT)
    session_factory = Mock(return_value=member)
    monkeypatch.setattr("aws_network_asserts.accounts.boto3.Session", session_factory)
    profiles = {MEMBER_ACCOUNT: "member-role"}
    accounts = AccountClients(AwsClients(central), account_profiles=profiles)
    profiles[MEMBER_ACCOUNT] = "changed-after-construction"

    accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
    session_factory.assert_not_called()

    client = accounts.client("ec2", REGION, MEMBER_ACCOUNT)
    assert accounts.client("ec2", REGION, MEMBER_ACCOUNT) is client
    session_factory.assert_called_once_with(profile_name="member-role")
    member_sts.get_caller_identity.assert_called_once_with()


def test_factories_and_identity_checks_are_cached_per_account_and_region():
    central, _ = make_session(CENTRAL_ACCOUNT)
    member, sts = make_session(MEMBER_ACCOUNT)
    accounts = AccountClients(AwsClients(central), account_sessions={MEMBER_ACCOUNT: member})

    london = accounts.client("ec2", REGION, MEMBER_ACCOUNT)
    ireland = accounts.client("ec2", OTHER_REGION, MEMBER_ACCOUNT)
    assert london is not ireland
    assert accounts.client("ec2", REGION, MEMBER_ACCOUNT) is london
    assert accounts.client("ec2", OTHER_REGION, MEMBER_ACCOUNT) is ireland
    assert sts.get_caller_identity.call_count == 2
    assert [
        (call.args[0], call.kwargs["region_name"]) for call in member.client.call_args_list
    ] == [("sts", REGION), ("ec2", REGION), ("sts", OTHER_REGION), ("ec2", OTHER_REGION)]


def test_endpoint_and_transport_settings_are_inherited_including_sts():
    central, _ = make_session(CENTRAL_ACCOUNT)
    member, _ = make_session(MEMBER_ACCOUNT)
    factory = AwsClients(
        central,
        endpoint_url="http://common.invalid:4566",
        endpoint_urls={
            "sts": "http://sts.invalid:4566",
            f"{REGION}:sts": "http://london-sts.invalid:4566",
            "ec2": "http://ec2.invalid:4566",
            f"{REGION}:ec2": "http://london-ec2.invalid:4566",
        },
        boto_config=Config(read_timeout=7, max_pool_connections=32),
        verify="/path/to/private-ca.pem",
    )
    accounts = AccountClients(factory, account_sessions={MEMBER_ACCOUNT: member})

    accounts.client("ec2", REGION, MEMBER_ACCOUNT)
    accounts.client("ec2", OTHER_REGION, MEMBER_ACCOUNT)
    accounts.client("config", OTHER_REGION, MEMBER_ACCOUNT)

    assert [call.kwargs["endpoint_url"] for call in member.client.call_args_list] == [
        "http://london-sts.invalid:4566",
        "http://london-ec2.invalid:4566",
        "http://sts.invalid:4566",
        "http://ec2.invalid:4566",
        "http://common.invalid:4566",
    ]
    for call in member.client.call_args_list:
        kwargs = call.kwargs
        assert kwargs["verify"] == "/path/to/private-ca.pem"
        assert kwargs["config"].read_timeout == 7
        assert kwargs["config"].connect_timeout == 5
        assert kwargs["config"].max_pool_connections == 32
        assert kwargs["config"].retries == {"mode": "standard", "total_max_attempts": 3}


def test_identity_from_one_region_cannot_authorize_another_region_endpoint():
    session, london_sts = make_session(MEMBER_ACCOUNT)
    ireland_sts = Mock()
    ireland_sts.get_caller_identity.return_value = {"Account": CENTRAL_ACCOUNT}
    session.client.side_effect = lambda service, **kwargs: (
        (london_sts if kwargs["region_name"] == REGION else ireland_sts)
        if service == "sts"
        else object()
    )
    accounts = AccountClients(AwsClients(session))
    accounts.client("ec2", REGION, MEMBER_ACCOUNT)

    with pytest.raises(AccountMismatchError):
        accounts.client("ec2", OTHER_REGION, MEMBER_ACCOUNT)

    assert [
        (call.args[0], call.kwargs["region_name"]) for call in session.client.call_args_list
    ] == [("sts", REGION), ("ec2", REGION), ("sts", OTHER_REGION)]


def test_account_verification_and_client_creation_are_serialized_between_threads():
    central, sts = make_session(CENTRAL_ACCOUNT)
    accounts = AccountClients(AwsClients(central))

    with ThreadPoolExecutor(max_workers=6) as executor:
        clients = list(
            executor.map(lambda _: accounts.client("ec2", REGION, CENTRAL_ACCOUNT), range(24))
        )

    assert all(client is clients[0] for client in clients)
    sts.get_caller_identity.assert_called_once_with()
    assert central.client.call_count == 2


def test_real_sts_client_is_verified_before_returning_requested_client():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    central = AwsClients(session, endpoint_url="http://localhost:4566")
    sts = central.client("sts", REGION)
    accounts = AccountClients(central)
    with Stubber(sts) as stub:
        stub.add_response(
            "get_caller_identity",
            {
                "Account": CENTRAL_ACCOUNT,
                "Arn": f"arn:aws:iam::{CENTRAL_ACCOUNT}:user/test",
                "UserId": "test-user",
            },
            {},
        )
        client = accounts.client("ec2", REGION, CENTRAL_ACCOUNT)
        stub.assert_no_pending_responses()

    assert client.meta.endpoint_url == "http://localhost:4566"
    assert client.meta.region_name == REGION
