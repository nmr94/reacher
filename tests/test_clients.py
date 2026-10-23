from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import NoRegionError

from aws_network_asserts.clients import AwsClients


def test_endpoint_precedence_and_region_scoped_cache():
    session = Mock(region_name="eu-west-2")
    session.client.side_effect = lambda *args, **kwargs: object()
    clients = AwsClients(
        session,
        endpoint_url="http://common.invalid:4566",
        endpoint_urls={
            "ec2": "http://ec2.invalid:4566",
            "eu-west-2:ec2": "http://london.invalid:4566",
        },
    )
    london = clients.client("ec2", "eu-west-2")
    ireland = clients.client("ec2", "eu-west-1")
    config = clients.client("config", "eu-west-2")

    assert london is clients.client("ec2", "eu-west-2")
    assert london is not ireland
    assert config is not london
    assert session.client.call_count == 3
    assert [call.kwargs["endpoint_url"] for call in session.client.call_args_list] == [
        "http://london.invalid:4566",
        "http://ec2.invalid:4566",
        "http://common.invalid:4566",
    ]
    assert [call.kwargs["region_name"] for call in session.client.call_args_list] == [
        "eu-west-2",
        "eu-west-1",
        "eu-west-2",
    ]


def test_omits_unspecified_endpoint_and_verify_and_keeps_credentials_in_session():
    session = Mock(region_name=None)
    clients = AwsClients(session)
    clients.client("ec2", "eu-west-2")

    kwargs = session.client.call_args.kwargs
    assert set(kwargs) == {"region_name", "config"}
    assert kwargs["config"].retries == {"mode": "standard", "total_max_attempts": 3}
    assert kwargs["config"].connect_timeout == 5
    assert kwargs["config"].read_timeout == 30
    assert clients.region_name is None
    with pytest.raises(NoRegionError):
        clients.client("ec2", "")


@pytest.mark.parametrize("verify", [False, True, "/path/to/private-ca.pem"])
def test_boto_config_and_tls_verification_are_forwarded(verify):
    session = Mock(region_name="eu-west-2")
    supplied = Config(read_timeout=7, max_pool_connections=32)
    clients = AwsClients(session, boto_config=supplied, verify=verify)
    clients.client("config", "eu-west-1")

    kwargs = session.client.call_args.kwargs
    assert kwargs["verify"] == verify
    assert kwargs["config"].read_timeout == 7
    assert kwargs["config"].connect_timeout == 5
    assert kwargs["config"].max_pool_connections == 32
    assert supplied.connect_timeout == 60  # caller's Config was not changed


def test_client_creation_is_serialized_and_reused_across_threads():
    session = Mock(region_name="eu-west-2")
    clients = AwsClients(session)
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: clients.client("ec2", "eu-west-2"), range(24)))
    assert all(client is results[0] for client in results)
    session.client.assert_called_once()


def test_real_boto_client_respects_endpoint_environment(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL_EC2", "http://localhost:4999")
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name="eu-west-2"
    )
    client = AwsClients(session).client("ec2", "eu-west-2")
    assert client.meta.endpoint_url == "http://localhost:4999"
    assert client.meta.region_name == "eu-west-2"
