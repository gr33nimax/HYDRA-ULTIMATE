from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, User
from hydra.ui import menus
from hydra.ui._menus import users_links


def test_add_user_normalizes_email_and_rejects_case_insensitive_duplicate():
    state = AppState(users=[User(email="alice@example.com", uuid="existing")])
    app = MagicMock()

    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "prompt", side_effect=["  ALICE@EXAMPLE.COM  ", ""]), \
         patch.object(menus, "error") as show_error, \
         patch("hydra.plugins.registry.enabled", return_value=[]):
        menus._add_user(state, app)

    app.add_user.assert_not_called()
    show_error.assert_called_once()


def test_add_user_accepts_username_without_email_domain():
    state = AppState()
    app = MagicMock()
    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "prompt", side_effect=["testik", ""]), \
         patch("hydra.plugins.registry.enabled", return_value=[]):
        menus._add_user(state, app)

    assert app.add_user.call_args.args[1].email == "testik"


def test_reconcile_blocks_user_immediately_when_quota_is_exhausted():
    user = User(
        email="alice@example.com",
        uuid="token",
        traffic_limit_gb=1,
        traffic_used_bytes=1073741824,
    )
    state = AppState(users=[user])
    app = MagicMock()

    with patch.object(menus, "warn"):
        menus._reconcile_user_access(state, user, app)

    app.block_user.assert_called_once_with(state, "alice@example.com")


def test_reconcile_offers_unblock_after_limits_are_extended():
    user = User(email="alice@example.com", uuid="token", blocked=True)
    state = AppState(users=[user])
    app = MagicMock()

    with patch.object(menus, "confirm", return_value=True), \
         patch.object(menus, "success"):
        menus._reconcile_user_access(state, user, app)

    app.unblock_user.assert_called_once_with(state, "alice@example.com")


def test_manual_unblock_is_rejected_while_subscription_is_expired():
    user = User(
        email="alice@example.com",
        uuid="token",
        blocked=True,
        expiry_date="2000-01-01T00:00:00Z",
    )
    state = AppState(users=[user])
    app = MagicMock()

    with patch.object(menus, "error") as show_error, \
         patch.object(menus, "prompt", return_value=""):
        menus._toggle_block(state, user, app)

    app.unblock_user.assert_not_called()
    assert "срок истёк" in show_error.call_args.args[0]


def test_subscription_urls_are_hidden_until_server_is_ready():
    user = User(email="alice@example.com", uuid="token")
    state = AppState(users=[user])
    app = MagicMock()
    app.admin.unit_active.return_value = False
    app.admin.subscription_certificate.return_value = (None, None)

    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "warn") as show_warning, \
         patch.object(menus, "prompt"), \
         patch.object(menus, "get_subscription_urls") as get_urls:
        menus._show_subscription_links(state, user, app)

    get_urls.assert_not_called()
    assert "не запущен" in show_warning.call_args.args[0]


def test_subscription_urls_are_hidden_without_https_material():
    user = User(email="alice@example.com", uuid="token")
    state = AppState(users=[user])
    app = MagicMock()
    app.admin.unit_active.return_value = True
    app.admin.subscription_certificate.return_value = (None, None)

    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "warn") as show_warning, \
         patch.object(menus, "prompt"), \
         patch.object(menus, "get_subscription_urls") as get_urls:
        menus._show_subscription_links(state, user, app)

    get_urls.assert_not_called()
    assert "сертификат отсутствует" in show_warning.call_args.args[0]


def test_client_uri_is_printed_as_one_unframed_exact_line():
    link = (
        "vless://token@example.com:443?security=tls&type=xhttp"
        "#Default%20VLESS%20XHTTP"
    )
    artifact = users_links._ClientArtifact(
        plugin_name="vless",
        display_name="VLESS",
        profile_name="",
        profile_label="",
        config="",
        links=(link,),
    )

    with patch("builtins.print") as output:
        users_links._render_inline_artifact(artifact)

    rendered = [call.args[0] for call in output.call_args_list if call.args]
    assert link in rendered
    assert not any("║" in line for line in rendered)


def test_subscription_urls_are_printed_as_exact_unframed_lines():
    user = User(email="alice@example.com", uuid="token")
    state = AppState(users=[user])
    app = MagicMock()
    app.admin.unit_active.return_value = True
    app.admin.subscription_certificate.return_value = ("cert", "key")
    urls = {
        "auto": "https://sub.example.com/sub/token",
        "nekobox": "https://sub.example.com/sub/token?client=nekobox",
        "shadowrocket": (
            "https://sub.example.com/sub/token?format=shadowrocket"
        ),
        "throne": "https://sub.example.com/sub/token?client=throne",
        "singbox": "https://sub.example.com/sub/token?format=singbox",
        "hydrabox": "https://sub.example.com/sub/token?format=hydrabox",
    }

    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "panel"), \
         patch.object(menus, "prompt"), \
         patch.object(menus, "get_subscription_urls", return_value=urls), \
         patch("builtins.print") as output:
        menus._show_subscription_links(state, user, app)

    rendered = [call.args[0] for call in output.call_args_list if call.args]
    assert all(url in rendered for url in urls.values())
