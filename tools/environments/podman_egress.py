"""Egress-proxy (iron-proxy) plumbing for the rootless Podman backend.

iron-proxy keeps its existing bind address (``docker0`` when present, else loopback)
and is never modified for Podman. The container reaches it through pasta:

* proxy on loopback: ``--network=pasta:-T,<port>,-T,<port+1>`` forwards exactly those
  two container-loopback ports to the host loopback; every other host-local port stays
  unreachable. The sandbox targets ``127.0.0.1``.
* proxy on a private IP (``docker0``): plain ``--network=pasta`` and the sandbox
  targets that IP directly.
* no pasta (slirp4netns only): refuse under ``proxy.enforce_on_podman``. slirp4netns
  ``allow_host_loopback`` is never used — it would expose the whole host loopback.
"""

from __future__ import annotations

import ipaddress
import logging

from tools.environments.docker_egress import _CONTAINER_CA, proxy_env, resolve_egress
from tools.environments.podman_args import label_volume
from tools.environments.podman_posture import PodmanPosture

logger = logging.getLogger("tools.environments.podman")

_ENFORCE_KEY = "enforce_on_podman"
_EMPTY: tuple[list[str], dict[str, str], list[str]] = ([], {}, [])


def egress_enforce_on_podman(default: bool = True) -> bool:
    """Read ``proxy.enforce_on_podman``; an unreadable config or a non-mapping ``proxy`` fails safe
    to *default*."""
    try:
        from hermes_cli.config import load_config
        proxy = load_config().get("proxy")
    except (ImportError, OSError, ValueError) as exc:
        logger.warning("Could not read proxy config for Podman egress: %s", exc)
        return default
    return bool(proxy.get(_ENFORCE_KEY, default)) if isinstance(proxy, dict) else default


def _classify_listen_host(host: str) -> tuple[str, str] | None:
    """``("loopback", container_host)`` or ``("private", ip)`` for a safe bind host, else None.

    Only private, specified, unicast addresses are accepted: the proxy must never be
    reached through a public or wildcard address.
    """
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost":
        return ("loopback", "127.0.0.1")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.is_loopback:
        return ("loopback", "::1" if addr.version == 6 else "127.0.0.1")
    if (addr.is_unspecified or addr.is_multicast or addr.is_link_local
            or addr.is_reserved or not addr.is_private):
        return None
    return ("private", str(addr))


def egress_args_for_podman(
    p: PodmanPosture, *, network: bool,
) -> tuple[list[str], dict[str, str], list[str]]:
    """``(volume_args, env_overrides, network_args)`` routing a Podman sandbox through
    iron-proxy; all empty when the sandbox has no network or the proxy is off.

    Raises ``RuntimeError`` when the proxy is enabled but unreachable from the sandbox,
    unless ``proxy.enforce_on_podman`` is false (then warns and returns empty).
    ``network_args`` is the pasta ``--network`` flag; reconciling it with the user's
    extra args is the caller's job.
    """
    if not network:
        return _EMPTY
    resolved = resolve_egress(_ENFORCE_KEY)
    if resolved is None:
        return _EMPTY

    def _degraded(msg: str) -> tuple[list[str], dict[str, str], list[str]]:
        if egress_enforce_on_podman():
            raise RuntimeError(
                f"{msg} Refusing to start the sandbox without egress protection; "
                f"set proxy.{_ENFORCE_KEY}: false to start it without the proxy.")
        logger.warning("%s — continuing without proxy (%s=false).", msg, _ENFORCE_KEY)
        return _EMPTY

    if not p.pasta_available:
        return _degraded(
            "Egress proxy is enabled but pasta is not installed; the Podman sandbox "
            "cannot reach iron-proxy (slirp4netns allow_host_loopback is never used). "
            "Install pasta (passt package).")

    target = _classify_listen_host(resolved.listen_host)
    if target is None:
        return _degraded(
            f"iron-proxy listens on {resolved.listen_host!r}, which is not a loopback or "
            "private address; the Podman sandbox will not be pointed at it.")

    kind, proxy_host = target
    port = resolved.tunnel_port
    if kind == "loopback":
        network_args = [f"--network=pasta:-T,{port},-T,{port + 1}"]
    else:
        network_args = ["--network=pasta"]

    volume_args = [
        "-v", label_volume(f"{resolved.ca_cert_path}:{_CONTAINER_CA}:ro", p.selinux)]
    env_overrides = proxy_env(proxy_host, port, resolved.token_env)
    return (volume_args, env_overrides, network_args)
