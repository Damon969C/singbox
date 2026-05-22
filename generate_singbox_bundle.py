#!/usr/bin/env python3
"""Generate sing-box VLESS and Hysteria2 tunnel configs for remote LAN access."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path


LAN_CIDRS = ["10.0.0.0/24", "10.10.10.0/24"]
GLOBAL_ROUTE_CIDRS = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
BOOTSTRAP_DNS_TAG = "bootstrap-dns"
BOOTSTRAP_DNS_SERVER = "223.5.5.5"
BOOTSTRAP_DOMAIN_RESOLVER = {
    "server": BOOTSTRAP_DNS_TAG,
    "strategy": "prefer_ipv4",
}
TUN_MTU = 1280
REMOTE_DNS_TAG = "remote-dns"
LAN_DNS_SERVER = "10.0.0.1"
REMOTE_DNS_SERVER = LAN_DNS_SERVER
LOCAL_DNS_PRIMARY_TAG = "local-dns-1"
LOCAL_DNS_SECONDARY_TAG = "local-dns-2"
LOCAL_DNS_PRIMARY_SERVER = "180.76.76.76"
LOCAL_DNS_SECONDARY_SERVER = "223.5.5.5"
MIHOMO_DNS_TAG = "mihomo-dns"
MIHOMO_DNS_PORT = 53
MIHOMO_SERVER = "10.0.0.20"
MIHOMO_MIXED_PORT = 7890
REALITY_SERVER_NAME = "www.bilibili.com"
REALITY_SERVER_PORT = 443
GLOBAL_ROUTE_RULES = [
    {
        "action": "sniff",
    },
    {
        "protocol": "dns",
        "action": "hijack-dns",
    },
]
LAN_ROUTE_RULES = [
    {
        "action": "sniff",
    },
    {
        "protocol": "dns",
        "action": "hijack-dns",
    },
    {
        "ip_cidr": LAN_CIDRS,
        "action": "route",
        "outbound": "lan-select",
    },
]

SERVER_CONFIG_NAME = "sing-box-server.json"
CLIENT_CONFIG_NAMES = {
    "vless-10": "vless-10.json",
    "vless-lan": "vless-lan.json",
    "vless-mihomo": "vless-mihomo.json",
    "hy2-10": "hy2-10.json",
    "hy2-lan": "hy2-lan.json",
    "hy2-mihomo": "hy2-mihomo.json",
}
SUMMARY_NAME = "sing-box-secrets.txt"
HY2_CERT_NAME = "sing-box-hy2-cert.pem"
HY2_KEY_NAME = "sing-box-hy2-key.pem"


@dataclass(frozen=True)
class SingBoxParams:
    server_domain: str
    vless_port: int
    hy2_port: int


@dataclass(frozen=True)
class SingBoxSecrets:
    uuid: str
    reality_private_key: str
    reality_public_key: str
    reality_short_id: str
    hy2_password: str
    hy2_obfs_password: str


@dataclass(frozen=True)
class BundlePaths:
    server_config_path: Path
    client_config_paths: dict[str, Path]
    summary_path: Path
    hy2_cert_path: Path
    hy2_key_path: Path


def configure_stdio():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def require_command(command: str):
    if shutil.which(command):
        return
    raise RuntimeError(f"缺少命令: {command}")


def run_command(args: list[str], *, check=True, capture_output=False):
    return subprocess.run(
        args,
        check=check,
        capture_output=capture_output,
        text=True,
    )


def parse_reality_key_pair(output: str) -> tuple[str, str]:
    private_key = None
    public_key = None

    for line in output.splitlines():
        normalized = line.lower().replace(" ", "")
        if normalized.startswith("privatekey:"):
            private_key = line.split(":", 1)[1].strip()
        elif normalized.startswith("publickey:"):
            public_key = line.split(":", 1)[1].strip()

    if not private_key or not public_key:
        raise RuntimeError("无法从 sing-box generate reality-keypair 输出中解析 Reality 密钥对")

    return private_key, public_key


def generate_reality_key_pair() -> tuple[str, str]:
    require_command("sing-box")
    result = run_command(["sing-box", "generate", "reality-keypair"], capture_output=True)
    return parse_reality_key_pair(result.stdout)


def generate_secrets() -> SingBoxSecrets:
    private_key, public_key = generate_reality_key_pair()
    return SingBoxSecrets(
        uuid=str(uuid.uuid4()),
        reality_private_key=private_key,
        reality_public_key=public_key,
        reality_short_id=secrets.token_hex(4),
        hy2_password=secrets.token_urlsafe(32),
        hy2_obfs_password=secrets.token_urlsafe(32),
    )


def build_server_config(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    cert_path: str,
    key_path: str,
) -> dict:
    return {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "::",
                "listen_port": params.vless_port,
                "users": [
                    {
                        "name": "lan-vless",
                        "uuid": secrets_value.uuid,
                        "flow": "xtls-rprx-vision",
                    },
                ],
                "tls": {
                    "enabled": True,
                    "server_name": REALITY_SERVER_NAME,
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": REALITY_SERVER_NAME,
                            "server_port": REALITY_SERVER_PORT,
                        },
                        "private_key": secrets_value.reality_private_key,
                        "short_id": [
                            secrets_value.reality_short_id,
                        ],
                    },
                },
            },
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": params.hy2_port,
                "users": [
                    {
                        "name": "lan-hy2",
                        "password": secrets_value.hy2_password,
                    },
                ],
                "obfs": {
                    "type": "salamander",
                    "password": secrets_value.hy2_obfs_password,
                },
                "tls": {
                    "enabled": True,
                    "certificate_path": cert_path,
                    "key_path": key_path,
                },
            },
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "route": {
            "final": "direct",
        },
    }


def build_tun_inbound(route_address: list[str]) -> dict:
    return {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "singbox-lan",
        "address": [
            "172.19.0.1/30",
            "fdfe:dcba:9876::1/126",
        ],
        "mtu": TUN_MTU,
        "auto_route": True,
        "strict_route": True,
        "auto_redirect": True,
        "route_address": route_address,
        "stack": "mixed",
    }


def build_selector_outbound(default_tunnel: str) -> dict:
    if default_tunnel not in {"vless-out", "hy2-out"}:
        raise ValueError("default_tunnel 必须是 vless-out 或 hy2-out")

    return {
        "type": "selector",
        "tag": "lan-select",
        "outbounds": [
            "vless-out",
            "hy2-out",
        ],
        "default": default_tunnel,
        "interrupt_exist_connections": True,
    }


def build_vless_outbound(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    domain_resolver: str | None = None,
) -> dict:
    outbound = {
        "type": "vless",
        "tag": "vless-out",
        "server": params.server_domain,
        "server_port": params.vless_port,
        "uuid": secrets_value.uuid,
        "flow": "xtls-rprx-vision",
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": REALITY_SERVER_NAME,
            "utls": {
                "enabled": True,
                "fingerprint": "chrome",
            },
            "reality": {
                "enabled": True,
                "public_key": secrets_value.reality_public_key,
                "short_id": secrets_value.reality_short_id,
            },
        },
    }
    if domain_resolver:
        outbound["domain_resolver"] = domain_resolver
    return outbound


def build_hy2_outbound(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    domain_resolver: str | None = None,
) -> dict:
    outbound = {
        "type": "hysteria2",
        "tag": "hy2-out",
        "server": params.server_domain,
        "server_port": params.hy2_port,
        "password": secrets_value.hy2_password,
        "obfs": {
            "type": "salamander",
            "password": secrets_value.hy2_obfs_password,
        },
        "tls": {
            "enabled": True,
            "server_name": params.server_domain,
            "insecure": True,
        },
    }
    if domain_resolver:
        outbound["domain_resolver"] = domain_resolver
    return outbound


def build_global_dns_config() -> dict:
    return {
        "servers": [
            {
                "type": "udp",
                "tag": BOOTSTRAP_DNS_TAG,
                "server": BOOTSTRAP_DNS_SERVER,
                "server_port": 53,
            },
            {
                "type": "tcp",
                "tag": REMOTE_DNS_TAG,
                "server": REMOTE_DNS_SERVER,
                "server_port": 53,
                "detour": "lan-select",
            },
        ],
        "final": REMOTE_DNS_TAG,
        "strategy": "prefer_ipv4",
        "reverse_mapping": True,
        "cache_capacity": 4096,
    }


def build_lan_dns_config() -> dict:
    return {
        "servers": [
            {
                "type": "udp",
                "tag": BOOTSTRAP_DNS_TAG,
                "server": BOOTSTRAP_DNS_SERVER,
                "server_port": 53,
            },
            {
                "type": "udp",
                "tag": LOCAL_DNS_PRIMARY_TAG,
                "server": LOCAL_DNS_PRIMARY_SERVER,
                "server_port": 53,
            },
            {
                "type": "udp",
                "tag": LOCAL_DNS_SECONDARY_TAG,
                "server": LOCAL_DNS_SECONDARY_SERVER,
                "server_port": 53,
            },
        ],
        "final": LOCAL_DNS_PRIMARY_TAG,
        "strategy": "prefer_ipv4",
        "reverse_mapping": True,
        "cache_capacity": 4096,
    }


def build_mihomo_dns_config() -> dict:
    return {
        "servers": [
            {
                "type": "udp",
                "tag": BOOTSTRAP_DNS_TAG,
                "server": BOOTSTRAP_DNS_SERVER,
                "server_port": 53,
            },
            {
                "type": "tcp",
                "tag": MIHOMO_DNS_TAG,
                "server": MIHOMO_SERVER,
                "server_port": MIHOMO_DNS_PORT,
                "detour": "lan-select",
            },
        ],
        "final": MIHOMO_DNS_TAG,
        "strategy": "prefer_ipv4",
        "reverse_mapping": True,
        "cache_capacity": 4096,
    }


def build_base_client_config(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    default_tunnel: str,
    route_address: list[str],
    route_rules: list[dict],
    final: str,
    dns_config: dict | None = None,
    default_domain_resolver: str | None = None,
    extra_outbounds: list[dict] | None = None,
) -> dict:
    outbounds = [
        build_selector_outbound(default_tunnel),
        build_vless_outbound(params, secrets_value, domain_resolver=default_domain_resolver),
        build_hy2_outbound(params, secrets_value, domain_resolver=default_domain_resolver),
    ]
    if extra_outbounds:
        outbounds.extend(extra_outbounds)
    outbounds.extend(
        [
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ]
    )
    config = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            build_tun_inbound(route_address),
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "rules": route_rules,
            "final": final,
        },
    }
    if dns_config:
        config["dns"] = dns_config
    if default_domain_resolver:
        config["route"]["default_domain_resolver"] = default_domain_resolver
    return config


def build_client_lan_config(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    default_tunnel: str = "vless-out",
) -> dict:
    return build_base_client_config(
        params,
        secrets_value,
        default_tunnel=default_tunnel,
        route_address=LAN_CIDRS,
        route_rules=LAN_ROUTE_RULES,
        final="direct",
        dns_config=build_lan_dns_config(),
        default_domain_resolver=BOOTSTRAP_DOMAIN_RESOLVER,
    )


def build_client_global_lan_config(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    default_tunnel: str = "vless-out",
) -> dict:
    return build_base_client_config(
        params,
        secrets_value,
        default_tunnel=default_tunnel,
        route_address=GLOBAL_ROUTE_CIDRS,
        route_rules=GLOBAL_ROUTE_RULES,
        final="lan-select",
        dns_config=build_global_dns_config(),
        default_domain_resolver=BOOTSTRAP_DOMAIN_RESOLVER,
    )


def build_client_global_vless_config(params: SingBoxParams, secrets_value: SingBoxSecrets) -> dict:
    return build_client_global_lan_config(params, secrets_value, default_tunnel="vless-out")


def build_client_global_mihomo_config(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    *,
    default_tunnel: str = "vless-out",
) -> dict:
    return build_base_client_config(
        params,
        secrets_value,
        default_tunnel=default_tunnel,
        route_address=GLOBAL_ROUTE_CIDRS,
        route_rules=GLOBAL_ROUTE_RULES,
        final="mihomo-out",
        dns_config=build_mihomo_dns_config(),
        default_domain_resolver=BOOTSTRAP_DOMAIN_RESOLVER,
        extra_outbounds=[
            {
                "type": "socks",
                "tag": "mihomo-out",
                "server": MIHOMO_SERVER,
                "server_port": MIHOMO_MIXED_PORT,
                "version": "5",
                "detour": "lan-select",
            },
        ],
    )


def build_client_config(params: SingBoxParams, secrets_value: SingBoxSecrets) -> dict:
    return build_client_lan_config(params, secrets_value)


def build_client_configs(params: SingBoxParams, secrets_value: SingBoxSecrets) -> dict[str, dict]:
    return {
        "vless-10": build_client_lan_config(params, secrets_value, default_tunnel="vless-out"),
        "vless-lan": build_client_global_lan_config(params, secrets_value, default_tunnel="vless-out"),
        "vless-mihomo": build_client_global_mihomo_config(params, secrets_value, default_tunnel="vless-out"),
        "hy2-10": build_client_lan_config(params, secrets_value, default_tunnel="hy2-out"),
        "hy2-lan": build_client_global_lan_config(params, secrets_value, default_tunnel="hy2-out"),
        "hy2-mihomo": build_client_global_mihomo_config(params, secrets_value, default_tunnel="hy2-out"),
    }


def write_json_file(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_summary_file(path: Path, params: SingBoxParams, secrets_value: SingBoxSecrets, paths: BundlePaths):
    summary = f"""sing-box tunnel bundle

server_domain: {params.server_domain}
vless_port: {params.vless_port}
hy2_port: {params.hy2_port}

uuid: {secrets_value.uuid}
reality_public_key: {secrets_value.reality_public_key}
reality_private_key: {secrets_value.reality_private_key}
reality_short_id: {secrets_value.reality_short_id}
hy2_password: {secrets_value.hy2_password}
hy2_obfs_password: {secrets_value.hy2_obfs_password}

server_config: {paths.server_config_path}
client_configs:
{format_client_config_summary(paths.client_config_paths)}
hy2_cert_path: {paths.hy2_cert_path}
hy2_key_path: {paths.hy2_key_path}

vless-10 / hy2-10: only routes {", ".join(LAN_CIDRS)}
vless-lan / hy2-lan: routes all traffic to the sing-box server LAN egress
vless-mihomo / hy2-mihomo: routes all traffic to {MIHOMO_SERVER}:{MIHOMO_MIXED_PORT} over the tunnel
"""
    path.write_text(summary, encoding="utf-8")


def format_client_config_summary(paths: dict[str, Path]) -> str:
    return "\n".join(f"  {name}: {path}" for name, path in paths.items())


def generate_self_signed_cert(domain: str, cert_path: Path, key_path: Path):
    if cert_path.exists() and key_path.exists():
        return

    require_command("openssl")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-subj",
            f"/CN={domain}",
            "-days",
            "36500",
        ]
    )
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)


def write_bundle(
    params: SingBoxParams,
    secrets_value: SingBoxSecrets,
    output_dir: Path,
    *,
    generate_cert: bool = False,
) -> BundlePaths:
    output_dir = output_dir.resolve()
    server_config_path = output_dir / SERVER_CONFIG_NAME
    client_config_paths = {
        name: output_dir / filename
        for name, filename in CLIENT_CONFIG_NAMES.items()
    }
    summary_path = output_dir / SUMMARY_NAME
    hy2_cert_path = output_dir / HY2_CERT_NAME
    hy2_key_path = output_dir / HY2_KEY_NAME

    paths = BundlePaths(
        server_config_path=server_config_path,
        client_config_paths=client_config_paths,
        summary_path=summary_path,
        hy2_cert_path=hy2_cert_path,
        hy2_key_path=hy2_key_path,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    if generate_cert:
        generate_self_signed_cert(params.server_domain, hy2_cert_path, hy2_key_path)

    server_config = build_server_config(
        params,
        secrets_value,
        cert_path=str(hy2_cert_path),
        key_path=str(hy2_key_path),
    )
    client_configs = build_client_configs(params, secrets_value)

    write_json_file(server_config_path, server_config)
    for name, client_config in client_configs.items():
        write_json_file(client_config_paths[name], client_config)
    write_summary_file(summary_path, params, secrets_value, paths)

    return paths


def prompt_text(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("[!] 不能为空")


def prompt_port(prompt: str, default: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default

        try:
            port = int(raw)
        except ValueError:
            print("[!] 端口必须是数字")
            continue

        if 1 <= port <= 65535:
            return port

        print("[!] 端口范围必须是 1-65535")


def normalize_domain(value: str) -> str:
    value = value.strip()
    value = re.sub(r"^https?://", "", value)
    return value.strip("/")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="生成 sing-box VLESS REALITY 与 Hysteria2 异地组网配置。")
    parser.add_argument("--domain", help="服务端域名或公网地址；未指定时交互输入")
    parser.add_argument("--vless-port", type=int, help="VLESS REALITY 监听端口；未指定时交互输入")
    parser.add_argument("--hy2-port", type=int, help="Hysteria2 监听端口；未指定时交互输入")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("."),
        help="输出目录，默认当前目录",
    )
    parser.add_argument(
        "--skip-cert",
        action="store_true",
        help="不生成 Hysteria2 自签证书，只写入配置文件",
    )
    return parser


def validate_port(port: int, name: str) -> int:
    if 1 <= port <= 65535:
        return port
    raise ValueError(f"{name} 端口范围必须是 1-65535")


def collect_params(args: argparse.Namespace) -> SingBoxParams:
    domain = normalize_domain(args.domain) if args.domain else normalize_domain(prompt_text("请输入服务端域名或公网地址: "))
    vless_port = args.vless_port if args.vless_port is not None else prompt_port("请输入 VLESS 监听端口", 8443)
    hy2_port = args.hy2_port if args.hy2_port is not None else prompt_port("请输入 Hysteria2 监听端口", 8444)
    return SingBoxParams(
        server_domain=domain,
        vless_port=validate_port(vless_port, "VLESS"),
        hy2_port=validate_port(hy2_port, "Hysteria2"),
    )


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        params = collect_params(args)
        secrets_value = generate_secrets()
        paths = write_bundle(
            params,
            secrets_value,
            args.output_dir,
            generate_cert=not args.skip_cert,
        )
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[!] 生成失败: {exc}", file=sys.stderr)
        return 1

    print(f"[+] 服务端配置: {paths.server_config_path}")
    print("[+] 客户端配置:")
    for name, path in paths.client_config_paths.items():
        print(f"    {name}: {path}")
    print(f"[+] 密钥摘要: {paths.summary_path}")
    print("[+] vless-* 默认使用 vless-out；hy2-* 默认使用 hy2-out")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
