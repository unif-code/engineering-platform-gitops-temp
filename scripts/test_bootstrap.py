from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / 'scripts/bootstrap/lib/common.sh'
HOST_CONFIG = ROOT / 'scripts/bootstrap/lib/host-config.sh'
PATH_FACTS = ROOT / 'scripts/bootstrap/lib/path-facts.sh'
EXEC_SAFETY = ROOT / 'scripts/bootstrap/lib/exec-safety.sh'
ARCHIVE_LIB = ROOT / 'scripts/bootstrap/lib/archive.sh'
KUBECTL_LIB = ROOT / 'scripts/bootstrap/lib/kubectl.sh'
HELM_LIB = ROOT / 'scripts/bootstrap/lib/helm.sh'
CIDR_CHECK = ROOT / 'scripts/bootstrap/check_cidrs.py'
# stage 路径的**唯一来源**。迁移到 stages/<NN-name>/run.sh 时只改这张表；
# 下面的常量、stage_names 与 stage_script() 全部由它派生，散落的字面量由
# test_stage_paths_come_from_one_table 挡住。
STAGE_SCRIPTS = {
    '00': 'scripts/bootstrap/stages/00-preflight/run.sh',
    '10': 'scripts/bootstrap/stages/10-stage-artifacts/run.sh',
    '20': 'scripts/bootstrap/stages/20-prepare-kernel/run.sh',
    '30': 'scripts/bootstrap/stages/30-install-containerd/run.sh',
    '40': 'scripts/bootstrap/stages/40-install-kubernetes/run.sh',
    '50': 'scripts/bootstrap/stages/50-kubeadm-init/run.sh',
    '60': 'scripts/bootstrap/stages/60-install-cilium/run.sh',
    '90': 'scripts/bootstrap/stages/90-verify/run.sh',
}
PREFLIGHT = ROOT / STAGE_SCRIPTS['00']
STAGE_ARTIFACTS = ROOT / STAGE_SCRIPTS['10']
PREPARE_KERNEL = ROOT / STAGE_SCRIPTS['20']
INSTALL_CONTAINERD = ROOT / STAGE_SCRIPTS['30']
INSTALL_KUBERNETES = ROOT / STAGE_SCRIPTS['40']
KUBEADM_INIT = ROOT / STAGE_SCRIPTS['50']
INSTALL_CILIUM = ROOT / STAGE_SCRIPTS['60']
FINAL_VERIFY = ROOT / STAGE_SCRIPTS['90']
BOOTSTRAP_ALL = ROOT / 'scripts/bootstrap/bootstrap-all.sh'
RUN_APPROVED = ROOT / 'scripts/bootstrap/run-approved.sh'

# 命令位置的完整枚举：行首、分隔符之后、复合命令关键字之后，再加上 `!`/`command`/
# `builtin` 这类可叠加的命令前缀。少一种写法就等于失败开放——那条 source 既不会被
# 展开校验，也不会被计入必须与门禁目录内容一致的集合。目标词不吃 `;&|`，一行里的
# 多条 source 才不会被第一条吞掉。
SHELL_SOURCE_STATEMENT = re.compile(
    r'(?:^|[;&|(){}]|\b(?:if|elif|then|else|while|until|do|time)\s)'
    r'(?:\s*(?:!|command|builtin)(?=\s))*'
    r'\s*(?:source|\.)\s+([^\s;&|]+)'
)
SHELL_DIRECTORY_ASSIGNMENT = re.compile(
    r'^[a-z_][a-z0-9_]*=\$\(cd .*&& pwd -P\)$'
)


def shell_source_words(text: str) -> list[str]:
    """收集脚本中每条 source/. 语句的目标词，整行注释不计入。"""
    words: list[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith('#'):
            continue
        words.extend(SHELL_SOURCE_STATEMENT.findall(line))
    return words


def shell_directory_assignments(text: str) -> list[str]:
    """收集脚本自身的目录推导赋值（cd … && pwd -P），保持原始顺序。"""
    return [
        line.strip()
        for line in text.splitlines()
        if SHELL_DIRECTORY_ASSIGNMENT.match(line.strip())
    ]


class BootstrapTestCase(unittest.TestCase):
    # mktemp 仍落在系统临时区（macOS 上是每用户目录）；TMPDIR 不在任何 stage 的
    # 不可信清单里，放行不影响守卫判定。白名单之外一律不进子进程环境。
    PRODUCTION_ENVIRONMENT_ALLOWLIST = ('TMPDIR',)

    # 敌意变量集从 stage 源码解析，不手工维护第二份名单。手写清单与 stage 的拒绝
    # 清单是两份要同步的东西，必然漂移——那正是本组用例要根治的缺陷形态，不能在
    # 更高一层重演。stage 拒绝 20 个具名变量与 5 组前缀通配，逐 stage 还不同。
    UNTRUSTED_GUARD_BLOCK = re.compile(r'for untrusted_name in ((?:.|\n)*?); do')
    UNTRUSTED_PREFIX = re.compile(r'\$\{!([A-Z_]+)@\}')

    @classmethod
    def untrusted_environment_guard(cls) -> tuple[frozenset[str], tuple[str, ...]]:
        """解析出 stage 拒绝的具名变量集合与前缀通配集合。

        返回两者而不是把前缀展开成示例名：判断"某个变量名会不会被 stage 拒绝"
        必须做前缀匹配。早先只返回示例名集合，于是拿它去和实际环境求交，
        PYTHONPATH 这种真实泄漏会漏判——集合里只有合成的 PYTHONPROBE。
        """
        names: set[str] = set()
        prefixes: set[str] = set()
        for script in sorted(ROOT / path for path in STAGE_SCRIPTS.values()):
            body = script.read_text(encoding='utf-8')
            for block in cls.UNTRUSTED_GUARD_BLOCK.findall(body):
                names.update(
                    re.findall(r'\b[A-Z][A-Z0-9_]+\b', block.replace('\\\n', ' '))
                )
            prefixes.update(cls.UNTRUSTED_PREFIX.findall(body))
        return frozenset(names), tuple(sorted(prefixes))

    @classmethod
    def environment_names_stages_reject(cls, seen: object) -> list[str]:
        """从一组变量名里挑出 stage 会判死的那些（具名命中或落在前缀通配内）。"""
        names, prefixes = cls.untrusted_environment_guard()
        return sorted(
            name for name in seen
            if name in names or any(name.startswith(p) for p in prefixes)
        )

    @classmethod
    def untrusted_environment_probe(cls) -> dict[str, str]:
        """把每个 stage 会拒绝的变量名各造一个探针值。

        前缀通配按 `<前缀>PROBE` 造名（`${!PYTHON@}` -> PYTHONPROBE），落在通配范围内。
        """
        names: set[str] = set()
        for script in sorted(ROOT / path for path in STAGE_SCRIPTS.values()):
            body = script.read_text(encoding='utf-8')
            for block in cls.UNTRUSTED_GUARD_BLOCK.findall(body):
                names.update(
                    re.findall(r'\b[A-Z][A-Z0-9_]+\b', block.replace('\\\n', ' '))
                )
            for prefix in cls.UNTRUSTED_PREFIX.findall(body):
                names.add(f'{prefix}PROBE')
        return {
            name: f'/tmp/unapproved-{name.lower()}' for name in sorted(names)
        }

    # 由 STAGE_SCRIPTS 派生的**相对 bootstrap 目录**路径。迁移后四个 stage 的文件名
    # 都是 run.sh，只取 name 会让 fixture 把四个写成同一个文件——真实布局是目录区分。
    stage_paths = {
        number: path.split('scripts/bootstrap/', 1)[1]
        for number, path in STAGE_SCRIPTS.items()
    }

    @staticmethod
    def library_source_pattern(library: str) -> str:
        """匹配「source 了某个共享库」，不钉锚点变量名。

        平铺 stage 用 ${script_dir}/lib/…，迁移进 stages/<NN-name>/run.sh 后用
        ${bootstrap_dir}/lib/…。锚点本身是否指向被门禁覆盖的那个目录，由
        BootstrapOrchestratorTest 的门禁前提用例逐条展开校验；这里再钉一次变量名
        只会让每次目录迁移都要重锚一批断言，却不增加任何捕获能力。
        """
        return (
            r'source "\$\{(?:script_dir|bootstrap_dir)\}/lib/'
            + re.escape(library) + '"'
        )

    @staticmethod
    def stage_script(stage: str) -> Path:
        """按编号取 stage 脚本路径；迁移目录时只有 STAGE_SCRIPTS 需要改。"""
        return ROOT / STAGE_SCRIPTS[stage]

    def temporary_directory(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    # 子进程环境一律从白名单起手构造，绝不整体继承调用者的 shell。stage 的不可信环境
    # 守卫按**名字前缀**判死（60/90 有 HELM_/PYTHON/OPENSSL_/KUBECTL_ 四组通配），
    # 「继承后再擦具名黑名单」原理上覆盖不了前缀，调用者 shell 里一个
    # PYTHONUNBUFFERED 就能让整个分片以 untrusted-environment-override 假红。
    def sanitized_environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            name: os.environ[name]
            for name in self.PRODUCTION_ENVIRONMENT_ALLOWLIST
            if name in os.environ
        }
        environment.update(overrides)
        return environment

    def run_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )

    HOST_TEMPLATE_DIR = ROOT / 'bootstrap/hosts/example-node'

    def write_fixture_host(
        self,
        hosts_root: Path,
        *,
        name: str = 'example-node',
        node_ip: str = '192.0.2.10',
        cluster_name: str = 'example-cluster',
        pod_cidr: str = '172.21.0.0/16',
        service_cidr: str = '172.20.0.0/16',
        swap_file: str = '/swap.img',
        swap_min: int = 4000000000,
        swap_max: int = 4400000000,
    ) -> Path:
        """按 example-node 的真实文件生成一台 fixture 主机目录。

        默认参数生成的文件与仓库文件逐字节相同，pins 因而也相同。"""
        host_dir = hosts_root / name
        host_dir.mkdir(parents=True)
        substitutions = (
            ('192.0.2.10', node_ip),
            ('example-node', name),
            ('example-cluster', cluster_name),
            ('172.21.0.0/16', pod_cidr),
            ('172.20.0.0/16', service_cidr),
        )
        for filename in ('kubeadm-init.yaml', 'cilium-values.yaml'):
            text = (self.HOST_TEMPLATE_DIR / filename).read_text(encoding='utf-8')
            for old, new in substitutions:
                text = text.replace(old, new)
            (host_dir / filename).write_text(text, encoding='utf-8')
        (host_dir / 'host.env').write_text(
            f'HOST_NAME={name}\n'
            f'HOST_NODE_IP={node_ip}\n'
            f'HOST_CLUSTER_NAME={cluster_name}\n'
            f'HOST_POD_CIDR={pod_cidr}\n'
            f'HOST_SERVICE_CIDR={service_cidr}\n'
            f'HOST_SWAP_FILE={swap_file}\n'
            f'HOST_SWAP_MIN_BYTES={swap_min}\n'
            f'HOST_SWAP_MAX_BYTES={swap_max}\n',
            encoding='utf-8',
        )
        (host_dir / 'pins.sha256').write_text(
            ''.join(
                hashlib.sha256((host_dir / filename).read_bytes()).hexdigest()
                + f'  {filename}\n'
                for filename in ('kubeadm-init.yaml', 'cilium-values.yaml')
            ),
            encoding='utf-8',
        )
        for entry in host_dir.iterdir():
            entry.chmod(0o644)
        host_dir.chmod(0o755)
        hosts_root.chmod(0o755)
        return host_dir

    def tree_snapshot(self, root: Path) -> dict[str, tuple[object, ...]]:
        snapshot: dict[str, tuple[object, ...]] = {}
        paths = [root]
        paths.extend(sorted(root.rglob('*')))
        for path in paths:
            relative = '.' if path == root else str(path.relative_to(root))
            stat_result = path.lstat()
            mode = stat_result.st_mode & 0o7777
            metadata = (stat_result.st_uid, stat_result.st_gid)
            if path.is_symlink():
                snapshot[relative] = (
                    'symlink', mode, metadata, os.readlink(path)
                )
            elif path.is_file():
                snapshot[relative] = (
                    'file', mode, metadata,
                    hashlib.sha256(path.read_bytes()).hexdigest()
                )
            elif path.is_dir():
                snapshot[relative] = ('directory', mode, metadata)
            else:
                snapshot[relative] = ('other', mode, metadata)
        return snapshot

    def admin_config_object(self) -> dict[str, object]:
        # 服务器实测形态：kubectl v1.36 省略空 preferences，cluster 与 context
        # 名称由 bootstrap/hosts/example-node/kubeadm-init.yaml 的 clusterName 决定。
        return {
            'apiVersion': 'v1',
            'kind': 'Config',
            'clusters': [
                {
                    'name': 'example-cluster',
                    'cluster': {
                        'server': 'https://192.0.2.10:6443',
                        'certificate-authority-data': 'Y2EtZml4dHVyZQ==',
                    },
                }
            ],
            'contexts': [
                {
                    'name': 'kubernetes-admin@example-cluster',
                    'context': {
                        'cluster': 'example-cluster',
                        'user': 'kubernetes-admin',
                    },
                }
            ],
            'current-context': 'kubernetes-admin@example-cluster',
            'users': [
                {
                    'name': 'kubernetes-admin',
                    'user': {
                        'client-certificate-data': 'Y2VydC1maXh0dXJl',
                        'client-key-data': 'a2V5LWZpeHR1cmU=',
                    },
                }
            ],
        }


class HostConfigTest(BootstrapTestCase):
    """lib/host-config.sh 的纯解析与目录合同边界。"""

    VALID_HOST_ENV = (
        '# fixture\n'
        'HOST_NAME=example-node\n'
        'HOST_NODE_IP=192.0.2.10\n'
        '\n'
        'HOST_CLUSTER_NAME=example-cluster\n'
        'HOST_POD_CIDR=172.21.0.0/16\n'
        'HOST_SERVICE_CIDR=172.20.0.0/16\n'
        'HOST_SWAP_FILE=/swap.img\n'
        'HOST_SWAP_MIN_BYTES=4000000000\n'
        'HOST_SWAP_MAX_BYTES=4400000000\n'
    )

    def run_parse(
        self, content: str = '', *, path: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        """path 为空时把 content 写进临时 host.env；否则直接解析给定文件。"""
        if path is None:
            directory = self.temporary_directory()
            target = directory / 'host.env'
            target.write_bytes(content.encode('utf-8'))
        else:
            target = path
        body = (
            'set -u\n'
            'if host_env_parse "$2"; then\n'
            '  printf "%s|%s|%s|%s|%s|%s|%s|%s\\n" '
            '"$HOST_NAME" "$HOST_NODE_IP" "$HOST_CLUSTER_NAME" '
            '"$HOST_POD_CIDR" "$HOST_SERVICE_CIDR" "$HOST_SWAP_FILE" '
            '"$HOST_SWAP_MIN_BYTES" "$HOST_SWAP_MAX_BYTES"\n'
            'else\n'
            '  printf "ERROR=%s\\n" "$HOST_CONFIG_ERROR"\n'
            '  exit 1\n'
            'fi\n'
        )
        return self.run_command(
            ['/bin/bash', '-c', f'source "$1"\n{body}', 'test-host-config',
             str(HOST_CONFIG), str(target)],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
        )

    def test_parse_accepts_comments_blank_lines_and_exact_key_set(self) -> None:
        result = self.run_parse(self.VALID_HOST_ENV)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'example-node|192.0.2.10|example-cluster|'
            '172.21.0.0/16|172.20.0.0/16|/swap.img|4000000000|4400000000\n',
        )

    def test_parse_rejects_every_invalid_shape(self) -> None:
        valid = self.VALID_HOST_ENV
        cases = {
            'missing-key': valid.replace('HOST_SWAP_FILE=/swap.img\n', ''),
            'extra-key': valid + 'HOST_EXTRA=1\n',
            'unknown-key': valid.replace('HOST_NAME=', 'HOSTNAME='),
            'duplicate-key': valid + 'HOST_NODE_IP=192.0.2.10\n',
            'quoted-value': valid.replace(
                'HOST_SWAP_FILE=/swap.img', 'HOST_SWAP_FILE="/swap.img"'
            ),
            'space-in-value': valid.replace(
                'HOST_SWAP_FILE=/swap.img', 'HOST_SWAP_FILE=/swap img'
            ),
            'dollar-in-value': valid.replace(
                'HOST_SWAP_FILE=/swap.img', 'HOST_SWAP_FILE=/$HOME/swap.img'
            ),
            'backtick-in-value': valid.replace(
                'HOST_CLUSTER_NAME=example-cluster',
                'HOST_CLUSTER_NAME=`id`',
            ),
            'crlf': valid.replace('\n', '\r\n'),
            'no-trailing-newline': valid.rstrip('\n'),
            'empty-file': '',
            'bad-ip-octet': valid.replace('192.0.2.10', '192.0.2.256'),
            'bad-ip-leading-zero': valid.replace('192.0.2.10', '0192.0.2.10'),
            'bad-ip-shape': valid.replace('192.0.2.10', '192.0.2'),
            'bad-cidr-prefix': valid.replace('172.21.0.0/16', '172.21.0.0/33'),
            'bad-cidr-no-prefix': valid.replace('172.21.0.0/16', '172.21.0.0'),
            'uppercase-hostname': valid.replace(
                'HOST_NAME=example-node', 'HOST_NAME=Retail'
            ),
            'hostname-trailing-dash': valid.replace(
                'HOST_NAME=example-node', 'HOST_NAME=retail-'
            ),
            'relative-swap-path': valid.replace(
                'HOST_SWAP_FILE=/swap.img', 'HOST_SWAP_FILE=swap.img'
            ),
            'dotdot-swap-path': valid.replace(
                'HOST_SWAP_FILE=/swap.img', 'HOST_SWAP_FILE=/../swap.img'
            ),
            'swap-min-not-numeric': valid.replace(
                'HOST_SWAP_MIN_BYTES=4000000000', 'HOST_SWAP_MIN_BYTES=4G'
            ),
            'swap-min-zero': valid.replace(
                'HOST_SWAP_MIN_BYTES=4000000000', 'HOST_SWAP_MIN_BYTES=0'
            ),
            'swap-min-not-below-max': valid.replace(
                'HOST_SWAP_MAX_BYTES=4400000000', 'HOST_SWAP_MAX_BYTES=4000000000'
            ),
        }
        for name, content in cases.items():
            with self.subTest(case=name):
                result = self.run_parse(content)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stdout, 'ERROR=host-config-invalid\n')

    def test_shipped_host_env_parses_with_bash_loader(self) -> None:
        """仓库里发货的 host.env 必须被 bash 解析器逐值接受。"""
        result = self.run_parse(path=self.HOST_TEMPLATE_DIR / 'host.env')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'example-node|192.0.2.10|example-cluster|'
            '172.21.0.0/16|172.20.0.0/16|/swap.img|4000000000|4400000000\n',
        )

    def test_load_reports_unreadable_hostname(self) -> None:
        """hostname 读不出来时必须是 hostname-unreadable，不得降级成其他 reason。"""
        directory = self.temporary_directory()
        hosts_root = directory / 'hosts'
        hosts_root.mkdir()
        self.write_fixture_host(hosts_root)
        fake_bin = directory / 'bin'
        fake_bin.mkdir()
        fake_hostname = fake_bin / 'hostname'
        fake_hostname.write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
        fake_hostname.chmod(0o755)
        body = (
            'set -u\n'
            'if load_host_config; then\n'
            '  printf "LOADED=%s\\n" "$HOST_NAME"\n'
            'else\n'
            '  printf "ERROR=%s\\n" "$HOST_CONFIG_ERROR"\n'
            '  exit 1\n'
            'fi\n'
        )

        result = self.run_command(
            ['/bin/bash', '-c', f'source "$1"\n{body}', 'test-host-config',
             str(HOST_CONFIG)],
            env={
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'LC_ALL': 'C',
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_HOSTS_DIR': str(hosts_root),
            },
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'ERROR=hostname-unreadable\n')

    def test_stage_scripts_contain_no_host_literals(self) -> None:
        """主机身份只能出现在 bootstrap/hosts/ 与测试文件里。"""
        forbidden = (
            '192.0.2.10', 'example-node', 'example-cluster',
            'CONFIG_SHA256=e', 'VALUES_SHA256=1', 'EXPECTED_HOSTNAME=',
            'EXPECTED_NODE_IP=', 'EXPECTED_NODE=', '/swap.img',
            '4000000000', '4400000000', '172.20.0.0/16', '172.21.0.0/16',
        )
        # 递归收集：新增子目录或新脚本自动纳入，不依赖手写清单。
        scripts = (
            sorted((ROOT / 'scripts/bootstrap').rglob('*.sh'))
            + sorted((ROOT / 'scripts/bootstrap').rglob('*.py'))
        )
        self.assertGreaterEqual(len(scripts), 18, scripts)
        for script in scripts:
            text = script.read_text(encoding='utf-8')
            for literal in forbidden:
                with self.subTest(script=script.name, literal=literal):
                    self.assertNotIn(literal, text)

    def test_only_host_directories_carry_host_identity(self) -> None:
        for path in sorted((ROOT / 'bootstrap').rglob('*')):
            relative = path.relative_to(ROOT / 'bootstrap')
            if not path.is_file() or relative.parts[0] == 'hosts':
                continue
            with self.subTest(path=str(relative)):
                self.assertNotIn(
                    '192.0.2.10', path.read_text(encoding='utf-8', errors='ignore')
                )


class CommonLibraryTest(BootstrapTestCase):
    def run_common(self, body: str) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', '-c', f'source "$1"\n{body}', 'test-common', str(COMMON)]
        )

    def test_parse_mode_defaults_to_check(self) -> None:
        result = self.run_common('parse_mode\nprintf "%s\\n" "$MODE"')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'CHECK\n')

    def test_parse_mode_accepts_only_explicit_apply(self) -> None:
        apply_result = self.run_common(
            'parse_mode --apply\nprintf "%s\\n" "$MODE"'
        )
        invalid_result = self.run_common('parse_mode --force')

        self.assertEqual(apply_result.returncode, 0, apply_result.stderr)
        self.assertEqual(apply_result.stdout, 'APPLY\n')
        self.assertEqual(invalid_result.returncode, 10)

    def test_managed_file_reports_all_three_states(self) -> None:
        directory = self.temporary_directory()
        source = directory / 'source'
        target = directory / 'target'
        source.write_text('approved\n', encoding='utf-8')

        missing = self.run_common(
            f'managed_file_state "{source}" "{target}"'
        )
        target.write_text('approved\n', encoding='utf-8')
        compliant = self.run_common(
            f'managed_file_state "{source}" "{target}"'
        )
        target.write_text('unknown\n', encoding='utf-8')
        unknown = self.run_common(
            f'managed_file_state "{source}" "{target}"'
        )

        self.assertEqual(missing.stdout, 'MISSING\n')
        self.assertEqual(compliant.stdout, 'COMPLIANT\n')
        self.assertEqual(unknown.stdout, 'UNKNOWN\n')

    def test_install_managed_file_refuses_unknown_target(self) -> None:
        directory = self.temporary_directory()
        source = directory / 'source'
        target = directory / 'target'
        source.write_text('approved\n', encoding='utf-8')
        target.write_text('unknown\n', encoding='utf-8')

        result = self.run_common(
            f'install_managed_file "{source}" "{target}" 0644'
        )

        self.assertEqual(result.returncode, 30)
        self.assertEqual(target.read_text(encoding='utf-8'), 'unknown\n')

    def test_open_evidence_never_overwrites_existing_file(self) -> None:
        directory = self.temporary_directory()
        evidence = directory / '07-preflight-20260810T000000Z.txt'
        evidence.write_text('preserve\n', encoding='utf-8')

        result = self.run_common(
            f'open_evidence 07-preflight "{directory}" 20260810T000000Z'
        )

        self.assertEqual(result.returncode, 30)
        self.assertEqual(evidence.read_text(encoding='utf-8'), 'preserve\n')

    def test_stage_paths_come_from_one_table(self) -> None:
        """stage 路径必须只有 STAGE_SCRIPTS 一个来源。

        目录迁移（stages/<NN-name>/run.sh）时，散落在别处的路径字面量会被漏改，
        而漏改的症状往往是「枚举型断言静默通过 0 个文件」——恒绿而非判红。
        """
        self.assertEqual(
            sorted(STAGE_SCRIPTS),
            ['00', '10', '20', '30', '40', '50', '60', '90'],
        )
        for number in STAGE_SCRIPTS:
            with self.subTest(stage=number):
                path = self.stage_script(number)
                self.assertTrue(path.is_file(), path)
                self.assertFalse(path.is_symlink(), path)
                self.assertTrue(os.access(path, os.X_OK), path)

        # 交叉校验：表必须与编排器 stage_path() 的映射逐条一致。没有这一条，
        # 「测试从表枚举、断言又拿表比」就退化成恒真——账本 R5 警告的正是这个。
        orchestrator = BOOTSTRAP_ALL.read_text(encoding='utf-8')
        mapping = dict(
            re.findall(
                r"^    ([0-9]{2})\) printf '%s/(\S+)\\n' \"\$stage_dir\" ;;$",
                orchestrator,
                re.M,
            )
        )
        self.assertEqual(
            mapping,
            {
                number: path.split('scripts/bootstrap/', 1)[1]
                for number, path in STAGE_SCRIPTS.items()
            },
            '测试的 STAGE_SCRIPTS 与编排器 stage_path() 不一致',
        )

        source = (ROOT / 'scripts/test_bootstrap.py').read_text(encoding='utf-8')
        lines = source.splitlines()
        start = lines.index('STAGE_SCRIPTS = {')
        end = next(i for i in range(start, len(lines)) if lines[i] == '}')
        pattern = re.compile(r'bootstrap/[0-9]{2}-')
        offenders = [
            number
            for number, line in enumerate(lines, 1)
            if pattern.search(line) and not start < number - 1 < end
        ]
        self.assertEqual(offenders, [], '这些行绕过了 STAGE_SCRIPTS 表')

    def test_every_stage_delegates_host_path_and_complete(self) -> None:
        """八个 stage 曾各留一份 host_path 与 complete，必须只保留共享库那一份。

        complete 有四种形态，其中 **stage 10 是唯一不委托 finish_phase 的**：它内联
        打印并硬编码 EVIDENCE=NONE / SHA256=NONE。统一为委托的前提已核实——stage 10
        从不调用 open_evidence，而 finish_phase 在未开证据文件时输出的字段与顺序和那份
        内联版本逐字段一致，因此统一不改变任何一个 stage 的输出（由各 stage 既有的
        完成块断言继续把关）。
        """
        shared = COMMON.read_text(encoding='utf-8')
        for declaration in ('host_path()', 'complete()'):
            self.assertEqual(shared.count(declaration), 1, declaration)
        # next 取更宽松的默认值，其余七个 stage 总是传参，不受影响。
        self.assertIn('local result=$1 reason=$2 code=$3 next=${4:-NONE}', shared)
        self.assertIn('finish_phase "$result" "$reason" "$code" "$next"', shared)

        # 走表而非通配：迁移后 `[0-9]*.sh` 只剩尚未迁移的那几个，枚举会静默变少。
        stages = sorted(ROOT / path for path in STAGE_SCRIPTS.values())
        self.assertEqual(len(stages), 8, [str(s) for s in stages])
        for stage in stages:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                for declaration in ('host_path()', 'complete()'):
                    self.assertNotIn(declaration + ' {', body, declaration)
                self.assertRegex(
                    body, self.library_source_pattern('common.sh')
                )
                # 内联版本独有的硬编码字段不得残留在任何 stage 里。
                self.assertNotIn("printf 'EVIDENCE=NONE\\n", body)

    def test_kubernetes_stages_share_kubelet_default_validator(self) -> None:
        shared = ROOT / 'scripts/bootstrap/lib/kubelet-default.sh'
        self.assertTrue(shared.is_file(), 'shared kubelet validator is missing')

        shared_source = shared.read_text(encoding='utf-8')
        stage40 = INSTALL_KUBERNETES.read_text(encoding='utf-8')
        stage50 = KUBEADM_INIT.read_text(encoding='utf-8')
        static = (ROOT / 'scripts/validate-static.sh').read_text(
            encoding='utf-8'
        )
        # 硬编码 source 字面量之一（其余在本类的 facts_source_line、
        # PathFactsTest 与 ExecSafetyTest）：Task 10 迁移 stage 40/50 后
        # ${script_dir} 语义改变，所有这类字面量必须一起改。
        source_line = self.library_source_pattern('kubelet-default.sh')
        call = (
            'kubelet_default_conffile_is_pristine '
            '"$(host_path /etc/default/kubelet)"'
        )

        self.assertRegex(stage40, source_line)
        self.assertRegex(stage50, source_line)
        self.assertIn(call, stage40)
        self.assertIn(call, stage50)
        combined = shared_source + stage40 + stage50
        for declaration in (
            'readonly KUBELET_DEFAULT_CONTENT=',
            'readonly KUBELET_DEFAULT_SIZE=',
            'readonly KUBELET_DEFAULT_SHA256=',
            'readonly KUBELET_DEFAULT_MD5=',
            'kubelet_registered_default_md5()',
            'kubelet_default_conffile_is_pristine()',
        ):
            self.assertEqual(combined.count(declaration), 1, declaration)
            self.assertIn(declaration, shared_source)
        self.assertNotIn('kubelet_operator_override_is_pristine()', stage40)
        self.assertNotIn('[[ -s "$default_file" ]]', stage50)
        # validator 调用的路径事实谓词由共享库提供，两个消费 stage 都必须 source 它。
        # 硬编码 source 字面量之一：本行、上面 kubelet-default.sh 的那条、
        # PathFactsTest 里的同源行，以及 ExecSafetyTest 的两条。Task 10 把 stage
        # 挪进 stages/<NN-name>/run.sh 后 ${script_dir} 语义改变，全部要一起改。
        facts_source_line = self.library_source_pattern('path-facts.sh')
        facts_source = PATH_FACTS.read_text(encoding='utf-8')
        self.assertRegex(stage40, facts_source_line)
        self.assertRegex(stage50, facts_source_line)
        for predicate in ('path_mode', 'path_size', 'owned_by_expected'):
            self.assertIn(f'{predicate} ', shared_source, predicate)
            self.assertIn(f'{predicate}()', facts_source, predicate)
            self.assertNotIn(f'{predicate}()', stage40, predicate)
            self.assertNotIn(f'{predicate}()', stage50, predicate)
        # 重锚：由「断言那两行通配的字面量」改为断言**覆盖面**——静态门禁必须把
        # 每一个已跟踪的 bootstrap shell 脚本都交给 shellcheck。写死通配在 stage
        # 迁进子目录后会静默漏检，而漏检不会报错，只会安静地不再守。
        self.assertIn("find \"$repo_root/scripts/bootstrap\"", static)
        self.assertIn('-exec shellcheck {} +', static)
        covered = sorted(
            path.relative_to(ROOT)
            for path in (ROOT / 'scripts/bootstrap').rglob('*.sh')
        )
        expected = sorted(
            Path(path) for path in STAGE_SCRIPTS.values()
        )
        for stage_path in expected:
            self.assertIn(stage_path, covered, stage_path)


class ShellSourceStatementTest(BootstrapTestCase):
    """source 语句识别正则本身的分类契约。

    门禁前提的两条断言（真实 stage 只 source 门禁目录内的文件、lib 只 source
    兄弟库）都以这条正则作为唯一入口，漏识别一种写法就等于失败开放：那条 source
    既不会被展开校验，也不会被计入必须与门禁目录内容一致的集合。仓库今天没有下面
    这些复合形态，这个用例负责让它们无法在未被识别的情况下混进来。"""

    MATCHING = (
        ('source /lib/plain.sh', ['/lib/plain.sh']),
        ('  . /lib/dot.sh', ['/lib/dot.sh']),
        ('source "${script_dir}/lib/quoted.sh"',
         ['"${script_dir}/lib/quoted.sh"']),
        ('if source /lib/if.sh; then :; fi', ['/lib/if.sh']),
        ('if ! source /lib/negated-if.sh; then :; fi',
         ['/lib/negated-if.sh']),
        ('elif source /lib/elif.sh; then :; fi', ['/lib/elif.sh']),
        ('while . /lib/while.sh; do :; done', ['/lib/while.sh']),
        ('until source /lib/until.sh; do :; done', ['/lib/until.sh']),
        ('! source /lib/negated.sh', ['/lib/negated.sh']),
        ('command source /lib/command.sh', ['/lib/command.sh']),
        ('builtin . /lib/builtin.sh', ['/lib/builtin.sh']),
        ('time source /lib/time.sh', ['/lib/time.sh']),
        ('then source /lib/then.sh', ['/lib/then.sh']),
        ('else source /lib/else.sh', ['/lib/else.sh']),
        ('do source /lib/do.sh', ['/lib/do.sh']),
        ('probe && source /lib/and.sh', ['/lib/and.sh']),
        ('probe || . /lib/or.sh', ['/lib/or.sh']),
        ('probe; source /lib/semicolon.sh', ['/lib/semicolon.sh']),
        ('probe | source /lib/pipe.sh', ['/lib/pipe.sh']),
        ('{ source /lib/brace.sh; }', ['/lib/brace.sh']),
        ('( . /lib/subshell.sh )', ['/lib/subshell.sh']),
        ('probe "$(source /lib/substitution.sh)"',
         ['/lib/substitution.sh)"']),
        ('source /lib/first.sh; source /lib/second.sh',
         ['/lib/first.sh', '/lib/second.sh']),
    )

    NON_MATCHING = (
        '# source /lib/whole-line-comment.sh',
        'probe --flag # source /lib/trailing-comment.sh',
        'message="use source with care"',
        "printf 'source of truth'",
        'resource /lib/prefix-word.sh',
        'my_source /lib/suffix-word.sh',
        'sourced=1',
        './lib/relative.sh',
        'cd ..',
        'probe --source /lib/long-flag.sh',
        'echo sources',
    )

    def test_every_command_position_source_form_is_recognised(self) -> None:
        """命令位置上的每种 source/. 写法都必须被识别并取到目标词。"""
        for line, expected in self.MATCHING:
            with self.subTest(line=line):
                self.assertEqual(shell_source_words(line), expected)

    def test_source_lookalikes_are_not_recognised(self) -> None:
        """注释、字符串与同形词不得被误判成 source 语句。"""
        for line in self.NON_MATCHING:
            with self.subTest(line=line):
                self.assertEqual(shell_source_words(line), [])


class PathFactsTest(BootstrapTestCase):
    """lib/path-facts.sh 的路径事实谓词与其测试缝。"""

    STAGES = (
        PREPARE_KERNEL,
        INSTALL_CONTAINERD,
        INSTALL_KUBERNETES,
        KUBEADM_INIT,
        INSTALL_CILIUM,
        FINAL_VERIFY,
    )

    def run_facts(
        self, body: str, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """在干净环境里 source lib 后执行 body，位置参数从 $1 开始。"""
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        environment.update(env or {})
        return self.run_command(
            [
                '/bin/bash',
                '-c',
                f'set -u\nsource "$0"\n{body}',
                str(PATH_FACTS),
                *arguments,
            ],
            env=environment,
        )

    def test_path_facts_report_owner_mode_and_size(self) -> None:
        """三个机械谓词必须复述 stat 的属主、八进制权限与字节数。"""
        directory = self.temporary_directory()
        target = directory / 'probe'
        target.write_bytes(b'0123456789')
        target.chmod(0o640)

        result = self.run_facts(
            'path_owner "$1"\npath_mode "$1"\npath_size "$1"', str(target)
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, f'{os.getuid()}:{os.getgid()}\n640\n10\n'
        )

    def test_path_facts_fail_on_missing_path(self) -> None:
        """缺失路径必须失败而不是打印空事实。"""
        directory = self.temporary_directory()
        missing = directory / 'absent'

        for predicate in ('path_owner', 'path_mode', 'path_size'):
            with self.subTest(predicate=predicate):
                result = self.run_facts(f'{predicate} "$1"', str(missing))

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_owned_by_expected_demands_root_outside_test_mode(self) -> None:
        """没有 BOOTSTRAP_TEST_MODE 时期望值恒为 0:0，非 root 拥有的路径必须判否。"""
        directory = self.temporary_directory()
        target = directory / 'probe'
        target.write_text('x', encoding='utf-8')

        result = self.run_facts('owned_by_expected "$1"', str(target))

        self.assertEqual(result.returncode, 1, result.stderr)

    def test_owned_by_expected_honours_both_drift_seams(self) -> None:
        """并集实现必须同时支持即时漂移与标记触发的延迟漂移。"""
        directory = self.temporary_directory()
        target = directory / 'probe'
        target.write_text('x', encoding='utf-8')
        other = directory / 'other'
        other.write_text('x', encoding='utf-8')
        marker = directory / 'marker'
        body = (
            'owned_by_expected "$1" && echo BASELINE_OK\n'
            'BOOTSTRAP_TEST_OWNER_DRIFT_PATH="$1" owned_by_expected "$1" ||\n'
            '  echo IMMEDIATE_DRIFT\n'
            'BOOTSTRAP_TEST_OWNER_DRIFT_PATH="$2" owned_by_expected "$1" &&\n'
            '  echo IMMEDIATE_UNRELATED_OK\n'
            'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH="$1" '
            'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER="$3" '
            'owned_by_expected "$1" && echo DEFERRED_INACTIVE\n'
            ': >"$3"\n'
            'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH="$1" '
            'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER="$3" '
            'owned_by_expected "$1" || echo DEFERRED_ACTIVE\n'
            'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH="$2" '
            'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER="$3" '
            'owned_by_expected "$1" && echo DEFERRED_UNRELATED_OK\n'
        )

        result = self.run_facts(
            body,
            str(target),
            str(other),
            str(marker),
            env={'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'BASELINE_OK\nIMMEDIATE_DRIFT\nIMMEDIATE_UNRELATED_OK\n'
            'DEFERRED_INACTIVE\nDEFERRED_ACTIVE\nDEFERRED_UNRELATED_OK\n',
        )

    def test_drift_seams_stay_inert_without_test_mode(self) -> None:
        """两条测试缝都不得在 BOOTSTRAP_TEST_MODE 之外改变判定。"""
        directory = self.temporary_directory()
        user_owned = directory / 'probe'
        user_owned.write_text('x', encoding='utf-8')
        marker = directory / 'marker'
        marker.write_text('x', encoding='utf-8')
        # 根目录在 macOS 与 Linux 上都是 0:0，正好等于生产期望值，基线判真；
        # 缝一旦泄漏到 BOOTSTRAP_TEST_MODE 之外就把期望抬成 1:0，判定会翻成假。
        # 只有这个属主为 root 的探针能杀掉泄漏变异，用户自有的探针基线本就判假。
        root_owned = Path('/')

        probes = (
            ('root-owned', root_owned, '0\n'),
            ('user-owned', user_owned, '1\n'),
        )
        for probe_name, probe, expected in probes:
            seams = {
                'immediate': {'BOOTSTRAP_TEST_OWNER_DRIFT_PATH': str(probe)},
                'deferred': {
                    'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH': str(probe),
                    'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER': str(marker),
                },
            }
            for name, seam in seams.items():
                with self.subTest(probe=probe_name, seam=name):
                    baseline = self.run_facts(
                        'owned_by_expected "$1"; printf "%s\\n" "$?"',
                        str(probe),
                    )
                    seamed = self.run_facts(
                        'owned_by_expected "$1"; printf "%s\\n" "$?"',
                        str(probe),
                        env=seam,
                    )

                    self.assertEqual(
                        baseline.stdout, expected, baseline.stderr
                    )
                    self.assertEqual(
                        seamed.stdout, baseline.stdout, seamed.stderr
                    )

    def test_every_stage_delegates_path_facts_to_the_shared_library(
        self,
    ) -> None:
        """六个 stage 必须只 source 共享库，不得保留本地副本。"""
        self.assertNotEqual(os.geteuid(), 0, '该用例必须由实际非 root 用户运行')
        self.assertTrue(PATH_FACTS.is_file(), 'lib/path-facts.sh is missing')
        self.assertFalse(PATH_FACTS.is_symlink())

        shared = PATH_FACTS.read_text(encoding='utf-8')
        # 与 CommonLibraryTest 里的 facts_source_line 同源的硬编码字面量：
        # Task 10 把 stage 挪进目录后 ${script_dir} 语义改变，连同
        # kubelet-default.sh 那条与 ExecSafetyTest 的两条，必须一起改。
        source_line = self.library_source_pattern('path-facts.sh')
        declarations = (
            'path_owner()',
            'path_mode()',
            'path_size()',
            'owned_by_expected()',
        )
        for declaration in declarations:
            self.assertIn(declaration, shared, declaration)

        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertRegex(body, source_line)
                self.assertIn(
                    'for test_override in "${!BOOTSTRAP_TEST_@}"',
                    body,
                    '生产守卫的前缀通配必须保留',
                )
                for declaration in declarations:
                    self.assertNotIn(declaration, body, declaration)

    def test_shared_library_carries_the_union_of_the_test_seams(self) -> None:
        """测试缝只允许在共享库里出现一次，stage 不得各自留一份。"""
        shared = PATH_FACTS.read_text(encoding='utf-8')
        seams = (
            'BOOTSTRAP_TEST_OWNER_DRIFT_PATH',
            'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH',
            'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER',
        )
        for seam in seams:
            with self.subTest(seam=seam):
                self.assertEqual(shared.count(seam), 1, seam)
                for stage in self.STAGES:
                    self.assertNotIn(
                        seam,
                        stage.read_text(encoding='utf-8'),
                        f'{stage.name} 仍保留 {seam}',
                    )


class ExecSafetyTest(BootstrapTestCase):
    """lib/exec-safety.sh 的受控执行与路径安全谓词。"""

    STAGES = (INSTALL_CILIUM, FINAL_VERIFY)

    def run_exec_safety(
        self, body: str, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """只 source exec-safety.sh 后执行 body，位置参数从 $1 开始。

        故意不 source path-facts.sh：safe_file/safe_directory 用到的 path_mode 与
        owned_by_expected 必须由本库自己带进来，否则这里的每个用例都会以
        command not found 变红。"""
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        environment.update(env or {})
        return self.run_command(
            [
                '/bin/bash',
                '-c',
                f'set -u\nsource "$0"\n{body}',
                str(EXEC_SAFETY),
                *arguments,
            ],
            env=environment,
        )

    def recorder(self, directory: Path, name: str, body: str) -> Path:
        """写一个复述自身参数的可执行探针，用来观察谓词实际发出的命令行。"""
        path = directory / name
        path.write_text(f'#!/bin/sh\n{body}\n', encoding='utf-8')
        path.chmod(0o755)
        return path

    def probe_tree(self) -> dict[str, Path]:
        """一棵覆盖类型、模式、符号链接三个维度的探针树。"""
        directory = self.temporary_directory()
        paths = {
            'directory': directory / 'tight-dir',
            'loose_directory': directory / 'loose-dir',
            'directory_link': directory / 'dir-link',
            'file': directory / 'tight-file',
            'loose_file': directory / 'loose-file',
            'file_link': directory / 'file-link',
            'missing': directory / 'absent',
            'spare': directory / 'spare',
        }
        paths['directory'].mkdir()
        paths['directory'].chmod(0o700)
        paths['loose_directory'].mkdir()
        paths['loose_directory'].chmod(0o755)
        paths['directory_link'].symlink_to(paths['directory'])
        paths['file'].write_text('x', encoding='utf-8')
        paths['file'].chmod(0o600)
        paths['loose_file'].write_text('x', encoding='utf-8')
        paths['loose_file'].chmod(0o644)
        paths['file_link'].symlink_to(paths['file'])
        return paths

    def test_python_isolated_runs_the_pinned_interpreter_in_isolation(
        self,
    ) -> None:
        """解释器必须是 stage 钉死的那个绝对路径，且始终带 -I -B。"""
        directory = self.temporary_directory()
        fake_python = self.recorder(
            directory, 'fake-python', "printf 'ARGV=%s\\n' \"$*\""
        )

        result = self.run_exec_safety(
            f'PYTHON_BINARY="{fake_python!s}"\n'
            'python_isolated -c "import sys" extra'
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'ARGV=-I -B -c import sys extra\n')

    def test_tar_safe_runs_the_pinned_tar_without_inherited_options(
        self,
    ) -> None:
        """继承来的 TAR_OPTIONS 必须被清空，否则解包参数可被环境改写。"""
        directory = self.temporary_directory()
        fake_tar = self.recorder(
            directory,
            'fake-tar',
            "printf 'OPTIONS=[%s] ARGV=%s\\n' \"${TAR_OPTIONS-unset}\" \"$*\"",
        )

        result = self.run_exec_safety(
            f'TAR_BINARY="{fake_tar!s}"\ntar_safe -xOf archive member',
            env={'TAR_OPTIONS': '--to-command=/bin/sh'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, 'OPTIONS=[] ARGV=-xOf archive member\n'
        )

    def test_controlled_execution_fails_closed_without_the_pinned_binaries(
        self,
    ) -> None:
        """PYTHON_BINARY/TAR_BINARY 缺失时必须报未绑定变量，不得退回 PATH。"""
        marker = self.temporary_directory()
        for predicate, decoy in (
            ('python_isolated -c "pass"', 'python3'),
            ('tar_safe --version', 'tar'),
        ):
            with self.subTest(predicate=predicate):
                self.recorder(
                    marker, decoy, f"printf 'PATH_FALLBACK_{decoy}\\n'"
                )

                result = self.run_exec_safety(
                    predicate, env={'PATH': f'{marker}:/usr/bin:/bin'}
                )

                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('PATH_FALLBACK', result.stdout)
                self.assertIn('unbound variable', result.stderr)

    def test_safe_file_demands_regular_file_mode_and_owner(self) -> None:
        """四项检查各自都必须能单独判否：类型、模式、属主，以及缺失路径。"""
        paths = self.probe_tree()
        body = (
            'safe_file "$1" 600 && echo REGULAR_ACCEPTED\n'
            'safe_file "$2" 755 || echo DIRECTORY_REJECTED\n'
            'safe_file "$3" 600 || echo WRONG_MODE_REJECTED\n'
            'BOOTSTRAP_TEST_OWNER_DRIFT_PATH="$1" safe_file "$1" 600 ||\n'
            '  echo WRONG_OWNER_REJECTED\n'
            'safe_file "$4" 600 || echo MISSING_REJECTED\n'
        )

        result = self.run_exec_safety(
            body,
            str(paths['file']),
            str(paths['loose_directory']),
            str(paths['loose_file']),
            str(paths['missing']),
            env={'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'REGULAR_ACCEPTED\nDIRECTORY_REJECTED\nWRONG_MODE_REJECTED\n'
            'WRONG_OWNER_REJECTED\nMISSING_REJECTED\n',
        )

    def test_safe_directory_demands_directory_mode_and_owner(self) -> None:
        """目录判定同样要能单独判否：普通文件、错模式、错属主、缺失路径。"""
        paths = self.probe_tree()
        body = (
            'safe_directory "$1" 700 && echo DIRECTORY_ACCEPTED\n'
            'safe_directory "$2" 600 || echo REGULAR_FILE_REJECTED\n'
            'safe_directory "$3" 700 || echo WRONG_MODE_REJECTED\n'
            'BOOTSTRAP_TEST_OWNER_DRIFT_PATH="$1" safe_directory "$1" 700 ||\n'
            '  echo WRONG_OWNER_REJECTED\n'
            'safe_directory "$4" 700 || echo MISSING_REJECTED\n'
        )

        result = self.run_exec_safety(
            body,
            str(paths['directory']),
            str(paths['file']),
            str(paths['loose_directory']),
            str(paths['missing']),
            env={'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'DIRECTORY_ACCEPTED\nREGULAR_FILE_REJECTED\nWRONG_MODE_REJECTED\n'
            'WRONG_OWNER_REJECTED\nMISSING_REJECTED\n',
        )

    def test_symlinks_are_rejected_by_the_link_check_alone(self) -> None:
        """符号链接必须由 ! -L 单独判否，不能靠模式或属主顺带判否。

        GNU stat 跟随符号链接、BSD stat 不跟随，两边 path_mode 报出的模式不同，
        随手写死一个期望模式会让模式那一项先判否，去掉 ! -L 也照样红不了。这里
        把期望模式取成 path_mode 实际报出的值，并用一个刚 chmod 成同一模式的真实
        路径做正对照：对照判真说明模式与属主两项都成立，链接仍判否就只剩 ! -L。"""
        paths = self.probe_tree()
        body = (
            'reported=$(path_mode "$1")\n'
            'safe_file "$1" "$reported" || echo FILE_LINK_REJECTED\n'
            'cp "$3" "$4" && chmod "$reported" "$4"\n'
            'safe_file "$4" "$reported" && echo FILE_CONTROL_ACCEPTED\n'
            'reported=$(path_mode "$2")\n'
            'safe_directory "$2" "$reported" || echo DIR_LINK_REJECTED\n'
            'chmod "$reported" "$5"\n'
            'safe_directory "$5" "$reported" && echo DIR_CONTROL_ACCEPTED\n'
        )

        result = self.run_exec_safety(
            body,
            str(paths['file_link']),
            str(paths['directory_link']),
            str(paths['file']),
            str(paths['spare']),
            str(paths['loose_directory']),
            env={'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'FILE_LINK_REJECTED\nFILE_CONTROL_ACCEPTED\n'
            'DIR_LINK_REJECTED\nDIR_CONTROL_ACCEPTED\n',
        )

    def test_both_consuming_stages_delegate_to_the_shared_library(
        self,
    ) -> None:
        """60/90 必须只 source 共享库，不得保留本地副本。"""
        self.assertTrue(EXEC_SAFETY.is_file(), 'lib/exec-safety.sh is missing')
        self.assertFalse(EXEC_SAFETY.is_symlink())
        # 与 bootstrap-all.sh 的 safe_owned_file 同义：它只拒绝组/他人可写
        # （mode & 0022）。早先钉死 0644 比门禁更严，且依赖 clone 时的 umask，
        # 在 umask 077/027 下会无故变红（独立评审实测门禁对 0600/0755 均放行）。
        self.assertEqual(EXEC_SAFETY.stat().st_mode & 0o022, 0)

        shared = EXEC_SAFETY.read_text(encoding='utf-8')
        # 硬编码 source 字面量，与 CommonLibraryTest/PathFactsTest 的几处同源：
        # Task 10 把 stage 挪进 stages/<NN-name>/run.sh 后 ${script_dir} 语义
        # 改变，所有这类字面量必须一起改。
        source_line = self.library_source_pattern('exec-safety.sh')
        facts_source_line = self.library_source_pattern('path-facts.sh')
        declarations = (
            'python_isolated()',
            'tar_safe()',
            'safe_directory()',
            'safe_file()',
        )
        for declaration in declarations:
            self.assertEqual(shared.count(declaration), 1, declaration)
        # 跨 lib 依赖：safe_file/safe_directory 只在被调用时才需要 path_mode 与
        # owned_by_expected，所以 stage 先 source 哪个库都不影响判定。本库仍显式
        # source 兄弟库，只 source 它的消费者才不会拿到半个依赖。
        self.assertIn('/path-facts.sh"', shared)

        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertRegex(body, source_line)
                self.assertRegex(body, facts_source_line)
                self.assertIn('readonly PYTHON_BINARY=/usr/bin/python3', body)
                self.assertIn('readonly TAR_BINARY=/usr/bin/tar', body)
                for declaration in declarations:
                    self.assertNotIn(declaration, body, declaration)


class ArchiveLibraryTest(BootstrapTestCase):
    """lib/archive.sh：stage 10 与 30 两份 validate_archive 的并集契约。

    两份实现能力不同而非写法不同（见账本 R13）：30 认硬链接条目并对每个期望成员
    做正规文件检查、未知族 fail-closed；10 多认 helm 族但缺 `*)` 默认分支。合并后
    必须同时具备，且不得给 helm 加上任何实现从未施加过的检查（无服务器实测证据）。
    """

    def run_archive(
        self, body: str, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
        environment.update(env or {})
        return self.run_command(
            ['/bin/bash', '-c', f'set -u\nsource "$0"\n{body}',
             str(ARCHIVE_LIB), *arguments],
            env=environment,
        )

    def write_archive(
        self, path: Path, members: list[tuple[str, str, str]]
    ) -> Path:
        """按 (类型, 名字, 内容或链接目标) 建归档；类型取 file/symlink/hardlink/dir。"""
        with tarfile.open(path, 'w:gz') as archive:
            for kind, name, payload in members:
                entry = tarfile.TarInfo(name)
                if kind == 'file':
                    entry.mode = 0o755
                    entry.size = len(payload)
                    archive.addfile(entry, io.BytesIO(payload.encode()))
                    continue
                if kind == 'symlink':
                    entry.type = tarfile.SYMTYPE
                elif kind == 'hardlink':
                    entry.type = tarfile.LNKTYPE
                else:
                    entry.type = tarfile.DIRTYPE
                entry.linkname = payload
                entry.size = 0
                archive.addfile(entry)
        return path

    def containerd_members(self) -> list[tuple[str, str, str]]:
        return [
            ('file', 'bin/containerd', 'containerd\n'),
            ('file', 'bin/ctr', 'ctr\n'),
            ('file', 'bin/containerd-shim-runc-v2', 'shim\n'),
        ]

    def test_hardlink_entries_are_validated_like_symlinks(self) -> None:
        """硬链接条目的目标必须同样受检——只认符号链接会漏掉整整一类逃逸。"""
        directory = self.temporary_directory()
        escaping = self.write_archive(
            directory / 'hardlink-escape.tgz',
            self.containerd_members()
            + [('hardlink', 'bin/escape', '../../../etc/passwd')],
        )
        contained = self.write_archive(
            directory / 'hardlink-inside.tgz',
            self.containerd_members()
            + [('hardlink', 'bin/alias', 'bin/ctr')],
        )

        result = self.run_archive(
            'validate_archive containerd "$1" || echo HARDLINK_ESCAPE_REJECTED\n'
            'validate_archive containerd "$2" && echo HARDLINK_INSIDE_ACCEPTED\n',
            str(escaping), str(contained),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'HARDLINK_ESCAPE_REJECTED\nHARDLINK_INSIDE_ACCEPTED\n',
        )

    def test_hardlink_escape_is_rejected_when_the_lister_sanitizes_it(
        self,
    ) -> None:
        """捕获「守卫只看列表打印值、而列表器已先行净化」导致的失效。

        GNU tar 1.35 在**列表阶段**就剥掉硬链接目标的前导 `/` 与 `../`（容器内实测：
        `bin/../../../etc/passwd`、`/etc/passwd`、`../../etc/passwd` 三者都打印成
        `etc/passwd`），只把 "Removing leading …" 写到 stderr。于是基于打印值的
        safe_symlink_target 在生产平台上永远判不出逃逸——而 bsdtar 原样打印，所以
        这个缺陷能在 macOS 上完整躲过测试。这里用假 tar 复现 GNU 的行为，让该场景
        在两个平台都被覆盖。
        """
        directory = self.temporary_directory()
        archive = self.write_archive(
            directory / 'hardlink-escape.tgz',
            self.containerd_members()
            + [('hardlink', 'bin/escape', '../../../etc/passwd')],
        )
        fake_bin = directory / 'fake-bin'
        fake_bin.mkdir()
        fake_tar = fake_bin / 'tar'
        fake_tar.write_text(
            '#!/bin/sh\n'
            '# 模拟 GNU tar：列表时剥掉硬链接目标的前导 ../ 并把净化写到 stderr。\n'
            'if [ "$1" = "-tvzf" ] && [ $# -eq 2 ]; then\n'
            '  /usr/bin/tar "$@" | sed "s# link to \\.\\./.*# link to etc/passwd#"\n'
            '  if /usr/bin/tar "$@" | grep -q " link to "; then\n'
            '    printf "tar: Removing leading \\`../../../%s from hard link targets\\n" "\'" >&2\n'
            '  fi\n'
            '  exit 0\n'
            'fi\n'
            'exec /usr/bin/tar "$@"\n',
            encoding='utf-8',
        )
        fake_tar.chmod(0o755)

        result = self.run_archive(
            'validate_archive containerd "$1" || echo SANITIZED_ESCAPE_REJECTED\n',
            str(archive),
            env={'PATH': f'{fake_bin}:/usr/bin:/bin'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'SANITIZED_ESCAPE_REJECTED\n')

    def test_symlink_entries_and_member_paths_may_not_escape(self) -> None:
        """符号链接目标与成员路径两条老断言都必须保留。"""
        directory = self.temporary_directory()
        link_escape = self.write_archive(
            directory / 'symlink-escape.tgz',
            self.containerd_members()
            + [('symlink', 'bin/escape', '../../../etc/shadow')],
        )
        path_escape = self.write_archive(
            directory / 'path-escape.tgz',
            self.containerd_members() + [('file', '../evil', 'x')],
        )
        absolute = self.write_archive(
            directory / 'absolute.tgz',
            self.containerd_members() + [('file', '/etc/evil', 'x')],
        )

        # 纯否定断言在"函数根本不存在"时也会成立（命令未找到同样返回非零），
        # 因此每组都配一个必须判真的对照，逼出实现真的存在且工作。
        contained = self.write_archive(
            directory / 'symlink-inside.tgz',
            self.containerd_members()
            + [('symlink', 'bin/alias', 'containerd')],
        )

        result = self.run_archive(
            'validate_archive containerd "$1" || echo SYMLINK_REJECTED\n'
            'validate_archive containerd "$2" || echo RELATIVE_REJECTED\n'
            'validate_archive containerd "$3" || echo ABSOLUTE_REJECTED\n'
            'validate_archive containerd "$4" && echo SAFE_SYMLINK_ACCEPTED\n',
            str(link_escape), str(path_escape), str(absolute), str(contained),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'SYMLINK_REJECTED\nRELATIVE_REJECTED\nABSOLUTE_REJECTED\n'
            'SAFE_SYMLINK_ACCEPTED\n',
        )

    def test_unknown_archive_family_fails_closed(self) -> None:
        """未知族必须判否。stage 10 原实现缺 `*)` 分支会静默放行，属潜伏 fail-open。"""
        directory = self.temporary_directory()
        archive = self.write_archive(
            directory / 'good.tgz', self.containerd_members()
        )

        result = self.run_archive(
            'validate_archive containerd "$1" && echo KNOWN_ACCEPTED\n'
            'validate_archive gateway-api "$1" || echo UNKNOWN_REJECTED\n'
            'validate_archive "" "$1" || echo EMPTY_REJECTED\n',
            str(archive),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'KNOWN_ACCEPTED\nUNKNOWN_REJECTED\nEMPTY_REJECTED\n',
        )

    def test_expected_members_must_be_regular_files(self) -> None:
        """期望成员被替换成目录或指向合法目标的符号链接时都必须判否。"""
        directory = self.temporary_directory()
        as_symlink = self.write_archive(
            directory / 'member-symlink.tgz',
            [
                ('file', 'bin/containerd', 'containerd\n'),
                ('symlink', 'bin/ctr', 'containerd'),
                ('file', 'bin/containerd-shim-runc-v2', 'shim\n'),
            ],
        )
        as_directory = self.write_archive(
            directory / 'member-directory.tgz',
            [
                ('file', 'bin/containerd', 'containerd\n'),
                ('dir', 'bin/ctr', ''),
                ('file', 'bin/containerd-shim-runc-v2', 'shim\n'),
            ],
        )

        # 同上：配一个全为正规文件的对照，否则实现缺席时本用例也会绿。
        regular = self.write_archive(
            directory / 'member-regular.tgz', self.containerd_members()
        )

        result = self.run_archive(
            'validate_archive containerd "$1" || echo SYMLINK_MEMBER_REJECTED\n'
            'validate_archive containerd "$2" || echo DIRECTORY_MEMBER_REJECTED\n'
            'validate_archive containerd "$3" && echo REGULAR_MEMBER_ACCEPTED\n',
            str(as_symlink), str(as_directory), str(regular),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'SYMLINK_MEMBER_REJECTED\nDIRECTORY_MEMBER_REJECTED\n'
            'REGULAR_MEMBER_ACCEPTED\n',
        )

    def test_every_family_keeps_its_required_members(self) -> None:
        """三个族都必须保留：合并若丢掉 helm，它会落进 `*)` 而被判否。"""
        directory = self.temporary_directory()
        helm_good = self.write_archive(
            directory / 'helm.tgz', [('file', 'linux-amd64/helm', 'helm\n')]
        )
        helm_bad = self.write_archive(
            directory / 'helm-missing.tgz', [('file', 'linux-amd64/tiller', 'x')]
        )
        crictl_good = self.write_archive(
            directory / 'crictl.tgz', [('file', 'crictl', 'crictl\n')]
        )
        crictl_bad = self.write_archive(
            directory / 'crictl-missing.tgz', [('file', 'other', 'x')]
        )
        containerd_bad = self.write_archive(
            directory / 'containerd-missing.tgz',
            [('file', 'bin/containerd', 'containerd\n')],
        )

        result = self.run_archive(
            'validate_archive helm "$1" && echo HELM_ACCEPTED\n'
            'validate_archive helm "$2" || echo HELM_MISSING_REJECTED\n'
            'validate_archive crictl "$3" && echo CRICTL_ACCEPTED\n'
            'validate_archive crictl "$4" || echo CRICTL_MISSING_REJECTED\n'
            'validate_archive containerd "$5" || echo CONTAINERD_MISSING_REJECTED\n',
            str(helm_good), str(helm_bad), str(crictl_good),
            str(crictl_bad), str(containerd_bad),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'HELM_ACCEPTED\nHELM_MISSING_REJECTED\nCRICTL_ACCEPTED\n'
            'CRICTL_MISSING_REJECTED\nCONTAINERD_MISSING_REJECTED\n',
        )

    def test_approved_record_covers_every_artifact_and_the_test_seam(
        self,
    ) -> None:
        """六个制品各一条四字段记录，未知名判否；30 的 lock 文件测试缝必须保留。"""
        directory = self.temporary_directory()
        lock = directory / 'approved.lock'
        lock.write_text(
            'containerd\t9.9.9\thttps://example.invalid/c.tgz\tdeadbeef\t/tmp/c\n',
            encoding='utf-8',
        )

        result = self.run_archive(
            'for name in containerd runc crictl helm gateway-api cilium-chart; do\n'
            '  record=$(approved_record "$name") || { echo "MISSING_$name"; continue; }\n'
            '  printf "%s\\t%s\\n" "$name" "$(printf "%s" "$record" | awk -F "\\t" "{print NF}")"\n'
            'done\n'
            'approved_record nonesuch || echo UNKNOWN_REJECTED\n'
            'BOOTSTRAP_TEST_MODE=1 BOOTSTRAP_TEST_APPROVED_LOCK_FILE="$1" '
            'approved_record containerd\n',
            str(lock),
            env={'BOOTSTRAP_TEST_MODE': '0'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        for name in (
            'containerd', 'runc', 'crictl', 'helm', 'gateway-api', 'cilium-chart'
        ):
            with self.subTest(artifact=name):
                self.assertIn(f'{name}\t4', lines)
        self.assertIn('UNKNOWN_REJECTED', lines)
        self.assertIn(
            '9.9.9\thttps://example.invalid/c.tgz\tdeadbeef\t/tmp/c', lines
        )

    def test_both_stages_delegate_to_the_shared_library(self) -> None:
        """10/30 必须只 source 共享库，不得保留本地副本。"""
        self.assertTrue(ARCHIVE_LIB.is_file(), 'lib/archive.sh is missing')
        self.assertFalse(ARCHIVE_LIB.is_symlink())
        # 与 bootstrap-all.sh 的 safe_owned_file 同义：它只拒绝组/他人可写
        # （mode & 0022）。早先钉死 0644 比门禁更严，且依赖 clone 时的 umask，
        # 在 umask 077/027 下会无故变红（独立评审实测门禁对 0600/0755 均放行）。
        self.assertEqual(ARCHIVE_LIB.stat().st_mode & 0o022, 0)

        shared = ARCHIVE_LIB.read_text(encoding='utf-8')
        source_line = self.library_source_pattern('archive.sh')
        declarations = (
            'array_contains()',
            'safe_archive_member()',
            'safe_symlink_target()',
            'approved_record()',
            'validate_archive()',
            'regular_archive_member()',
        )
        for declaration in declarations:
            self.assertEqual(shared.count(declaration), 1, declaration)
        for stage in (STAGE_ARTIFACTS, INSTALL_CONTAINERD):
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertRegex(body, source_line)
                for declaration in declarations:
                    self.assertNotIn(declaration, body, declaration)
                # 10 私有的两个包装随并集吸收，不得留下孤儿定义。
                self.assertNotIn('require_archive_member()', body)
                self.assertNotIn('require_regular_archive_member()', body)


class KubectlLibraryTest(BootstrapTestCase):
    """lib/kubectl.sh：stage 60/90 曾各留一份的 admin.conf 生命周期与 kubectl 门禁。

    两份实现归一命名后字节一致，唯一差异是 60 把 safe_file 的四项检查内联展开
    （账本 Task 5 裁决）。统一取 90 的命名与抽取形态。
    """

    STAGES = (INSTALL_CILIUM, FINAL_VERIFY)
    DECLARATIONS = (
        'admin_conf_metadata_is_safe()',
        'capture_admin_conf()',
        'admin_conf_is_safe()',
        'kubectl_run()',
        'kubectl_query_is_empty()',
    )

    def test_both_consuming_stages_delegate_to_the_shared_library(self) -> None:
        """60/90 必须只 source 共享库，且不得残留旧的 _gate 命名。"""
        self.assertTrue(KUBECTL_LIB.is_file(), 'lib/kubectl.sh is missing')
        self.assertFalse(KUBECTL_LIB.is_symlink())
        self.assertEqual(KUBECTL_LIB.stat().st_mode & 0o022, 0)

        shared = KUBECTL_LIB.read_text(encoding='utf-8')
        for declaration in self.DECLARATIONS:
            self.assertEqual(shared.count(declaration), 1, declaration)
        # 跨 lib 依赖：safe_file 来自 exec-safety.sh，admin_conf_json_is_exact 来自
        # admin-conf.sh；只 source 本库的消费者不能拿到半个依赖。
        self.assertIn('/exec-safety.sh"', shared)
        self.assertIn('/admin-conf.sh"', shared)

        source_line = self.library_source_pattern('kubectl.sh')
        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertRegex(body, source_line)
                for declaration in self.DECLARATIONS:
                    self.assertNotIn(declaration, body, declaration)
                # 旧命名一处都不许留：60 曾用 _gate 后缀，改名不彻底会让调用点
                # 指向不存在的函数，而 set -u 之外的 command not found 只在真正
                # 执行到那条路径时才暴露。
                self.assertNotIn('admin_conf_gate', body)
                self.assertNotIn('admin_conf_metadata_gate', body)

    def test_capture_state_lives_only_in_the_shared_library(self) -> None:
        """捕获状态必须只有一份，stage 各留一份会让 TOCTOU 判定各自为政。"""
        # 按整行匹配：函数体内的 ADMIN_CONF_CONTENT=$captured 是赋值不是声明。
        shared = KUBECTL_LIB.read_text(encoding='utf-8').splitlines()
        for name in ('ADMIN_CONF_CAPTURED=0', 'ADMIN_CONF_CONTENT='):
            self.assertEqual(shared.count(name), 1, name)
        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertNotIn('ADMIN_CONF_CAPTURED=0', body)
                self.assertNotIn('\nADMIN_CONF_CONTENT=\n', body)

    def test_kubectl_never_reads_the_kubeconfig_from_disk(self) -> None:
        """kubectl 一律读已捕获内容，且调用前后各校验一次磁盘文件。

        直接把磁盘路径交给 kubectl，读取期间文件被替换不会被发现；这条断言钉住
        TOCTOU 防护的三个要件，任何一件被拿掉都判红。
        """
        shared = KUBECTL_LIB.read_text(encoding='utf-8')
        run_body = shared.split('kubectl_run() {', 1)[1].split('\n}\n', 1)[0]

        self.assertIn('--kubeconfig <(printf', run_body)
        self.assertNotIn('--kubeconfig "$admin_conf"', run_body)
        self.assertEqual(run_body.count('admin_conf_is_safe || return 1'), 2)


class HelmLibraryTest(BootstrapTestCase):
    """lib/helm.sh：helm 调用与瞬态 kubeconfig 的生命周期。

    该临时文件是 `--check` 零写入原则唯一文档化的例外，所以它的四条性质——目录 700、
    文件 600、内容与 ADMIN_CONF_CONTENT 逐字节一致、退出时必被清理——都要有断言。
    """

    STAGES = (INSTALL_CILIUM, FINAL_VERIFY)
    DECLARATIONS = (
        'helm_run()',
        'cleanup_helm_kubeconfig()',
        'helm_cluster_run()',
        'helm_kubeconfig_residue_exists()',
        'helm_values_json_is_exact()',
        'helm_archive_is_safe()',
    )

    def test_transient_kubeconfig_is_locked_down_and_always_removed(self) -> None:
        """目录 700、文件 600、内容逐字节一致，且函数返回后不留残留。"""
        directory = self.temporary_directory()
        root = directory / 'root'
        root.mkdir()
        root.chmod(0o700)
        fake_helm = directory / 'fake-helm'
        fake_helm.write_text(
            '#!/bin/sh\n'
            'kubeconfig=$2\n'
            'dir=$(dirname "$kubeconfig")\n'
            # GNU 在前、BSD 在后，与 lib/path-facts.sh 的 path_mode 同序。
            # 反过来写会在 Linux 上静默出错：GNU 的 -f 是「显示文件系统状态」
            # 且返回 0，`||` 的回退永远走不到，于是吐出一堆文件系统信息。
            'mode() { stat -c "%a" "$1" 2>/dev/null || stat -f "%Lp" "$1"; }\n'
            'printf "KUBECONFIG_DIR_MODE=%s\\n" "$(mode "$dir")"\n'
            'printf "KUBECONFIG_FILE_MODE=%s\\n" "$(mode "$kubeconfig")"\n'
            'printf "KUBECONFIG_CONTENT=%s\\n" "$(cat "$kubeconfig")"\n',
            encoding='utf-8',
        )
        fake_helm.chmod(0o755)

        body = (
            'umask 077\n'
            'admin_conf_is_safe() { return 0; }\n'
            f'host_path() {{ printf "%s%s\\n" "{directory}" "$1"; }}\n'
            'ADMIN_CONF_CONTENT=fake-kubeconfig-bytes\n'
            f'helm_binary={fake_helm}\n'
            'helm_cluster_run version --short || echo CLUSTER_RUN_REJECTED\n'
            'helm_kubeconfig_residue_exists && echo RESIDUE_LEFT || echo RESIDUE_CLEAN\n'
        )
        result = self.run_command(
            ['/bin/bash', '-c', f'set -u\nsource "$0"\n{body}',
             str(HELM_LIB)],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                 'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CLUSTER_RUN_REJECTED', result.stdout)
        self.assertIn('KUBECONFIG_DIR_MODE=700', result.stdout)
        self.assertIn('KUBECONFIG_FILE_MODE=600', result.stdout)
        self.assertIn('KUBECONFIG_CONTENT=fake-kubeconfig-bytes', result.stdout)
        self.assertIn('RESIDUE_CLEAN', result.stdout)
        self.assertEqual(list(root.iterdir()), [], '瞬态目录必须被清掉')

        # 同一段逻辑在 umask 放宽时必须判否——否则 kubeconfig 会以 644 落盘。
        # 没有这一问，safe_file 那一项被拿掉也不会有任何用例变红。
        loose = self.run_command(
            ['/bin/bash', '-c',
             f'set -u\nsource "$0"\n{body.replace("umask 077", "umask 022")}',
             str(HELM_LIB)],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                 'BOOTSTRAP_TEST_MODE': '1'},
        )

        self.assertIn('CLUSTER_RUN_REJECTED', loose.stdout)
        self.assertNotIn('KUBECONFIG_FILE_MODE', loose.stdout)
        self.assertEqual(list(root.iterdir()), [], '判否路径同样不得留残留')

    def test_both_consuming_stages_delegate_to_the_shared_library(self) -> None:
        """60/90 必须只 source 共享库，不得保留本地副本。"""
        self.assertTrue(HELM_LIB.is_file(), 'lib/helm.sh is missing')
        self.assertFalse(HELM_LIB.is_symlink())
        self.assertEqual(HELM_LIB.stat().st_mode & 0o022, 0)

        shared = HELM_LIB.read_text(encoding='utf-8')
        for declaration in self.DECLARATIONS:
            self.assertEqual(shared.count(declaration + ' '), 1, declaration)
        # 临时目录变量也必须只有一份，两边各留一份会让 trap 清理各自为政。
        self.assertEqual(
            shared.splitlines().count('helm_kubeconfig_dir='), 1
        )
        self.assertIn('/exec-safety.sh"', shared)
        self.assertIn('/kubectl.sh"', shared)

        source_line = self.library_source_pattern('helm.sh')
        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                body = stage.read_text(encoding='utf-8')
                self.assertRegex(body, source_line)
                for declaration in self.DECLARATIONS:
                    self.assertNotIn(declaration + ' {', body, declaration)
                    self.assertNotIn(declaration + ' (', body, declaration)
                self.assertNotIn('\nhelm_kubeconfig_dir=\n', body)

    def test_archive_predicate_requires_an_explicit_argument(self) -> None:
        """helm_archive_is_safe 必须显式传参：60 有 staged 与 apply 两个来源，
        默认参数会让调用点看不出用的是哪一个。"""
        shared = HELM_LIB.read_text(encoding='utf-8')
        self.assertIn('  local archive=$1\n', shared)
        self.assertNotIn('${1:-$helm_archive_input}', shared)
        for stage in self.STAGES:
            with self.subTest(stage=stage.name):
                for line in stage.read_text(encoding='utf-8').splitlines():
                    if 'helm_archive_is_safe' in line:
                        self.assertRegex(line, r'helm_archive_is_safe "\$')


class CidrCheckTest(BootstrapTestCase):
    def run_cidr(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.run_command(['/usr/bin/python3', str(CIDR_CHECK), *arguments])

    def base_arguments(self) -> list[str]:
        return [
            '--service-cidr',
            '172.20.0.0/16',
            '--pod-cidr',
            '172.21.0.0/16',
        ]

    def test_accepts_non_overlapping_local_networks(self) -> None:
        result = self.run_cidr(
            *self.base_arguments(),
            '--address',
            '192.0.2.10/24',
            '--route',
            '192.0.2.0/24',
            '--route',
            '10.0.0.0/8',
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CIDRS', result.stdout)
        self.assertIn('SCOPE=SERVER_LOCAL_SCOPE_ONLY', result.stdout)

    def test_rejects_service_cidr_overlapping_address(self) -> None:
        result = self.run_cidr(
            *self.base_arguments(), '--address', '172.20.8.2/24'
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CIDR_OVERLAP', result.stdout)

    def test_rejects_pod_cidr_overlapping_route(self) -> None:
        result = self.run_cidr(
            *self.base_arguments(), '--route', '172.21.8.0/24'
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CIDR_OVERLAP', result.stdout)

    def test_rejects_service_and_pod_overlap(self) -> None:
        result = self.run_cidr(
            '--service-cidr',
            '172.20.0.0/16',
            '--pod-cidr',
            '172.20.128.0/17',
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CIDR_OVERLAP', result.stdout)


    def test_exempts_cni_owned_entries_inside_pod_cidr(self) -> None:
        """装完 Cilium 后 cilium_host 上的 PodCIDR 段路由/地址是设计使然，不是冲突。"""
        result = self.run_cidr(
            *self.base_arguments(),
            '--cni-device', 'cilium_host', '--cni-device', 'lxc*',
            '--address', '192.0.2.10/24@ens160',
            '--address', '172.21.0.168/32@cilium_host',
            '--route', '192.0.2.0/24@ens160',
            '--route', '172.21.0.0/24@cilium_host',
            '--route', '172.21.0.5/32@lxc9f2a',
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_CIDRS', result.stdout)

    def test_cni_exemption_is_narrow(self) -> None:
        cases = {
            'no-cni-device-declared': (
                ['--address', '172.21.0.168/32@cilium_host'],
                'STOP_CIDR_OVERLAP', 'pod-overlaps-local-address',
            ),
            'foreign-device-inside-pod-cidr': (
                ['--cni-device', 'cilium_host', '--address', '172.21.5.1/24@ens160'],
                'STOP_CIDR_OVERLAP', 'pod-overlaps-local-address',
            ),
            'cni-device-but-service-cidr': (
                ['--cni-device', 'cilium_host', '--route', '172.20.0.0/24@cilium_host'],
                'STOP_CIDR_OVERLAP', 'service-overlaps-local-route',
            ),
            # Pod CIDR 的超网即使在 CNI 网卡上也不豁免（豁免只给完全落在 Pod CIDR 内的条目）。
            # 用不与 Service CIDR 相交的超网，确保命中的是 Pod 检查而不是更早的 Service 检查。
            'cni-device-supernet-of-pod-cidr': (
                ['--service-cidr', '10.96.0.0/12', '--pod-cidr', '172.21.0.0/16',
                 '--cni-device', 'cilium_host', '--route', '172.0.0.0/8@cilium_host'],
                'STOP_CIDR_OVERLAP', 'pod-overlaps-local-route',
            ),
            'device-without-tag-is-not-exempt': (
                ['--cni-device', 'cilium_host', '--route', '172.21.0.0/24'],
                'STOP_CIDR_OVERLAP', 'pod-overlaps-local-route',
            ),
            'invalid-device-name': (
                ['--cni-device', 'cilium_host', '--address', '172.21.0.1/32@bad name'],
                'STOP_CIDR_INVALID', None,
            ),
            'empty-device-name': (
                ['--cni-device', 'cilium_host', '--address', '172.21.0.1/32@'],
                'STOP_CIDR_INVALID', None,
            ),
            'invalid-cni-pattern': (
                ['--cni-device', 'cilium host', '--address', '172.21.0.1/32@cilium_host'],
                'STOP_CIDR_INVALID', None,
            ),
        }
        for name, (extra, expected_result, expected_reason) in cases.items():
            with self.subTest(case=name):
                arguments = extra if '--pod-cidr' in extra else [*self.base_arguments(), *extra]
                result = self.run_cidr(*arguments)

                self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
                self.assertIn(f'RESULT={expected_result}', result.stdout)
                if expected_reason:
                    self.assertIn(f'REASON={expected_reason}', result.stdout)


class PreflightTest(BootstrapTestCase):
    cleanup_digest = (
        'a68a3d2ff340bcdcb4265853107a3a2c22a9f7328728473d81d9be2d1486e635'
    )

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def make_environment(
        self, *, ambient_support_path: str | None = None
    ) -> tuple[dict[str, str], Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        support_bin = directory / 'support-bin'
        (host / 'etc').mkdir(parents=True)
        (host / 'root/dev-infra-evidence').mkdir(parents=True)
        fake_bin.mkdir()
        hosts_root = directory / 'hosts'
        hosts_root.mkdir()
        self.write_fixture_host(hosts_root)
        support_bin.mkdir()
        support_path = ambient_support_path or os.environ.get('PATH', os.defpath)
        for command in (
            'awk',
            'chmod',
            'cmp',
            'date',
            'dirname',
            'grep',
            'python3',
            'readlink',
            'tr',
        ):
            source = shutil.which(command, path=support_path)
            if source is None:
                self.fail(f'fixture support command missing: {command}')
            (support_bin / command).symlink_to(Path(source).resolve())
        (host / 'etc/os-release').write_text(
            'ID=ubuntu\nVERSION_ID="24.04"\n', encoding='utf-8'
        )
        (host / 'swap.img').write_bytes(b'')
        cleanup = (
            host
            / 'root/dev-infra-evidence'
            / '06-host-workflow-cleanup-20260810T033358Z.txt'
        )
        cleanup.write_text('fixture content is hashed by fake shasum\n', encoding='utf-8')

        self.write_executable(
            fake_bin / 'id',
            '''
            #!/bin/sh
            [ "$1" = "-u" ] || exit 2
            printf '%s\n' "${FAKE_ID_UID:-0}"
            ''',
        )
        self.write_executable(
            fake_bin / 'hostname',
            '''
            #!/bin/sh
            [ -z "${FAKE_CANARY:-}" ] || printf '%s\n' "$FAKE_CANARY" >&2
            printf '%s\n' "${FAKE_HOSTNAME:-example-node}"
            ''',
        )
        self.write_executable(
            fake_bin / 'uname',
            '''
            #!/bin/sh
            printf '%s\n' "${FAKE_ARCH:-x86_64}"
            ''',
        )
        self.write_executable(
            fake_bin / 'ip',
            '''
            #!/bin/sh
            node_ip="${FAKE_NODE_IP:-192.0.2.10}"
            node_subnet="${node_ip%.*}.0/24"
            case "$*" in
              *address*) printf '%s\n' "${FAKE_IP_ADDRESS:-2: ens160    inet ${node_ip}/24 scope global ens160}" ;;
              *route*) printf '%s\n' "${FAKE_IP_ROUTES:-${node_subnet} dev ens160 proto kernel scope link src ${node_ip}}" ;;
              *) exit 2 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'stat',
            '''
            #!/bin/sh
            if [ "$1" = "-fc" ]; then
              printf '%s\n' "${FAKE_CGROUP_FS:-cgroup2fs}"
              exit 0
            fi
            last=
            for last do :; done
            if [ -n "${FAKE_STAT_OWNER_DRIFT:-}" ] && [ "$last" = "$FAKE_STAT_OWNER_DRIFT" ] &&
               { [ "$2" = '%u:%g' ] || [ "$2" = '%u' ]; }; then
              printf '65534:65534\n'
              exit 0
            fi
            exec /usr/bin/stat "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'swapon',
            '''
            #!/bin/sh
            printf '%s\n' "${FAKE_SWAP_OUTPUT:-/swap.img 4294963200}"
            ''',
        )
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            case "$1" in
              is-active) printf 'active\n' ;;
              list-unit-files) exit 0 ;;
              *) exit 2 ;;
            esac
            ''',
        )
        self.write_executable(fake_bin / 'ss', '#!/bin/sh\nexit 0\n')
        self.write_executable(fake_bin / 'dpkg-query', '#!/bin/sh\nexit 1\n')
        self.write_executable(
            fake_bin / 'shasum',
            f'''
            #!/bin/sh
            case "$*" in
              *06-host-workflow-cleanup*)
                last=
                for last do :; done
                printf '%s  %s\n' "${{FAKE_CLEANUP_SHA:-{self.cleanup_digest}}}" "$last"
                ;;
              *) exec /usr/bin/shasum "$@" ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'sha256sum',
            f'''
            #!/bin/sh
            case "$*" in
              *06-host-workflow-cleanup*)
                last=
                for last do :; done
                printf '%s  %s\n' "${{FAKE_CLEANUP_SHA:-{self.cleanup_digest}}}" "$last"
                ;;
              *)
                if [ -x /usr/bin/sha256sum ]; then
                  exec /usr/bin/sha256sum "$@"
                fi
                exec /usr/bin/shasum -a 256 "$@"
                ;;
            esac
            ''',
        )

        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': os.pathsep.join((str(fake_bin), str(support_bin))),
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_HOSTS_DIR': str(hosts_root),
            }
        )
        return environment, host

    def run_preflight(
        self, **overrides: str
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        environment, host = self.make_environment()
        environment.update(overrides)
        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )
        return result, host

    def evidence_text(self, host: Path) -> str:
        evidence = sorted((host / 'root/dev-infra-evidence').glob('07-preflight-*.txt'))
        self.assertEqual(len(evidence), 1)
        return evidence[0].read_text(encoding='utf-8')

    def test_stops_when_not_root(self) -> None:
        result, _ = self.run_preflight(FAKE_ID_UID='1000')

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_HOST_IDENTITY', result.stdout)

    def test_stops_on_wrong_hostname(self) -> None:
        result, _ = self.run_preflight(FAKE_HOSTNAME='wrong-host')

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
        self.assertIn('REASON=host-not-registered', result.stdout)

    def test_host_directory_contract_is_fail_closed(self) -> None:
        cases = (
            'directory-symlink', 'directory-mode', 'directory-owner',
            'env-symlink', 'env-mode', 'env-owner', 'extra-file',
            'missing-file', 'pins-mode', 'name-mismatch', 'invalid-env',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host = self.make_environment()
                hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
                host_dir = hosts_root / 'example-node'
                expected = 'host-config-unsafe'
                if case == 'directory-symlink':
                    real = hosts_root / 'real'
                    host_dir.rename(real)
                    host_dir.symlink_to(real)
                elif case == 'directory-mode':
                    host_dir.chmod(0o777)
                elif case == 'directory-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(host_dir)
                elif case == 'env-symlink':
                    (host_dir / 'host.env').rename(hosts_root / 'outside.env')
                    (host_dir / 'host.env').symlink_to(hosts_root / 'outside.env')
                elif case == 'env-mode':
                    (host_dir / 'host.env').chmod(0o666)
                elif case == 'env-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(host_dir / 'host.env')
                elif case == 'extra-file':
                    (host_dir / 'README.md').write_text('x\n', encoding='utf-8')
                elif case == 'missing-file':
                    (host_dir / 'pins.sha256').unlink()
                elif case == 'pins-mode':
                    (host_dir / 'pins.sha256').chmod(0o600)
                elif case == 'name-mismatch':
                    expected = 'host-config-name-mismatch'
                    env = host_dir / 'host.env'
                    env.write_text(
                        env.read_text(encoding='utf-8').replace(
                            'HOST_NAME=example-node', 'HOST_NAME=other-host'
                        ),
                        encoding='utf-8',
                    )
                else:
                    expected = 'host-config-invalid'
                    env = host_dir / 'host.env'
                    env.write_text(
                        env.read_text(encoding='utf-8').replace(
                            'HOST_NODE_IP=192.0.2.10', 'HOST_NODE_IP=192.0.2.256'
                        ),
                        encoding='utf-8',
                    )

                result = self.run_command(
                    ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                self.assertIn(f'REASON={expected}', result.stdout)

    def test_swap_contract_comes_from_host_env(self) -> None:
        """swap 文件名与区间必须来自 host.env，而不是脚本字面量。"""
        environment, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        shutil.rmtree(hosts_root / 'example-node')
        self.write_fixture_host(hosts_root, swap_min=1000, swap_max=2000)

        result = self.run_command(['/bin/bash', str(PREFLIGHT), '--check'], env=environment)

        self.assertEqual(result.returncode, 10, result.stdout)
        self.assertIn('REASON=swap-size-mismatch', result.stdout)

    def test_registered_second_host_flows_through_preflight(self) -> None:
        environment, host = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        self.write_fixture_host(
            hosts_root, name='fixture-host-b', node_ip='10.200.0.2',
            cluster_name='fixture-b', pod_cidr='10.244.0.0/16',
            service_cidr='10.96.0.0/12', swap_file='/swap-b.img',
            swap_min=3000000000, swap_max=3400000000,
        )
        (host / 'swap-b.img').write_bytes(b'')
        environment['FAKE_HOSTNAME'] = 'fixture-host-b'
        environment['FAKE_NODE_IP'] = '10.200.0.2'
        environment['FAKE_SWAP_OUTPUT'] = '/swap-b.img 3221225472'

        result = self.run_command(['/bin/bash', str(PREFLIGHT), '--check'], env=environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)
        evidence = self.evidence_text(host)
        self.assertIn('HOSTNAME=fixture-host-b', evidence)
        self.assertIn('NODE_IP=10.200.0.2', evidence)
        self.assertIn('POD_CIDR=10.244.0.0/16', evidence)
        self.assertIn('SWAP=/swap-b.img', evidence)

    def test_accepts_canonical_ubuntu_os_release_symlink(self) -> None:
        environment, host = self.make_environment()
        canonical = host / 'usr/lib/os-release'
        canonical.parent.mkdir(parents=True)
        (host / 'etc/os-release').replace(canonical)
        (host / 'etc/os-release').symlink_to('../usr/lib/os-release')

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)

    def test_rejects_noncanonical_os_release_symlink(self) -> None:
        environment, host = self.make_environment()
        unapproved = host / 'tmp/os-release'
        unapproved.parent.mkdir(parents=True)
        (host / 'etc/os-release').replace(unapproved)
        (host / 'etc/os-release').symlink_to('../tmp/os-release')

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('REASON=os-release-missing', result.stdout)

    def test_uses_swapon_show_columns_for_exact_swap_layout(self) -> None:
        environment, _ = self.make_environment()
        fake_bin = Path(environment['PATH'].split(':', 1)[0])
        self.write_executable(
            fake_bin / 'swapon',
            '''
            #!/bin/sh
            if [ "$*" = "--show=NAME,SIZE --noheadings --raw --bytes" ]; then
              printf '/swap.img 4106219520\n'
            else
              printf '/swap.img file 4106219520 0 -2 fixture-uuid\n'
            fi
            ''',
        )

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)

    def test_stops_on_cleanup_evidence_digest_drift(self) -> None:
        result, _ = self.run_preflight(FAKE_CLEANUP_SHA='0' * 64)

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CLEANUP_EVIDENCE', result.stdout)

    def test_fake_cleanup_digest_precedes_system_sha256sum(self) -> None:
        """捕获 Linux 优先选择 sha256sum 时绕过批准 digest fixture 的缺陷。"""
        environment, _ = self.make_environment()
        fake_bin, support_bin = map(Path, environment['PATH'].split(os.pathsep))
        system_bin = fake_bin.parent / 'system-bin'
        system_bin.mkdir()
        self.write_executable(
            system_bin / 'sha256sum',
            '''
            #!/bin/sh
            printf '%064d  %s\n' 0 "$1"
            ''',
        )
        environment['PATH'] = os.pathsep.join(
            (str(fake_bin), str(system_bin), str(support_bin))
        )

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)

    def test_ambient_containerd_is_excluded_from_fixture_path(self) -> None:
        ambient_bin = self.temporary_directory() / 'ambient-bin'
        ambient_bin.mkdir()
        self.write_executable(ambient_bin / 'containerd', '#!/bin/sh\nexit 0\n')
        ambient_support_path = os.pathsep.join(
            (str(ambient_bin), os.environ.get('PATH', os.defpath))
        )

        environment, _ = self.make_environment(
            ambient_support_path=ambient_support_path
        )
        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)

    def test_stage30_owned_runtime_footprint_does_not_fail_preflight(self) -> None:
        environment, host = self.make_environment()
        fake_bin = Path(environment['PATH'].split(os.pathsep, 1)[0])
        self.write_executable(fake_bin / 'containerd', '#!/bin/sh\nexit 0\n')
        self.write_executable(fake_bin / 'runc', '#!/bin/sh\nexit 0\n')
        for path in ('etc/containerd', 'opt/containerd', 'var/lib/containerd'):
            (host / path).mkdir(parents=True)
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            case "$1" in
              is-active) printf 'active\n' ;;
              list-unit-files) printf 'containerd.service enabled\n' ;;
              *) exit 2 ;;
            esac
            ''',
        )

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)

    def test_legacy_runtime_conflicts_still_fail_preflight(self) -> None:
        environment, _ = self.make_environment()
        fake_bin = Path(environment['PATH'].split(os.pathsep, 1)[0])
        self.write_executable(fake_bin / 'docker', '#!/bin/sh\nexit 0\n')

        result = self.run_command(
            ['/bin/bash', str(PREFLIGHT), '--check'], env=environment
        )

        self.assertEqual(result.returncode, 30, result.stdout + result.stderr)
        self.assertIn('RESULT=STOP_OLD_RUNTIME', result.stdout)
        self.assertIn('REASON=unexpected-binary-docker', result.stdout)

    def test_stops_on_local_cidr_overlap(self) -> None:
        result, _ = self.run_preflight(
            FAKE_IP_ROUTES='172.21.8.0/24 dev ens160 scope link'
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CIDR_OVERLAP', result.stdout)

    def test_accepts_cilium_owned_pod_cidr_entries_after_install(self) -> None:
        """装完 Cilium 后（真机 ip 输出）preflight 必须仍然通过，否则永远到不了 Stage 90。"""
        routes = (
            'local default dev lo table 2004 proto kernel scope host \n'
            'default via 192.0.2.1 dev ens160 proto static \n'
            '192.0.2.0/24 dev ens160 proto kernel scope link src 192.0.2.10 \n'
            '172.21.0.0/24 via 172.21.0.168 dev cilium_host proto kernel src 172.21.0.168 \n'
            '172.21.0.168 dev cilium_host proto kernel scope link \n'
            'local 192.0.2.10 dev ens160 table local proto kernel scope host src 192.0.2.10 \n'
            'local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1 \n'
            'local 172.21.0.168 dev cilium_host table local proto kernel scope host src 172.21.0.168 '
        )
        addresses = (
            '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n'
            '2: ens160    inet 192.0.2.10/24 brd 192.0.2.255 scope global ens160\\       valid_lft forever preferred_lft forever\n'
            '28264: cilium_host    inet 172.21.0.168/32 scope global cilium_host\\       valid_lft forever preferred_lft forever'
        )
        result, host = self.run_preflight(FAKE_IP_ROUTES=routes, FAKE_IP_ADDRESS=addresses)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)
        self.assertIn('POD_CIDR=172.21.0.0/16', self.evidence_text(host))

    def test_foreign_route_inside_pod_cidr_still_stops_after_install(self) -> None:
        """豁免只给 CNI 网卡：外部网卡上落进 Pod 段的路由仍是真冲突。"""
        routes = (
            '172.21.0.0/24 via 172.21.0.168 dev cilium_host proto kernel src 172.21.0.168 \n'
            '172.21.8.0/24 dev ens160 scope link'
        )
        result, _ = self.run_preflight(FAKE_IP_ROUTES=routes)

        self.assertEqual(result.returncode, 10)
        self.assertIn('RESULT=STOP_CIDR_OVERLAP', result.stdout)

    def test_passes_without_leaking_command_stderr_canary(self) -> None:
        canary = 'SECRET_CANARY_DO_NOT_LOG'
        result, host = self.run_preflight(FAKE_CANARY=canary)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_PREFLIGHT', result.stdout)
        self.assertIn('SERVER_LOCAL_SCOPE_ONLY', result.stdout)
        self.assertNotIn(canary, result.stdout + result.stderr)
        self.assertNotIn(canary, self.evidence_text(host))


class KernelStageTest(BootstrapTestCase):
    modules_content = 'overlay\nbr_netfilter\n'
    sysctl_content = (
        'net.bridge.bridge-nf-call-iptables = 1\n'
        'net.bridge.bridge-nf-call-ip6tables = 1\n'
        'net.ipv4.ip_forward = 1\n'
    )

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def make_environment(self) -> tuple[dict[str, str], Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        command_log = directory / 'commands.log'
        (host / 'etc/modules-load.d').mkdir(parents=True)
        (host / 'etc/sysctl.d').mkdir(parents=True)
        (host / 'proc/sys/net/bridge').mkdir(parents=True)
        (host / 'proc/sys/net/ipv4').mkdir(parents=True)
        (host / 'sys/module').mkdir(parents=True)
        (host / 'root/dev-infra-evidence').mkdir(parents=True)
        (host / 'swap.img').write_bytes(b'preserve swap\n')
        fake_bin.mkdir()

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'modprobe',
            '''
            #!/bin/sh
            printf 'modprobe %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "${FAKE_MODPROBE_FAIL:-}" != "$1" ] || exit 1
            mkdir -p "$FAKE_HOST_ROOT/sys/module/$1"
            ''',
        )
        self.write_executable(
            fake_bin / 'sysctl',
            '''
            #!/bin/sh
            printf 'sysctl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "${FAKE_SYSCTL_FAIL:-0}" != 1 ] || exit 1
            [ "$1" = "--load" ] && [ "$2" = "$FAKE_HOST_ROOT/etc/sysctl.d/99-kubernetes-cri.conf" ] || exit 2
            printf '%s\n' "${FAKE_BRIDGE_IPV4_VALUE:-1}" >"$FAKE_HOST_ROOT/proc/sys/net/bridge/bridge-nf-call-iptables"
            printf '%s\n' "${FAKE_BRIDGE_IPV6_VALUE:-1}" >"$FAKE_HOST_ROOT/proc/sys/net/bridge/bridge-nf-call-ip6tables"
            printf '%s\n' "${FAKE_IP_FORWARD_VALUE:-1}" >"$FAKE_HOST_ROOT/proc/sys/net/ipv4/ip_forward"
            ''',
        )
        self.write_executable(
            fake_bin / 'mktemp',
            '''
            #!/bin/sh
            temporary=$(/usr/bin/mktemp "$@") || exit
            printf '%s\n' "$temporary"
            if [ -n "${FAKE_MKTEMP_RACE_PARENT:-}" ]; then
              chmod 0700 "$FAKE_MKTEMP_RACE_PARENT"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'mv',
            '''
            #!/bin/sh
            printf 'mv %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            if [ "${FAKE_MV_RACE_TARGET:-}" = "${3:-}" ]; then
              printf 'concurrent\n' >"$FAKE_MV_RACE_TARGET"
              [ "${FAKE_MV_RACE_RC:-0}" = 0 ] && exit 0
              exit "$FAKE_MV_RACE_RC"
            fi
            [ "${FAKE_MV_FAIL_TARGET:-}" != "${3:-}" ] || exit 1
            exec /bin/mv "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'install',
            '''
            #!/bin/sh
            printf 'install %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            exec /usr/bin/install "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'sync',
            '''
            #!/bin/sh
            printf 'sync %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "${FAKE_SYNC_FAIL:-0}" != 1 ]
            ''',
        )

        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_HOST_ROOT': str(host),
            }
        )
        return environment, host, command_log

    def run_stage(
        self, environment: dict[str, str], mode: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', str(PREPARE_KERNEL), mode], env=environment
        )

    def modules_file(self, host: Path) -> Path:
        return host / 'etc/modules-load.d/99-kubernetes.conf'

    def canonical_modules_file(self, host: Path) -> Path:
        return host / 'etc/modules-load.d/99-kubernetes.conf'

    def sysctl_file(self, host: Path) -> Path:
        return host / 'etc/sysctl.d/99-kubernetes-cri.conf'

    def set_persistent_files(self, host: Path) -> None:
        self.modules_file(host).write_text(self.modules_content, encoding='utf-8')
        self.sysctl_file(host).write_text(self.sysctl_content, encoding='utf-8')
        self.modules_file(host).chmod(0o644)
        self.sysctl_file(host).chmod(0o644)

    def set_runtime(self, host: Path, value: str = '1') -> None:
        (host / 'sys/module/overlay').mkdir(exist_ok=True)
        (host / 'sys/module/br_netfilter').mkdir(exist_ok=True)
        for path in (
            host / 'proc/sys/net/bridge/bridge-nf-call-iptables',
            host / 'proc/sys/net/bridge/bridge-nf-call-ip6tables',
            host / 'proc/sys/net/ipv4/ip_forward',
        ):
            path.write_text(f'{value}\n', encoding='utf-8')

    def test_check_rejects_unknown_managed_file_without_overwriting_it(self) -> None:
        """捕获把未知内容、类型或权限漂移误判为可安全覆盖的缺陷。"""
        cases = ('content', 'mode', 'symlink', 'directory')
        for target_name in ('modules', 'sysctl'):
            for drift in cases:
                with self.subTest(target=target_name, drift=drift):
                    environment, host, command_log = self.make_environment()
                    target = (
                        self.modules_file(host)
                        if target_name == 'modules'
                        else self.sysctl_file(host)
                    )
                    expected = (
                        self.modules_content
                        if target_name == 'modules'
                        else self.sysctl_content
                    )
                    if drift == 'content':
                        target.write_text('unknown\n', encoding='utf-8')
                    elif drift == 'mode':
                        target.write_text(expected, encoding='utf-8')
                        target.chmod(0o600)
                    elif drift == 'symlink':
                        target.symlink_to('/tmp/escape')
                    else:
                        target.mkdir()

                    result = self.run_stage(environment, '--check')

                    self.assertEqual(result.returncode, 30, result.stderr)
                    self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                    self.assertTrue(target.exists() or target.is_symlink())
                    self.assertFalse(command_log.exists())

    def test_check_rejects_partial_persistent_installation(self) -> None:
        """捕获只存在一个受管文件时继续安装、掩盖部分安装的缺陷。"""
        for existing in ('modules', 'sysctl'):
            with self.subTest(existing=existing):
                environment, host, command_log = self.make_environment()
                target = (
                    self.modules_file(host)
                    if existing == 'modules'
                    else self.sysctl_file(host)
                )
                content = (
                    self.modules_content
                    if existing == 'modules'
                    else self.sysctl_content
                )
                target.write_text(content, encoding='utf-8')
                target.chmod(0o644)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertFalse(command_log.exists())

    def test_check_uses_canonical_modules_path_and_rejects_legacy_alias(self) -> None:
        """捕获继续管理旧 containerd.conf 或忽略该未知旧别名的缺陷。"""
        environment, host, _ = self.make_environment()
        self.canonical_modules_file(host).write_text(
            self.modules_content, encoding='utf-8'
        )
        self.canonical_modules_file(host).chmod(0o644)
        self.sysctl_file(host).write_text(self.sysctl_content, encoding='utf-8')
        self.sysctl_file(host).chmod(0o644)
        self.set_runtime(host)

        canonical = self.run_stage(environment, '--check')

        self.assertEqual(canonical.returncode, 0, canonical.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', canonical.stdout)

        legacy = host / 'etc/modules-load.d/containerd.conf'
        legacy.write_text(self.modules_content, encoding='utf-8')
        legacy.chmod(0o644)
        legacy_result = self.run_stage(environment, '--check')

        self.assertEqual(legacy_result.returncode, 30, legacy_result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', legacy_result.stdout)

    def test_check_is_read_only_when_kernel_changes_are_needed(self) -> None:
        """捕获默认 CHECK 调用写命令、创建目标或改动 swap 的缺陷。"""
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KERNEL_CHECK', result.stdout)
        self.assertFalse(self.modules_file(host).exists())
        self.assertFalse(self.sysctl_file(host).exists())
        self.assertFalse(command_log.exists())
        self.assertEqual((host / 'swap.img').read_bytes(), b'preserve swap\n')
        self.assertEqual(list((host / 'root/dev-infra-evidence').iterdir()), [])

    def test_check_reports_only_fully_compliant_state_as_already_compliant(self) -> None:
        """捕获仅检查持久文件、遗漏 runtime 模块或 sysctl 的缺陷。"""
        environment, host, command_log = self.make_environment()
        self.set_persistent_files(host)
        self.set_runtime(host)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        self.assertFalse(command_log.exists())

        (host / 'sys/module/overlay').rmdir()
        result = self.run_stage(environment, '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KERNEL_CHECK', result.stdout)
        self.assertFalse(command_log.exists())

    def test_apply_atomically_writes_contract_and_verifies_runtime(self) -> None:
        """捕获内容错误、非原子发布、漏加载模块、漏应用 sysctl 或改 swap 的缺陷。"""
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KERNEL_PREPARED', result.stdout)
        self.assertEqual(
            self.modules_file(host).read_text(encoding='utf-8'),
            self.modules_content,
        )
        self.assertEqual(
            self.sysctl_file(host).read_text(encoding='utf-8'),
            self.sysctl_content,
        )
        self.assertEqual(self.modules_file(host).stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.sysctl_file(host).stat().st_mode & 0o777, 0o644)
        self.assertEqual((host / 'swap.img').read_bytes(), b'preserve swap\n')
        command_text = command_log.read_text(encoding='utf-8')
        self.assertIn('modprobe overlay\n', command_text)
        self.assertIn('modprobe br_netfilter\n', command_text)
        self.assertIn(
            f'sysctl --load {self.sysctl_file(host)}\n', command_text
        )
        evidence = list(
            (host / 'root/dev-infra-evidence').glob('09-prepare-kernel-*.txt')
        )
        self.assertEqual(len(evidence), 1)
        evidence_keys = {
            line.split('=', 1)[0]
            for line in evidence[0].read_text(encoding='utf-8').splitlines()
        }
        self.assertEqual(
            evidence_keys,
            {
                'MODULE_BR_NETFILTER',
                'MODULE_OVERLAY',
                'SYSCTL_BRIDGE_IPV4',
                'SYSCTL_BRIDGE_IPV6',
                'SYSCTL_IP_FORWARD',
                'PHASE',
                'MODE',
                'RESULT',
                'REASON',
                'EVIDENCE',
                'EXIT_CODE',
                'NEXT',
            },
        )

    def test_apply_does_not_rewrite_exact_files_when_only_runtime_drifted(self) -> None:
        """捕获 runtime 修复时无谓覆盖精确持久文件的缺陷。"""
        environment, host, command_log = self.make_environment()
        self.set_persistent_files(host)
        before = (
            self.modules_file(host).stat().st_ino,
            self.sysctl_file(host).stat().st_ino,
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KERNEL_PREPARED', result.stdout)
        after = (
            self.modules_file(host).stat().st_ino,
            self.sysctl_file(host).stat().st_ino,
        )
        self.assertEqual(after, before)
        command_text = command_log.read_text(encoding='utf-8')
        self.assertNotIn('mv ', command_text)
        self.assertNotIn('install ', command_text)

    def test_apply_fails_when_sync_or_runtime_verification_fails(self) -> None:
        """捕获忽略 sync 失败或未逐项验证 /proc/sys 值的缺陷。"""
        environment, host, _ = self.make_environment()
        environment['FAKE_SYNC_FAIL'] = '1'

        sync_result = self.run_stage(environment, '--apply')

        self.assertEqual(sync_result.returncode, 40, sync_result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', sync_result.stdout)
        self.assertFalse(self.modules_file(host).exists())
        self.assertFalse(self.sysctl_file(host).exists())

        environment, host, _ = self.make_environment()
        environment['FAKE_IP_FORWARD_VALUE'] = '0'
        verify_result = self.run_stage(environment, '--apply')

        self.assertEqual(verify_result.returncode, 50, verify_result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', verify_result.stdout)

    def test_apply_never_overwrites_target_that_appears_during_publish(self) -> None:
        """捕获发布竞态覆盖并发创建目标的缺陷。"""
        for conflict_rc in ('0', '1'):
            with self.subTest(conflict_rc=conflict_rc):
                environment, host, _ = self.make_environment()
                target = self.modules_file(host)
                environment.update(
                    {
                        'FAKE_MV_RACE_TARGET': str(target),
                        'FAKE_MV_RACE_RC': conflict_rc,
                    }
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertEqual(
                    target.read_text(encoding='utf-8'), 'concurrent\n'
                )
                self.assertFalse(self.sysctl_file(host).exists())

    def test_apply_keeps_non_conflict_mv_failure_as_apply_failed(self) -> None:
        """捕获把没有并发目标的 mv I/O 失败误分类为 UNKNOWN 的缺陷。"""
        environment, host, _ = self.make_environment()
        target = self.modules_file(host)
        environment['FAKE_MV_FAIL_TARGET'] = str(target)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertFalse(target.exists())

    def test_check_rejects_kernel_parent_and_file_owner_drift(self) -> None:
        """捕获忽略 kernel 受管 parent/file uid:gid 漂移的缺陷。"""
        for target_name in ('modules-parent', 'sysctl-parent', 'modules', 'sysctl'):
            with self.subTest(target=target_name):
                environment, host, _ = self.make_environment()
                self.set_persistent_files(host)
                self.set_runtime(host)
                paths = {
                    'modules-parent': self.modules_file(host).parent,
                    'sysctl-parent': self.sysctl_file(host).parent,
                    'modules': self.modules_file(host),
                    'sysctl': self.sysctl_file(host),
                }
                environment['BOOTSTRAP_TEST_OWNER_DRIFT_PATH'] = str(
                    paths[target_name]
                )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_revalidates_kernel_parent_after_mktemp_race(self) -> None:
        """捕获 mktemp 后 parent 权限竞态仍发布 kernel 文件的缺陷。"""
        environment, host, _ = self.make_environment()
        parent = self.modules_file(host).parent
        environment['FAKE_MKTEMP_RACE_PARENT'] = str(parent)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertFalse(self.modules_file(host).exists())


class BootstrapEntrySecurityTest(BootstrapTestCase):
    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def production_environment(self) -> tuple[dict[str, str], Path]:
        directory = self.temporary_directory()
        fake_bin = directory / 'fake-bin'
        fake_bin.mkdir()
        command_log = directory / 'commands.log'
        for name, output in (
            ('id', '0'),
            ('systemctl', 'active'),
            ('python3', 'FAKE_PYTHON_CONTROLLED'),
        ):
            self.write_executable(
                fake_bin / name,
                f'''#!/bin/sh
                printf '{name} controlled\\n' >>"$FAKE_COMMAND_LOG"
                printf '%s\\n' '{output}'
                ''',
            )
        environment = self.sanitized_environment(
            PATH=f'{fake_bin}:/usr/bin:/bin',
            FAKE_COMMAND_LOG=str(command_log),
        )
        return environment, command_log

    def test_environment_rejection_names_offending_variables(self) -> None:
        """拒绝不可信环境时必须列出违规变量名（只列名不列值），便于运维定位 unset。"""
        for script in (INSTALL_CILIUM, FINAL_VERIFY):
            with self.subTest(script=script.name):
                environment, command_log = self.production_environment()
                environment['KUBECACHEDIR'] = '/dev/null'
                environment['PYTHONDONTWRITEBYTECODE'] = '1'

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(
                    'REASON=untrusted-environment-override', result.stderr
                )
                self.assertIn(
                    'VARS=KUBECACHEDIR,PYTHONDONTWRITEBYTECODE', result.stderr
                )
                self.assertNotIn('/dev/null', result.stderr)
                self.assertFalse(command_log.exists())

    def test_environment_rejection_lists_fixed_names_in_kubernetes_stages(self) -> None:
        for script in (INSTALL_KUBERNETES, KUBEADM_INIT):
            with self.subTest(script=script.name):
                environment, command_log = self.production_environment()
                environment['APT_CONFIG'] = '/tmp/unapproved-apt.conf'
                environment['KUBECONFIG'] = '/tmp/unapproved-kubeconfig'

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('VARS=APT_CONFIG,KUBECONFIG', result.stderr)
                self.assertNotIn('unapproved', result.stderr)
                self.assertFalse(command_log.exists())

    def test_environment_rejection_deduplicates_fixed_and_prefix_names(self) -> None:
        """KUBECTL_EXTERNAL_DIFF 同时命中固定清单与 KUBECTL_ 前缀，只能列出一次。"""
        for script in (INSTALL_CILIUM, FINAL_VERIFY):
            with self.subTest(script=script.name):
                environment, _ = self.production_environment()
                environment['KUBECTL_EXTERNAL_DIFF'] = 'diff'

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('VARS=KUBECTL_EXTERNAL_DIFF', result.stderr)
                self.assertEqual(
                    result.stderr.count('KUBECTL_EXTERNAL_DIFF'), 1
                )

    def test_production_fixes_safe_path_before_command_lookup(self) -> None:
        """捕获 production 从调用者 PATH 执行伪造 id/systemctl/python3 的缺陷。"""
        self.assertNotEqual(os.geteuid(), 0, '该用例必须由实际非 root 用户运行')
        for script in (
            PREPARE_KERNEL, INSTALL_CONTAINERD, INSTALL_KUBERNETES, KUBEADM_INIT,
        ):
            with self.subTest(script=script.name):
                environment, command_log = self.production_environment()

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('REASON=not-root', result.stdout)
                self.assertFalse(command_log.exists())

    def test_production_rejects_all_test_overrides_before_lookup(self) -> None:
        """捕获 production 接受 TEST_ROOT/LOCK/owner seam 或先执行不可信命令的缺陷。"""
        # 六个 source lib/path-facts.sh 的 stage 都要覆盖：漂移缝在库里是并集，
        # 安全性完全依赖入口守卫拦在 source 之前。
        for script in (
            PREPARE_KERNEL, INSTALL_CONTAINERD, INSTALL_KUBERNETES, KUBEADM_INIT,
            INSTALL_CILIUM, FINAL_VERIFY,
        ):
            with self.subTest(script=script.name):
                environment, command_log = self.production_environment()
                environment.update(
                    {
                        'BOOTSTRAP_TEST_ROOT': '/',
                        'BOOTSTRAP_TEST_LOCK_FILE': '/tmp/unapproved.lock',
                        'BOOTSTRAP_TEST_OWNER_DRIFT_PATH': '/etc',
                    }
                )

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('REASON=test-override-in-production', result.stderr)
                self.assertFalse(command_log.exists())

    def ambient_environment(self, **variables: str) -> None:
        """把变量塞进本进程环境并在用例结束后精确还原（原本存在的恢复原值）。"""
        for name, value in variables.items():
            if name in os.environ:
                self.addCleanup(os.environ.__setitem__, name, os.environ[name])
            else:
                self.addCleanup(os.environ.pop, name, None)
            os.environ[name] = value

    def test_untrusted_guard_parse_is_not_vacuous(self) -> None:
        """解析若失灵会让下面两条用例静默空转，这里先钉住解析结果本身。"""
        probe = self.untrusted_environment_probe()

        self.assertGreaterEqual(len(probe), 20, probe)
        for name in (
            'APT_CONFIG', 'KUBECONFIG', 'GNUPGHOME', 'TAR_OPTIONS',
            'BASH_ENV', 'ENV', 'KUBECACHEDIR', 'IMAGE_SERVICE_ENDPOINT',
            'HELM_DRIVER', 'DPKG_ROOT',
        ):
            with self.subTest(name=name):
                self.assertIn(name, probe)
        for prefix in ('HELM_', 'PYTHON', 'OPENSSL_', 'KUBECTL_', 'BOOTSTRAP_TEST_'):
            with self.subTest(prefix=prefix):
                self.assertIn(f'{prefix}PROBE', probe)

    def test_every_bootstrap_entry_enables_fail_closed_shell_flags(self) -> None:
        """捕获入口脚本丢掉 -E/-e/-u/pipefail、或把它放在第一条命令之后的缺陷。

        九个 lib 都不自设 flag，靠 source 它们的 shell 继承。lib/exec-safety.sh 的
        fail-closed 保证——PYTHON_BINARY 缺失时报未绑定变量，而不是拿空命令继续——
        就建立在这个前提上，而此前没有任何用例钉住它。钉「第一条可执行语句」而不是
        行号：flag 必须在任何命令与任何 source 之前生效，注释与空行不算。
        """
        # stage 走表（迁移后不在 bootstrap/ 顶层），非 stage 入口仍按通配收集。
        scripts = sorted(
            {ROOT / path for path in STAGE_SCRIPTS.values()}
            | set(BOOTSTRAP_ALL.parent.glob('*.sh'))
        )
        self.assertGreaterEqual(len(scripts), 11, '入口脚本集合异常')
        for script in scripts:
            with self.subTest(script=script.name):
                # 只钉 flag，不钉 shebang：00-50 用 #!/usr/bin/env bash、60/90 用
                # #!/bin/bash -p，差异是有依据的——bootstrap-all.sh 以
                # `/usr/bin/env -u BASH_ENV -u ENV /bin/bash -p "$script"` 调用每个
                # stage，脚本当参数传入，自身 shebang 不参与；保护边界在调用侧。
                # 60/90 因为 runbook 里会被单独执行才自带 -p。
                lines = script.read_text(encoding='utf-8').splitlines()
                # 只跳过真正的 shebang。早先写成无条件丢掉第 1 行，等于把它变成
                # 盲区：把 shebang 换成 `PATH=/attacker/bin:$PATH` 这种真会执行的
                # 命令，用例照样绿（独立评审实测）。
                body = lines[1:] if lines and lines[0].startswith('#!') else lines
                executable = [
                    line for line in body
                    if line.strip() and not line.lstrip().startswith('#')
                ]
                self.assertTrue(executable, f'{script.name} 没有可执行语句')
                self.assertEqual(
                    executable[0],
                    'set -Eeuo pipefail',
                    f'{script.name} 的第一条可执行语句不是 fail-closed flag',
                )

    def test_no_test_harness_inherits_the_caller_environment(self) -> None:
        """捕获任何子进程环境构造器整体继承调用者 shell 的缺陷。

        stage 的不可信环境守卫按**名字前缀**判死（60/90 有 HELM_/PYTHON/OPENSSL_/
        KUBECTL_ 四组通配），"继承后再擦具名黑名单"原理上覆盖不了前缀。此前
        production_environment 已改白名单，但 CiliumInstallTest 与 FinalVerifyTest
        的构造器仍在继承，调用者 shell 里一个 PYTHONUNBUFFERED 就让这两个最慢的
        分片共 81 条用例以 untrusted-environment-override 假红（独立评审实测）。
        这条断言钉的是模式本身，防止任何一处重新长回来。
        """
        # 分片拼出被禁的写法，否则本用例自身的源码就会命中自己。
        forbidden = 'os.environ' + '.copy()'
        modules = {
            'test_bootstrap.py': ROOT / 'scripts/test_bootstrap.py',
            'test_validate.py': ROOT / 'scripts/test_validate.py',
        }
        for name, path in modules.items():
            with self.subTest(module=name):
                offenders = [
                    number
                    for number, line in enumerate(
                        path.read_text(encoding='utf-8').splitlines(), 1
                    )
                    if forbidden in line and 'forbidden =' not in line
                ]
                self.assertEqual(
                    offenders, [], f'{name} 这些行整体继承了调用者环境'
                )
        # 非空转守卫：统一构造器必须真的被广泛使用，否则上面那条断言可以靠
        # "把所有构造器都删掉" 来满足。
        harness = modules['test_bootstrap.py'].read_text(encoding='utf-8')
        self.assertGreaterEqual(
            harness.count('self.sanitized_environment('), 12, harness.count('self.sanitized_environment(')
        )

    def test_production_environment_admits_no_ambient_variable(self) -> None:
        """捕获用例环境继承调用者 shell 的缺陷：白名单之外一个都不许进来。"""
        probe = self.untrusted_environment_probe()
        self.ambient_environment(**probe)

        environment, _ = self.production_environment()

        for name in probe:
            with self.subTest(variable=name):
                self.assertNotIn(name, environment)

    def test_ambient_environment_cannot_flip_the_production_verdict(
        self,
    ) -> None:
        """捕获调用者环境改写守卫次序的缺陷。

        `validate-fast.sh` 与 `validate.sh` 曾以 `PYTHONDONTWRITEBYTECODE=1 python3 …`
        前缀赋值启动套件，该变量被导出后一路继承进 stage 子进程，撞上 60/90 的
        `${!PYTHON@}` 通配，REASON 从 test-override-in-production 变成
        untrusted-environment-override——本地恒红两条而 CI 全绿。用例环境必须与
        调用者的 shell 无关，否则任何人导出 KUBECONFIG 或 HELM_* 都会重演。
        """
        for script in (INSTALL_CILIUM, FINAL_VERIFY):
            with self.subTest(script=script.name):
                self.ambient_environment(**self.untrusted_environment_probe())
                environment, command_log = self.production_environment()
                environment['BOOTSTRAP_TEST_ROOT'] = '/'

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(
                    'REASON=test-override-in-production', result.stderr
                )
                self.assertFalse(command_log.exists())

    def test_kubernetes_stages_reject_apt_and_kubeconfig_environment(self) -> None:
        for script in (INSTALL_KUBERNETES, KUBEADM_INIT):
            for variable, value in (
                ('APT_CONFIG', ''),
                ('APT_CONFIG', '/tmp/unapproved-apt.conf'),
                ('KUBECONFIG', ''),
                ('KUBECONFIG', '/tmp/unapproved-kubeconfig'),
            ):
                with self.subTest(
                    script=script.name, variable=variable, value=value
                ):
                    environment, command_log = self.production_environment()
                    environment[variable] = value

                    result = self.run_command(
                        ['/bin/bash', str(script), '--check'], env=environment
                    )

                    self.assertEqual(result.returncode, 10, result.stderr)
                    self.assertIn(
                        'REASON=untrusted-environment-override', result.stderr
                    )
                    self.assertFalse(command_log.exists())

    def test_kubernetes_install_rejects_gnupghome_environment(self) -> None:
        for value in ('', '/tmp/unapproved-gnupg-home'):
            with self.subTest(value=value):
                environment, command_log = self.production_environment()
                environment['GNUPGHOME'] = value

                result = self.run_command(
                    ['/bin/bash', str(INSTALL_KUBERNETES), '--check'],
                    env=environment,
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn(
                    'REASON=untrusted-environment-override', result.stderr
                )
                self.assertFalse(command_log.exists())

    def test_kubernetes_stages_reject_dpkg_environment(self) -> None:
        for script in (INSTALL_KUBERNETES, KUBEADM_INIT):
            for variable in (
                'DPKG_ADMINDIR',
                'DPKG_ROOT',
                'DPKG_FORCE',
                'DPKG_FRONTEND_LOCKED',
            ):
                for value in ('', '/tmp/unapproved-dpkg-state'):
                    with self.subTest(
                        script=script.name,
                        variable=variable,
                        value=value,
                    ):
                        environment, command_log = self.production_environment()
                        environment[variable] = value

                        result = self.run_command(
                            ['/bin/bash', str(script), '--check'], env=environment
                        )

                        self.assertEqual(result.returncode, 10, result.stderr)
                        self.assertIn(
                            'REASON=untrusted-environment-override', result.stderr
                        )
                        self.assertFalse(command_log.exists())

    def test_test_mode_requires_non_root_mapped_root(self) -> None:
        """捕获 test mode 映射到真实 `/` 或省略隔离 test root 的缺陷。"""
        for script in (
            PREPARE_KERNEL, INSTALL_CONTAINERD, INSTALL_KUBERNETES, KUBEADM_INIT,
        ):
            with self.subTest(script=script.name):
                environment, command_log = self.production_environment()
                environment.update(
                    {
                        'BOOTSTRAP_TEST_MODE': '1',
                        'BOOTSTRAP_TEST_ROOT': '/',
                    }
                )

                result = self.run_command(
                    ['/bin/bash', str(script), '--check'], env=environment
                )

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('REASON=test-root-must-be-isolated', result.stderr)
                self.assertFalse(command_log.exists())


class RunApprovedTest(BootstrapTestCase):
    """一行式运维入口：门禁 + 干净环境启动 bootstrap-all。"""

    def write_executable(self, path: Path, source: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def git(self, *arguments: str, cwd: Path) -> None:
        completed = subprocess.run(
            # 固定注入上游 git 的默认分支 master：fixture 必须自己显式声明 main，
            # 否则裸仓 HEAD 指向不存在的 master，clone 成功却得到空工作树（CI 曾如此）。
            ['/usr/bin/git', '-c', 'user.name=t', '-c', 'user.email=t@t',
             '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=master',
             *arguments],
            cwd=cwd, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def make_gated_repo(
        self, *, origin_name: str = 'unif-code/engineering-platform-gitops.git'
    ) -> tuple[Path, str]:
        """返回 (落后一个提交的 clone, 已批准的 origin/main SHA)。"""
        directory = self.temporary_directory()
        bare = directory / origin_name
        bare.parent.mkdir(parents=True, exist_ok=True)
        self.git('init', '--bare', '--initial-branch', 'main', str(bare), cwd=directory)
        seed = directory / 'seed'
        self.git('init', '--initial-branch', 'main', str(seed), cwd=directory)
        scripts = seed / 'scripts/bootstrap'
        scripts.mkdir(parents=True)
        (scripts / 'run-approved.sh').write_bytes(RUN_APPROVED.read_bytes())
        (scripts / 'run-approved.sh').chmod(0o755)
        self.write_executable(
            scripts / 'bootstrap-all.sh',
            '#!/bin/bash\n'
            'printf \'FAKE_MODE=%s\\n\' "$1"\n'
            'printf \'KUBECACHEDIR_SEEN=%s\\n\' "${KUBECACHEDIR:-ABSENT}"\n'
            'printf \'PYTHON_SEEN=%s\\n\' "${PYTHONDONTWRITEBYTECODE:-ABSENT}"\n',
        )
        self.git('add', '-A', cwd=seed)
        self.git('commit', '-q', '-m', 'seed', cwd=seed)
        self.git('remote', 'add', 'origin', str(bare), cwd=seed)
        self.git('push', '-q', 'origin', 'main', cwd=seed)
        clone = directory / 'clone'
        self.git('clone', '-q', str(bare), str(clone), cwd=directory)
        self.assertTrue(
            (clone / 'scripts/bootstrap/run-approved.sh').is_file(),
            'clone 必须包含入口脚本；空工作树说明裸仓 HEAD 指向了错误的默认分支',
        )
        (seed / 'approved.txt').write_text('approved\n', encoding='utf-8')
        self.git('add', '-A', cwd=seed)
        self.git('commit', '-q', '-m', 'approved', cwd=seed)
        self.git('push', '-q', 'origin', 'main', cwd=seed)
        head = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=seed,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return clone, head, seed

    def publish_validated(self, seed: Path, sha: str) -> None:
        """模拟 CI 在 validation-gate 全绿后发布 validated 分支。"""
        self.git('push', '-q', '--force', 'origin', f'{sha}:refs/heads/validated', cwd=seed)

    def side_commit(self, seed: Path) -> str:
        """制造一个不在 main 历史上的提交。"""
        self.git('checkout', '-q', '-b', 'side', cwd=seed)
        (seed / 'side.txt').write_text('side\n', encoding='utf-8')
        self.git('add', '-A', cwd=seed)
        self.git('commit', '-q', '-m', 'side', cwd=seed)
        sha = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=seed,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.git('checkout', '-q', 'main', cwd=seed)
        return sha

    def run_wrapper(
        self, clone: Path, *arguments: str, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = self.sanitized_environment()
        environment.update(extra_env or {})
        return subprocess.run(
            ['/bin/bash', str(clone / 'scripts/bootstrap/run-approved.sh'), *arguments],
            cwd=clone, capture_output=True, text=True, check=False,
            env=environment,
        )

    def test_gates_then_launches_bootstrap_in_clean_environment(self) -> None:
        clone, approved, _ = self.make_gated_repo()

        result = self.run_wrapper(
            clone, approved, '--check',
            extra_env={'KUBECACHEDIR': '/dev/null', 'PYTHONDONTWRITEBYTECODE': '1'},
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('FAKE_MODE=--check', result.stdout)
        self.assertIn('KUBECACHEDIR_SEEN=ABSENT', result.stdout)
        self.assertIn('PYTHON_SEEN=ABSENT', result.stdout)
        self.assertIn('COMMAND_EXIT_CODE=0', result.stdout)
        head = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=clone,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertEqual(head, approved)

    def test_defaults_to_ci_published_validated_ref(self) -> None:
        """不带 SHA 时使用 CI 发布的 origin/validated，运维无需手工转述 40 位字符。"""
        clone, approved, seed = self.make_gated_repo()
        self.publish_validated(seed, approved)

        result = self.run_wrapper(clone, '--check')

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'APPROVED_SHA={approved}', result.stdout)
        self.assertIn('source=origin/validated', result.stdout)
        self.assertIn('FAKE_MODE=--check', result.stdout)
        head = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=clone,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertEqual(head, approved)

    def test_uses_validated_even_when_main_moved_ahead(self) -> None:
        """main 上有尚未通过 CI 的新提交时，只部署 validated 指向的那个绿提交。"""
        clone, approved, seed = self.make_gated_repo()
        self.publish_validated(seed, approved)
        (seed / 'unvalidated.txt').write_text('later\n', encoding='utf-8')
        self.git('add', '-A', cwd=seed)
        self.git('commit', '-q', '-m', 'not yet validated', cwd=seed)
        self.git('push', '-q', 'origin', 'main', cwd=seed)

        result = self.run_wrapper(clone, '--check')

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        head = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=clone,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertEqual(head, approved, 'must deploy validated, not the newer main tip')

    def test_stops_when_validated_ref_is_unavailable_or_off_main(self) -> None:
        clone, _, seed = self.make_gated_repo()
        result = self.run_wrapper(clone, '--check')
        self.assertEqual(result.returncode, 99, result.stdout + result.stderr)
        self.assertIn('STOP: validated ref unavailable', result.stdout)
        self.assertNotIn('FAKE_MODE', result.stdout)

        self.publish_validated(seed, self.side_commit(seed))
        result = self.run_wrapper(clone, '--check')
        self.assertEqual(result.returncode, 100, result.stdout + result.stderr)
        self.assertIn('STOP: validated ref is not on origin/main history', result.stdout)
        self.assertNotIn('FAKE_MODE', result.stdout)

    def test_explicit_sha_reports_its_source(self) -> None:
        clone, approved, seed = self.make_gated_repo()
        self.publish_validated(seed, approved)

        result = self.run_wrapper(clone, approved, '--check')

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'APPROVED_SHA={approved}', result.stdout)
        self.assertIn('source=argument', result.stdout)

    def test_refuses_invalid_arguments(self) -> None:
        clone, approved, _ = self.make_gated_repo()
        for arguments, code in (
            (('not-a-sha', '--check'), 90),
            ((approved, '--force'), 2),
            ((approved,), 2),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_wrapper(clone, *arguments)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertNotIn('FAKE_MODE', result.stdout)

    def test_apply_requires_root(self) -> None:
        self.assertNotEqual(os.geteuid(), 0, '该用例必须由实际非 root 用户运行')
        clone, approved, _ = self.make_gated_repo()

        result = self.run_wrapper(clone, approved, '--apply')

        self.assertEqual(result.returncode, 91, result.stdout)
        self.assertIn('STOP: --apply must run as root', result.stdout)
        self.assertNotIn('FAKE_MODE', result.stdout)

    def test_stops_on_dirty_worktree_origin_name_and_sha_mismatch(self) -> None:
        clone, approved, _ = self.make_gated_repo()
        (clone / 'dirty.txt').write_text('dirty\n', encoding='utf-8')
        result = self.run_wrapper(clone, approved, '--check')
        self.assertEqual(result.returncode, 95, result.stdout)
        self.assertIn('STOP: worktree is not clean', result.stdout)
        (clone / 'dirty.txt').unlink()

        stale = subprocess.run(
            ['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=clone,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        result = self.run_wrapper(clone, stale, '--check')
        self.assertEqual(result.returncode, 96, result.stdout)
        self.assertIn('STOP: origin/main SHA mismatch', result.stdout)

        wrong_clone, wrong_approved, _ = self.make_gated_repo(origin_name='wrong-name.git')
        result = self.run_wrapper(wrong_clone, wrong_approved, '--check')
        self.assertEqual(result.returncode, 93, result.stdout)
        self.assertIn('STOP: unexpected origin', result.stdout)
        self.assertNotIn('FAKE_MODE', result.stdout)


class BootstrapOrchestratorTest(BootstrapTestCase):
    commit = '0123456789abcdef0123456789abcdef01234567'
    canary = 'SECRET_CANARY_ORCHESTRATOR_DO_NOT_LOG'
    library_names = (
        'common.sh',
        'host-config.sh',
        'os-release.sh',
    )

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def setUp(self) -> None:
        self.fixture_root = self.temporary_directory().resolve()
        self.stage_dir = self.fixture_root / 'stages'
        self.library_dir = self.stage_dir / 'lib'
        self.state_dir = self.fixture_root / 'state'
        self.fake_bin = self.fixture_root / 'bin'
        for directory in (self.stage_dir, self.state_dir, self.fake_bin):
            directory.mkdir()
            directory.chmod(0o700)
        self.command_log = self.fixture_root / 'commands.log'
        self.lock_dir = self.fixture_root / 'lock'
        self.lock_dir.mkdir(mode=0o777)
        self.lock_dir.chmod(0o1777)
        self.lock_file = self.lock_dir / 'bootstrap.lock'
        self.command_log.write_text('', encoding='utf-8')
        # 真实 bootstrap 目录里有 check_cidrs.py，且它被 stage 以 root 执行，因此在
        # 门禁覆盖范围内；fixture 必须同构，否则门禁会因文件缺失而对所有用例判死。
        cidr = self.stage_dir / 'check_cidrs.py'
        cidr.write_text('#!/usr/bin/env python3\n', encoding='utf-8')
        cidr.chmod(0o644)
        self.write_fake_stages()
        self.write_fake_library()
        self.write_fake_commands()

        self.base_environment = self.sanitized_environment()
        for name in tuple(self.base_environment):
            if name.startswith('BOOTSTRAP_ORCHESTRATOR_TEST_'):
                del self.base_environment[name]
        self.base_environment.update(
            {
                'PATH': f'{self.fake_bin}:/usr/bin:/bin',
                'BOOTSTRAP_ORCHESTRATOR_TEST_MODE': '1',
                'BOOTSTRAP_ORCHESTRATOR_TEST_STAGE_DIR': str(self.stage_dir),
                'BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE': str(self.lock_file),
                'ORCHESTRATOR_STATE_DIR': str(self.state_dir),
                'FAKE_COMMAND_LOG': str(self.command_log),
                'FAKE_GIT_COMMIT': self.commit,
            }
        )
        self.environment = self.base_environment.copy()

    def write_fake_stages(self) -> None:
        source = r'''
            #!/bin/sh
            stage=${0##*/}
            if [ "$stage" = run.sh ]; then
              parent=${0%/*}
              stage=${parent##*/}
            fi
            stage=${stage%%-*}
            [ "$#" -eq 1 ] || exit 10
            case "$1" in
              --check) mode=CHECK ;;
              --apply) mode=APPLY ;;
              *) exit 10 ;;
            esac
            printf '%s %s\n' "$stage" "$1" >>"$FAKE_COMMAND_LOG"

            if [ -n "${FAKE_STAGE_STOP:-}" ] &&
               [ "${FAKE_STAGE_STOP%%:*}" = "$stage" ]; then
              printf '%s\n' "${FAKE_STAGE_STDOUT_MARKER:-stage-stop-stdout}"
              printf '%s\n' "${FAKE_STAGE_STDERR_MARKER:-stage-stop-stderr}" >&2
              exit "${FAKE_STAGE_STOP#*:}"
            fi

            case "$stage" in
              00)
                result=PASS_PREFLIGHT
                reason=preflight-ready
                ;;
              90)
                result=PASS_BOOTSTRAP_VERIFIED
                reason=verification-ready
                ;;
              10)
                check_result=PASS_ARTIFACTS_CHECK
                apply_result=PASS_ARTIFACTS_STAGED
                ;;
              20)
                check_result=PASS_KERNEL_CHECK
                apply_result=PASS_KERNEL_PREPARED
                ;;
              30)
                check_result=PASS_CONTAINERD_CHECK
                apply_result=PASS_CONTAINERD_INSTALLED
                ;;
              40)
                check_result=PASS_KUBERNETES_CHECK
                apply_result=PASS_KUBERNETES_INSTALLED
                ;;
              50)
                check_result=PASS_KUBEADM_CHECK
                apply_result=PASS_KUBEADM_INITIALIZED
                ;;
              60)
                check_result=PASS_CILIUM_CHECK
                apply_result=PASS_CILIUM_INSTALLED
                ;;
              *) exit 30 ;;
            esac

            case "$stage" in
              00|90) ;;
              *)
                if [ "$1" = --check ]; then
                  if [ -f "$ORCHESTRATOR_STATE_DIR/$stage" ] &&
                     [ "${FAKE_POSTCHECK_STALE:-}" != "$stage" ]; then
                    result=ALREADY_COMPLIANT
                    reason=stage-ready
                  else
                    result=$check_result
                    reason=apply-required
                  fi
                else
                  : >"$ORCHESTRATOR_STATE_DIR/$stage"
                  result=$apply_result
                  reason=stage-ready
                fi
                ;;
            esac

            evidence=NONE
            sha256=NONE
            exit_code=0
            next=${FAKE_STAGE_NEXT:-NONE}
            malformed=${FAKE_STAGE_MALFORMED:-}
            if [ "${malformed%%:*}" = "$stage" ]; then
              case "${malformed#*:}" in
                exit-mismatch) exit_code=10 ;;
                unknown-result) result=UNAPPROVED_RESULT ;;
                result-canary) result=$FAKE_STAGE_CANARY ;;
                unsafe-evidence)
                  evidence="/tmp/$FAKE_STAGE_CANARY"
                  evidence=$(printf '%s\033' "$evidence")
                  ;;
                unsafe-sha) sha256=ABCDEF ;;
              esac
            fi
            printf 'PHASE=%s\nMODE=%s\nRESULT=%s\nREASON=%s\nEVIDENCE=%s\nEXIT_CODE=%s\nNEXT=%s\nSHA256=%s\n' \
              "$stage" "$mode" "$result" "$reason" "$evidence" \
              "$exit_code" "$next" "$sha256"
            if [ "$malformed" = "$stage:duplicate-result" ]; then
              printf 'RESULT=%s\n' "$result"
            fi
            if [ "$malformed" = "$stage:duplicate-exit" ]; then
              printf 'EXIT_CODE=10\n'
            fi
        '''
        # 整棵重建：目录级篡改（chmod/符号链接/多塞条目）不是重写文件能撤销的，
        # 留到下一个子用例就会让它误判——门禁会先在残留的坏目录上判死。
        stages_root = self.stage_dir / 'stages'
        if stages_root.is_symlink() or stages_root.is_file():
            stages_root.unlink()
        elif stages_root.is_dir():
            shutil.rmtree(stages_root)
        stages_root.mkdir(mode=0o755)
        for relative in self.stage_paths.values():
            target = self.stage_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            self.write_executable(target, source)

    def write_fake_library(self) -> None:
        """重建 stage 目录下的被 source 库，用于复原被破坏的 fixture。"""
        if self.library_dir.is_symlink() or self.library_dir.is_file():
            self.library_dir.unlink()
        elif self.library_dir.is_dir():
            shutil.rmtree(self.library_dir)
        self.library_dir.mkdir()
        self.library_dir.chmod(0o700)
        for name in self.library_names:
            library_file = self.library_dir / name
            library_file.write_text(
                f'# fixture library {name}\n', encoding='utf-8'
            )
            library_file.chmod(0o644)

    def write_fake_commands(self) -> None:
        self.write_executable(
            self.fake_bin / 'git',
            r'''
            #!/bin/sh
            if [ "$1" = -C ]; then
              shift 2
            fi
            case "$*" in
              'rev-parse HEAD')
                printf '%s\n' "${FAKE_GIT_COMMIT:-}"
                ;;
              'branch --show-current')
                printf '%s\n' "${FAKE_GIT_BRANCH:-main}"
                ;;
              'status --porcelain=v1 --untracked-files=all')
                [ "${FAKE_GIT_STATUS_FAIL:-0}" != 1 ] || exit 2
                [ "${FAKE_GIT_DIRTY:-0}" != 1 ] || printf ' M fixture\n'
                ;;
              *) exit 2 ;;
            esac
            ''',
        )
        self.write_executable(
            self.fake_bin / 'flock',
            r'''
            #!/bin/sh
            [ "$*" = '-n 9' ] || exit 2
            if [ "${FAKE_LOCK_RACE:-0}" = 1 ]; then
              rm -f -- "$BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE"
              ln -s "$FAKE_LOCK_RACE_TARGET" \
                "$BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE"
              printf 'fd-nine-locked\n' >&9
            fi
            [ "${FAKE_FLOCK_FAIL:-0}" != 1 ]
            ''',
        )

    def reset_fixture(self) -> None:
        for path in self.state_dir.iterdir():
            path.unlink()
        self.command_log.write_text('', encoding='utf-8')
        self.environment = self.base_environment.copy()

    def run_orchestrator(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.assertTrue(
            BOOTSTRAP_ALL.exists(), 'bootstrap-all.sh entry is missing'
        )
        return self.run_command(
            ['/bin/bash', '-p', str(BOOTSTRAP_ALL), *arguments],
            env=environment if environment is not None else self.environment,
        )

    def run_orchestrator_direct(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.assertTrue(
            BOOTSTRAP_ALL.exists(), 'bootstrap-all.sh entry is missing'
        )
        return self.run_command(
            [str(BOOTSTRAP_ALL), *arguments],
            env=environment if environment is not None else self.environment,
        )

    def test_direct_entry_ignores_path_bash_and_bash_env(self) -> None:
        fake_bash_marker = self.fixture_root / 'fake-bash-ran'
        bash_env_marker = self.fixture_root / 'bash-env-ran'
        bash_env = self.fixture_root / 'caller-bash-env.sh'
        bash_env.write_text(
            ': >"$FAKE_BASH_ENV_MARKER"\n', encoding='utf-8'
        )
        self.write_executable(
            self.fake_bin / 'bash',
            '''#!/bin/sh
            : >"$FAKE_BASH_MARKER"
            exec /bin/bash "$@"
            ''',
        )
        environment = self.environment.copy()
        environment.update(
            {
                'BASH_ENV': str(bash_env),
                'FAKE_BASH_MARKER': str(fake_bash_marker),
                'FAKE_BASH_ENV_MARKER': str(bash_env_marker),
            }
        )

        result = self.run_orchestrator_direct(
            '--check', environment=environment
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_CHECK', result.stdout)
        self.assertFalse(fake_bash_marker.exists())
        self.assertFalse(bash_env_marker.exists())

    def test_check_stops_read_only_at_first_apply_required_stage(self) -> None:
        result = self.run_orchestrator('--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_CHECK', result.stdout)
        self.assertIn('NEXT_STAGE=10', result.stdout)
        self.assertEqual(list(self.state_dir.iterdir()), [])

    def test_check_resumes_from_every_legal_checkpoint(self) -> None:
        cases = (
            ((), 'PASS_BOOTSTRAP_CHECK', '10'),
            (('10',), 'PASS_BOOTSTRAP_CHECK', '20'),
            (('10', '20'), 'PASS_BOOTSTRAP_CHECK', '30'),
            (('10', '20', '30'), 'PASS_BOOTSTRAP_CHECK', '40'),
            (('10', '20', '30', '40'), 'PASS_BOOTSTRAP_CHECK', '50'),
            (('10', '20', '30', '40', '50'), 'PASS_BOOTSTRAP_CHECK', '60'),
            (
                ('10', '20', '30', '40', '50', '60'),
                'PASS_BOOTSTRAP_ALL_CHECK',
                'NONE',
            ),
        )
        for completed, expected_result, expected_next in cases:
            with self.subTest(completed=completed):
                self.reset_fixture()
                for stage in completed:
                    (self.state_dir / stage).touch()

                result = self.run_orchestrator('--check')

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'RESULT={expected_result}', result.stdout)
                self.assertIn(f'NEXT_STAGE={expected_next}', result.stdout)
                expected_checks = ['00', *completed]
                expected_checks.append('90' if expected_next == 'NONE' else expected_next)
                self.assertEqual(
                    self.command_log.read_text(encoding='utf-8').splitlines(),
                    [f'{stage} --check' for stage in expected_checks],
                )

    def test_apply_on_fully_complete_state_performs_no_stage_apply(self) -> None:
        for stage in ('10', '20', '30', '40', '50', '60'):
            (self.state_dir / stage).touch()

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_ALL', result.stdout)
        self.assertIn('NEXT_STAGE=NONE', result.stdout)
        lines = self.command_log.read_text(encoding='utf-8').splitlines()
        self.assertEqual(
            lines,
            [f'{stage} --check' for stage in ('00', '10', '20', '30', '40', '50', '60', '90')],
        )
        self.assertTrue(all('--apply' not in line for line in lines))

    def test_apply_resumes_at_40_and_reaches_final_verify(self) -> None:
        for stage in ('10', '20', '30'):
            (self.state_dir / stage).touch()

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_ALL', result.stdout)
        log = self.command_log.read_text(encoding='utf-8')
        self.assertNotIn('10 --apply', log)
        self.assertNotIn('20 --apply', log)
        self.assertNotIn('30 --apply', log)
        self.assertIn('40 --apply', log)
        self.assertIn('90 --check', log)

    def test_nonzero_stage_exit_is_preserved(self) -> None:
        self.environment['FAKE_STAGE_STOP'] = '40:20'
        self.environment['FAKE_STAGE_STDOUT_MARKER'] = 'stage-40-stdout-stop'
        self.environment['FAKE_STAGE_STDERR_MARKER'] = 'stage-40-stderr-stop'

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 20)
        diagnostics = result.stdout + result.stderr
        self.assertIn('stage-40-stdout-stop', diagnostics)
        self.assertIn('stage-40-stderr-stop', diagnostics)
        self.assertNotIn('STAGE_40_', diagnostics)

    def test_zero_exit_with_malformed_result_stops_unknown(self) -> None:
        self.environment['FAKE_STAGE_MALFORMED'] = '40:duplicate-result'

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 30)
        self.assertIn('RESULT=STOP_ORCHESTRATOR', result.stdout)

    def test_structured_output_and_postcheck_fail_closed(self) -> None:
        cases = (
            ('FAKE_POSTCHECK_STALE', '40', 'post-apply-check-not-compliant'),
            ('FAKE_STAGE_MALFORMED', '40:exit-mismatch', 'invalid-stage-output'),
            ('FAKE_STAGE_MALFORMED', '40:unknown-result', 'invalid-stage-result'),
            ('FAKE_STAGE_MALFORMED', '40:unsafe-sha', 'invalid-stage-output'),
            ('FAKE_STAGE_MALFORMED', '40:duplicate-exit', 'invalid-stage-output'),
        )
        for variable, value, reason in cases:
            with self.subTest(variable=variable, value=value):
                self.reset_fixture()
                self.environment[variable] = value

                result = self.run_orchestrator('--apply')

                self.assertEqual(result.returncode, 30)
                self.assertIn('RESULT=STOP_ORCHESTRATOR', result.stdout)
                self.assertIn(f'REASON={reason}', result.stdout)

    def test_apply_requires_main_clean_repo_and_exclusive_lock(self) -> None:
        cases = (
            ('FAKE_GIT_BRANCH', 'feature', 'current-branch-not-main'),
            ('FAKE_GIT_DIRTY', '1', 'worktree-not-clean'),
            ('FAKE_FLOCK_FAIL', '1', 'concurrent-run'),
        )
        for variable, value, reason in cases:
            with self.subTest(variable=variable):
                self.reset_fixture()
                self.environment[variable] = value

                result = self.run_orchestrator('--apply')

                self.assertEqual(result.returncode, 30)
                self.assertIn(f'REASON={reason}', result.stdout)

    def test_apply_accepts_sticky_lock_parent_and_atomically_creates_target(
        self,
    ) -> None:
        self.assertFalse(self.lock_file.exists())

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.lock_file.is_symlink())
        self.assertTrue(self.lock_file.is_file())
        self.assertEqual(self.lock_file.stat().st_mode & 0o7777, 0o600)

    def test_apply_rejects_symlink_or_unsafe_lock_target(self) -> None:
        unsafe_target = self.fixture_root / 'unsafe-lock-target'
        unsafe_target.write_text('preserve\n', encoding='utf-8')
        cases = ('symlink', 'writable')
        for case in cases:
            with self.subTest(case=case):
                self.reset_fixture()
                if self.lock_file.exists() or self.lock_file.is_symlink():
                    self.lock_file.unlink()
                if case == 'symlink':
                    self.lock_file.symlink_to(unsafe_target)
                else:
                    self.lock_file.touch(mode=0o600)
                    self.lock_file.chmod(0o666)

                result = self.run_orchestrator('--apply')

                self.assertIn(result.returncode, (10, 30))
                self.assertIn('REASON=unsafe-lock-target', result.stdout)
                self.assertEqual(
                    unsafe_target.read_text(encoding='utf-8'), 'preserve\n'
                )

    def test_lock_target_swap_cannot_redirect_open_file_descriptor(self) -> None:
        race_target = self.fixture_root / 'race-lock-target'
        race_target.write_text('preserve\n', encoding='utf-8')
        self.environment.update(
            {
                'FAKE_LOCK_RACE': '1',
                'FAKE_LOCK_RACE_TARGET': str(race_target),
            }
        )

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(race_target.read_text(encoding='utf-8'), 'preserve\n')
        self.assertTrue(self.lock_file.is_symlink())

    def test_check_all_complete_reaches_final_verify(self) -> None:
        for stage in ('10', '20', '30', '40', '50', '60'):
            (self.state_dir / stage).touch()

        result = self.run_orchestrator('--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_ALL_CHECK', result.stdout)
        self.assertIn(
            '90 --check', self.command_log.read_text(encoding='utf-8')
        )

    def test_summary_is_structured_and_does_not_leak_untrusted_next(self) -> None:
        self.environment['FAKE_STAGE_NEXT'] = self.canary

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'GIT_COMMIT={self.commit}', result.stdout)
        self.assertIn('STAGE_40_RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)
        self.assertIn('STAGE_40_EVIDENCE=NONE', result.stdout)
        self.assertIn('STAGE_40_SHA256=NONE', result.stdout)
        self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_unsafe_evidence_stops_without_leaking_control_data(self) -> None:
        self.environment.update(
            {
                'FAKE_STAGE_MALFORMED': '40:unsafe-evidence',
                'FAKE_STAGE_CANARY': self.canary,
            }
        )

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 30)
        self.assertIn('REASON=invalid-stage-output', result.stdout)
        self.assertNotIn(self.canary, result.stdout + result.stderr)
        self.assertNotIn('\x1b', result.stdout + result.stderr)

    def test_rejects_invalid_cli_and_production_test_override(self) -> None:
        for arguments in ((), ('--force',), ('--check', '--apply')):
            with self.subTest(arguments=arguments):
                result = self.run_orchestrator(*arguments)
                self.assertEqual(result.returncode, 10)

        environment = self.sanitized_environment()
        environment['BOOTSTRAP_ORCHESTRATOR_TEST_STAGE_DIR'] = str(
            self.stage_dir
        )
        result = self.run_orchestrator('--check', environment=environment)
        self.assertEqual(result.returncode, 10)
        self.assertIn('REASON=test-override-in-production', result.stderr)

    def test_test_mode_rejects_unsafe_injected_paths(self) -> None:
        unsafe_stage_dir = self.fixture_root / 'unsafe-stages'
        unsafe_stage_dir.symlink_to(self.stage_dir, target_is_directory=True)
        unsafe_state_dir = self.fixture_root / 'unsafe-state'
        unsafe_state_dir.symlink_to(self.state_dir, target_is_directory=True)
        unsafe_lock = self.fixture_root / 'unsafe.lock'
        unsafe_lock.symlink_to(self.lock_file)
        cases = (
            ('BOOTSTRAP_ORCHESTRATOR_TEST_STAGE_DIR', str(unsafe_stage_dir)),
            ('ORCHESTRATOR_STATE_DIR', str(unsafe_state_dir)),
            ('BOOTSTRAP_ORCHESTRATOR_TEST_LOCK_FILE', str(unsafe_lock)),
        )
        for variable, value in cases:
            with self.subTest(variable=variable):
                environment = self.base_environment.copy()
                environment[variable] = value

                result = self.run_orchestrator(
                    '--check', environment=environment
                )

                self.assertEqual(result.returncode, 10)
                self.assertIn('REASON=unsafe-test-path', result.stdout)

    def test_production_apply_requires_actual_root(self) -> None:
        self.assertNotEqual(os.geteuid(), 0, '该用例必须由实际非 root 用户运行')
        environment = self.sanitized_environment()
        for name in tuple(environment):
            if name.startswith('BOOTSTRAP_ORCHESTRATOR_TEST_') or name.startswith('GIT_'):
                del environment[name]

        result = self.run_orchestrator('--apply', environment=environment)

        self.assertEqual(result.returncode, 10)
        self.assertIn('REASON=not-root', result.stdout)

    def test_production_rejects_every_caller_git_environment_variable(
        self,
    ) -> None:
        cases = (
            ('GIT_DIR', ''),
            ('GIT_WORK_TREE', str(self.fixture_root)),
            ('GIT_CONFIG_COUNT', '0'),
            ('GIT_OBJECT_DIRECTORY', str(self.fixture_root)),
        )
        for variable, value in cases:
            with self.subTest(variable=variable, value=value):
                environment = self.sanitized_environment()
                for name in tuple(environment):
                    if name.startswith('BOOTSTRAP_ORCHESTRATOR_TEST_') or name.startswith('GIT_'):
                        del environment[name]
                environment[variable] = value

                result = self.run_orchestrator(
                    '--check', environment=environment
                )

                self.assertEqual(result.returncode, 10)
                self.assertIn(
                    'REASON=untrusted-git-environment', result.stderr
                )

    def test_test_path_checks_ignore_caller_stat_binary(self) -> None:
        self.state_dir.chmod(0o777)
        self.write_executable(
            self.fake_bin / 'stat',
            f'''#!/bin/sh
            case "$2" in
              %u) printf '{os.geteuid()}\\n' ;;
              %Lp|%a) printf '700\\n' ;;
              *) exit 2 ;;
            esac
            ''',
        )

        result = self.run_orchestrator('--check')

        self.assertEqual(result.returncode, 10)
        self.assertIn('REASON=unsafe-test-path', result.stdout)

    def test_gnu_stat_fallback_discards_failed_probe_stdout(self) -> None:
        fake_stat = self.fixture_root / 'gnu-stat'
        self.write_executable(
            fake_stat,
            r'''
            #!/usr/bin/python3
            import os
            import stat
            import sys

            if len(sys.argv) != 4:
                raise SystemExit(2)
            option, field, path = sys.argv[1:]
            contaminated = os.environ['FAKE_STAT_CONTAMINATE']
            if option == '-f' and (
                (field == '%u' and contaminated == 'owner')
                or (field == '%Lp' and contaminated == 'mode')
            ):
                print('gnu-stat-filesystem-report')
                raise SystemExit(1)

            path_stat = os.stat(path)
            mode = stat.S_IMODE(path_stat.st_mode)
            values = {
                ('-f', '%u'): str(path_stat.st_uid),
                ('-f', '%Lp'): f'{mode:o}',
                ('-f', '%Mp%Lp'): f'{mode:04o}',
                ('-c', '%u'): str(path_stat.st_uid),
                ('-c', '%a'): f'{mode:o}',
            }
            try:
                print(values[(option, field)])
            except KeyError:
                raise SystemExit(2)
            ''',
        )
        compat_repo = self.fixture_root / 'compat-repo'
        compat_bootstrap_dir = compat_repo / 'scripts' / 'bootstrap'
        compat_bootstrap_dir.mkdir(parents=True)
        compat_bootstrap = compat_bootstrap_dir / 'bootstrap-all.sh'
        source = BOOTSTRAP_ALL.read_text(encoding='utf-8')
        self.assertIn('/usr/bin/stat', source)
        self.write_executable(
            compat_bootstrap, source.replace('/usr/bin/stat', str(fake_stat))
        )

        for contaminated_probe in ('owner', 'mode'):
            with self.subTest(contaminated_probe=contaminated_probe):
                environment = self.base_environment.copy()
                environment['FAKE_STAT_CONTAMINATE'] = contaminated_probe

                result = self.run_command(
                    ['/bin/bash', '-p', str(compat_bootstrap), '--check'],
                    env=environment,
                )

                self.assertEqual(
                    result.returncode, 0, result.stdout + result.stderr
                )
                self.assertIn('RESULT=PASS_BOOTSTRAP_CHECK', result.stdout)

    def test_git_status_failure_cannot_be_treated_as_clean(self) -> None:
        self.environment['FAKE_GIT_STATUS_FAIL'] = '1'

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 30)
        self.assertIn('REASON=worktree-state-unreadable', result.stdout)

    def test_invalid_result_canary_is_not_recorded_in_summary(self) -> None:
        self.environment.update(
            {
                'FAKE_STAGE_MALFORMED': '40:result-canary',
                'FAKE_STAGE_CANARY': self.canary,
            }
        )

        result = self.run_orchestrator('--apply')

        self.assertEqual(result.returncode, 30)
        self.assertIn('REASON=invalid-stage-result', result.stdout)
        self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_test_mode_rejects_unsafe_repository_path(self) -> None:
        unsafe_repo = self.fixture_root / 'unsafe-repo'
        copied_entry = unsafe_repo / 'scripts/bootstrap/bootstrap-all.sh'
        copied_entry.parent.mkdir(parents=True)
        copied_entry.write_bytes(BOOTSTRAP_ALL.read_bytes())
        copied_entry.chmod(0o755)
        unsafe_repo.chmod(0o777)

        result = self.run_command(
            ['/bin/bash', '-p', str(copied_entry), '--check'],
            env=self.environment,
        )

        self.assertEqual(result.returncode, 10)
        self.assertIn('REASON=unsafe-repository-path', result.stdout)

    def test_stage_directories_and_executed_files_are_gated(self) -> None:
        """stages/ 三层与被 root 执行的 check_cidrs.py 都必须先过门禁。

        stage 迁进目录后，被 root 触碰的不再只有一个文件：stages/ 本身、每个 stage
        目录、目录里的**每个条目**（run.sh、gates.sh、README.md 及任何新增文件），
        以及 stage 以 root 执行的 check_cidrs.py（账本 R3 从 Task 1 下沉至此）。
        """
        stages_root = self.stage_dir / 'stages'
        stage_home = self.stage_dir / self.stage_paths['00']
        stage_home = stage_home.parent
        cidr = self.stage_dir / 'check_cidrs.py'

        def world_writable_stages_root() -> None:
            stages_root.chmod(0o777)

        def group_writable_stage_directory() -> None:
            stage_home.chmod(0o770)

        def symlinked_stage_directory() -> None:
            relocated = self.fixture_root / 'relocated-stage'
            shutil.move(str(stage_home), str(relocated))
            stage_home.symlink_to(relocated, target_is_directory=True)

        def world_writable_sibling_entry() -> None:
            # gates.sh / README.md 这类非 run.sh 条目同样在 root 的读取路径上。
            sibling = stage_home / 'gates.sh'
            sibling.write_text('# gates\n', encoding='utf-8')
            sibling.chmod(0o666)

        def world_writable_dotfile_entry() -> None:
            hidden = stage_home / '.hidden.sh'
            hidden.write_text('# hidden\n', encoding='utf-8')
            hidden.chmod(0o666)

        def nested_directory_entry() -> None:
            (stage_home / 'nested').mkdir(mode=0o700)

        def world_writable_cidr_script() -> None:
            cidr.chmod(0o666)

        def symlinked_cidr_script() -> None:
            planted = self.fixture_root / 'planted-cidr.py'
            planted.write_text('# planted\n', encoding='utf-8')
            planted.chmod(0o644)
            cidr.unlink()
            cidr.symlink_to(planted)

        def missing_cidr_script() -> None:
            cidr.unlink()

        cases = (
            ('world-writable-stages-root', world_writable_stages_root, 'unsafe-stage-file'),
            ('group-writable-stage-directory', group_writable_stage_directory, 'unsafe-stage-file'),
            ('symlinked-stage-directory', symlinked_stage_directory, 'unsafe-stage-file'),
            ('world-writable-sibling-entry', world_writable_sibling_entry, 'unsafe-stage-file'),
            ('world-writable-dotfile-entry', world_writable_dotfile_entry, 'unsafe-stage-file'),
            ('nested-directory-entry', nested_directory_entry, 'unsafe-stage-file'),
            ('world-writable-cidr-script', world_writable_cidr_script, 'unsafe-executed-file'),
            ('symlinked-cidr-script', symlinked_cidr_script, 'unsafe-executed-file'),
            ('missing-cidr-script', missing_cidr_script, 'unsafe-executed-file'),
        )
        for label, tamper, reason in cases:
            with self.subTest(case=label):
                self.reset_fixture()
                tamper()
                try:
                    result = self.run_orchestrator('--check')
                finally:
                    self.write_fake_library()
                    self.write_fake_stages()
                    if cidr.is_symlink() or cidr.exists():
                        cidr.unlink()
                    cidr.write_text(
                        '#!/usr/bin/env python3\n', encoding='utf-8'
                    )
                    cidr.chmod(0o644)

                self.assertEqual(result.returncode, 30, result.stdout)
                self.assertIn(f'REASON={reason}', result.stdout)
                # 必须停在任何 stage 之前：编排器自身的 PHASE=bootstrap-all 是正常的，
                # 但只要出现 stage 的 PHASE，就说明已经以 root 执行过东西了。
                self.assertIn('PHASE=bootstrap-all', result.stdout)
                self.assertNotIn('PHASE=preflight', result.stdout)

    def test_library_files_are_gated_before_any_stage_runs(self) -> None:
        """每个 stage 都以 root source lib/*.sh，属主与权限必须先过门禁。"""
        common = self.library_dir / 'common.sh'
        planted = self.fixture_root / 'planted-common.sh'
        planted.write_text('# planted\n', encoding='utf-8')
        planted.chmod(0o644)

        def world_writable_directory() -> None:
            self.library_dir.chmod(0o777)

        def group_writable_directory() -> None:
            self.library_dir.chmod(0o770)

        def world_writable_file() -> None:
            common.chmod(0o666)

        def group_writable_file() -> None:
            common.chmod(0o664)

        def symlinked_file() -> None:
            common.unlink()
            common.symlink_to(planted)

        def symlinked_directory() -> None:
            relocated = self.fixture_root / 'relocated-lib'
            shutil.move(str(self.library_dir), str(relocated))
            self.library_dir.symlink_to(relocated, target_is_directory=True)

        def missing_directory() -> None:
            shutil.rmtree(self.library_dir)

        def empty_directory() -> None:
            for library_file in self.library_dir.iterdir():
                library_file.unlink()

        def world_writable_dotfile() -> None:
            hidden = self.library_dir / '.hidden.sh'
            hidden.write_text('# hidden\n', encoding='utf-8')
            hidden.chmod(0o666)

        def nested_directory() -> None:
            (self.library_dir / 'nested').mkdir(mode=0o700)

        def library_and_stage_unsafe() -> None:
            self.library_dir.chmod(0o777)
            (self.stage_dir / self.stage_paths['00']).chmod(0o777)

        cases = (
            ('world-writable-directory', world_writable_directory),
            ('group-writable-directory', group_writable_directory),
            ('world-writable-file', world_writable_file),
            ('group-writable-file', group_writable_file),
            ('symlinked-file', symlinked_file),
            ('symlinked-directory', symlinked_directory),
            ('missing-directory', missing_directory),
            ('empty-directory', empty_directory),
            ('world-writable-dotfile', world_writable_dotfile),
            ('nested-directory', nested_directory),
            ('library-and-stage-unsafe', library_and_stage_unsafe),
        )
        for label, tamper in cases:
            with self.subTest(case=label):
                self.reset_fixture()
                tamper()
                try:
                    result = self.run_orchestrator('--check')
                finally:
                    self.write_fake_library()
                    self.write_fake_stages()

                self.assertEqual(result.returncode, 30, result.stdout)
                self.assertIn('REASON=unsafe-library-file', result.stdout)
                self.assertEqual(
                    self.command_log.read_text(encoding='utf-8'),
                    '',
                    '门禁必须在任何 stage 启动前停机',
                )
                self.assertEqual(list(self.state_dir.iterdir()), [])

    def expand_shell_word(
        self, assignments: list[str], word: str, script_source: str
    ) -> str:
        """用脚本自身的目录推导逐字展开一个词，真实执行 cd/pwd -P。"""
        program = '\n'.join(
            ['set -Eeuo pipefail', *assignments, "printf '%s' " + word]
        )
        environment = self.sanitized_environment()
        environment['BOOTSTRAP_REAL_SCRIPT_SOURCE'] = script_source
        result = self.run_command(
            ['/bin/bash', '-c', program], env=environment
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def sourced_names_inside_gate(
        self, script: Path, gated_dir: str
    ) -> list[str]:
        """逐字展开脚本里每条 source 的目标，钉在门禁目录内，返回文件名。"""
        body = script.read_text(encoding='utf-8')
        assignments = [
            line.replace(
                '${BASH_SOURCE[0]}', '${BOOTSTRAP_REAL_SCRIPT_SOURCE}'
            )
            for line in shell_directory_assignments(body)
        ]
        names: list[str] = []
        for word in shell_source_words(body):
            target = Path(
                self.expand_shell_word(assignments, word, str(script))
            )
            self.assertEqual(
                str(target.parent),
                gated_dir,
                f'{script.name} source 了门禁目录之外的 {target}',
            )
            self.assertTrue(
                target.is_file() and not target.is_symlink(),
                f'{script.name} source 的 {target} 不是普通文件',
            )
            names.append(target.name)
        return names

    def test_real_stages_source_only_files_under_the_gated_library_dir(
        self,
    ) -> None:
        """fixture 不 source 任何文件，这里用真实 stage 钉住门禁的前提。"""
        bootstrap_dir = BOOTSTRAP_ALL.parent
        real_library_dir = bootstrap_dir / 'lib'
        orchestrator = BOOTSTRAP_ALL.read_text(encoding='utf-8')
        declaration = re.search(
            r'^library_dir=(\S+)$', orchestrator, re.MULTILINE
        )
        self.assertIsNotNone(declaration, '编排器未声明 library_dir')
        assert declaration is not None
        gated_dir = self.expand_shell_word(
            ['stage_dir=$BOOTSTRAP_REAL_SCRIPT_SOURCE'],
            declaration.group(1),
            str(bootstrap_dir),
        )
        self.assertEqual(gated_dir, str(real_library_dir))

        # 迁移后 `[0-9]*.sh` 会静默少枚举——枚举型断言通过 0 个文件是本仓库反复
        # 出现的「测试恒绿、生产必停」形态（账本 R5）。改从表枚举并钉住数量；
        # 表本身与编排器 stage_path() 的一致性由
        # CommonLibraryTest.test_stage_paths_come_from_one_table 交叉校验。
        stage_scripts = sorted(ROOT / path for path in STAGE_SCRIPTS.values())
        self.assertEqual(len(stage_scripts), 8, [str(s) for s in stage_scripts])
        for script in stage_scripts:
            self.assertTrue(script.is_file(), script)
        sourced: set[str] = set()
        for script in stage_scripts:
            names = self.sourced_names_inside_gate(script, gated_dir)
            self.assertTrue(names, f'{script.name} 没有 source 任何文件')
            sourced.update(names)
        self.assertEqual(
            sorted(sourced),
            sorted(path.name for path in real_library_dir.glob('*.sh')),
            '被 source 的文件集合必须与门禁目录内容一致',
        )
        # 原断言是「lib 下的文件不 source 任何东西」，用来保证门禁扫过的那一层
        # 就是全部被求值的代码。跨 lib 依赖（exec-safety.sh 要 path-facts.sh 的
        # path_mode/owned_by_expected）让那条断言过强：source 兄弟库并不会引入
        # 门禁没扫过的文件。这里改钉真正的前提——lib 里每条 source 的目标父目录
        # 必须仍是门禁目录本身，一旦指向目录之外就绕过了门禁，继续判死。
        library_sourced: list[str] = []
        for library_file in sorted(real_library_dir.iterdir()):
            library_sourced.extend(
                self.sourced_names_inside_gate(library_file, gated_dir)
            )
        # 放宽后的那条断言只有在真的存在跨 lib 依赖时才被求值：exec-safety.sh
        # source path-facts.sh 就是它。少了这条守卫，跨 lib 依赖一旦被拆掉，
        # 上面的循环会退回空转，而放宽本身还留在原地。
        self.assertTrue(
            library_sourced, '放宽后的断言需要真实的跨 lib 依赖来喂，否则空转'
        )


class ArtifactStageTest(BootstrapTestCase):
    approved_digests = {
        'containerd': '628448bd973610c656c1cbea8e88b32fafd85b23cc1aa4a3372eb7198478c054',
        'runc': '3f3921dbbee7723e9868f97e88e51ffc910206e3ba55646e74d93d24ea76023c',
        'crictl': '83855e114566a8a8c44c548d515670f51de3a5e1da8b2effb59870e2f10c25a3',
        'helm': '0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36',
        'gateway-api': '24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73',
        'cilium-chart': 'c5f013912360d1a334f44ef25f36da59ba3414cdb48f466ee12d0c4fdff27883',
    }

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def make_environment(
        self,
        artifact: bytes,
        *,
        name: str = 'runc',
        version: str = '1.3.6',
        url: str = 'https://github.com/opencontainers/runc/releases/download/v1.3.6/runc.amd64',
        digest: str | None = None,
        target: str = '/usr/local/sbin/runc',
        records: list[tuple[str, str, str, bytes, str]] | None = None,
    ) -> tuple[dict[str, str], Path, Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        evidence = host / 'root/dev-infra-evidence'
        evidence.mkdir(parents=True)
        fake_bin.mkdir()
        lock = directory / 'artifacts.lock.tsv'
        if records is None:
            records = self.approved_records()
            records = [
                (
                    name,
                    version,
                    url,
                    artifact,
                    target,
                )
                if record_name == name
                else record
                for record in records
                for record_name, *_ in [record]
            ]
        fixtures = directory / 'download-fixtures'
        fixtures.mkdir()
        digest_map = directory / 'artifact-digest-map.tsv'
        for _, _, record_url, record_artifact, _ in records:
            (fixtures / Path(record_url).name).write_bytes(record_artifact)
        digest_map.write_text(
            ''.join(
                f'{hashlib.sha256(record_artifact).hexdigest()}\t'
                f'{self.approved_digests[record_name]}\n'
                for record_name, _, _, record_artifact, _ in records
                if record_name in self.approved_digests
                and not (record_name == name and digest is not None)
            ),
            encoding='utf-8',
        )
        lock.write_text(
            ''.join(
                '\t'.join(
                    [
                        record_name,
                        record_version,
                        record_url,
                        (
                            digest
                            if record_name == name and digest is not None
                            else self.approved_digests.get(
                                record_name,
                                hashlib.sha256(record_artifact).hexdigest(),
                            )
                        ),
                        record_target,
                    ]
                )
                + '\n'
                for record_name, record_version, record_url, record_artifact, record_target in records
            ),
            encoding='utf-8',
        )
        curl_log = directory / 'curl.log'

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'stat',
            '''
            #!/usr/bin/python3
            import os
            import stat
            import sys

            if len(sys.argv) != 4:
                raise SystemExit(64)
            option, field, path = sys.argv[1:]
            if option == '-f' and field == '%Lp':
                if os.environ.get('FAKE_STAT_CONTAMINATE_BSD') == '1':
                    print('failed-bsd-probe-garbage')
                    raise SystemExit(1)
            elif option != '-c' or field != '%a':
                raise SystemExit(64)
            print(f'{stat.S_IMODE(os.stat(path).st_mode):o}')
            ''',
        )
        self.write_executable(
            fake_bin / 'sha256sum',
            '''
            #!/bin/sh
            actual=$(/usr/bin/shasum -a 256 "$1" | awk '{print $1}') || exit 1
            approved=$(awk -F '\t' -v digest="$actual" '$1 == digest {print $2}' "$FAKE_ARTIFACT_DIGEST_MAP")
            [ -n "$approved" ] || approved=$actual
            printf '%s  %s\n' "$approved" "$1"
            ''',
        )
        self.write_executable(
            fake_bin / 'curl',
            '''
            #!/bin/sh
            printf '%s\n' "$*" >>"$FAKE_CURL_LOG"
            output=
            url=
            fail=false
            location=false
            protocol=false
            tls=false
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --fail)
                  fail=true
                  shift
                  ;;
                --location)
                  location=true
                  shift
                  ;;
                --proto)
                  [ "$2" = '=https' ] || exit 64
                  protocol=true
                  shift 2
                  ;;
                --tlsv1.2)
                  tls=true
                  shift
                  ;;
                --output)
                  output=$2
                  shift 2
                  ;;
                https://*)
                  url=$1
                  shift
                  ;;
                *)
                  shift
                  ;;
              esac
            done
            [ "$fail" = true ] && [ "$location" = true ] && \
              [ "$protocol" = true ] && [ "$tls" = true ] && [ -n "$output" ] && [ -n "$url" ] || exit 64
            /bin/cp "$FAKE_DOWNLOAD_FIXTURES/${url##*/}" "$output"
            ''',
        )

        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_LOCK_FILE': str(lock),
                'FAKE_CURL_LOG': str(curl_log),
                'FAKE_DOWNLOAD_FIXTURES': str(fixtures),
                'FAKE_ARTIFACT_DIGEST_MAP': str(digest_map),
            }
        )
        return environment, host, lock, curl_log

    def approved_records(self) -> list[tuple[str, str, str, bytes, str]]:
        return [
            (
                'containerd',
                '2.3.1',
                'https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
                self.archive_bytes(
                    [
                        ('bin/containerd', b'containerd\n'),
                        ('bin/ctr', b'ctr\n'),
                        ('bin/containerd-shim-runc-v2', b'shim\n'),
                    ]
                ),
                '/usr/local/bin',
            ),
            (
                'runc',
                '1.3.6',
                'https://github.com/opencontainers/runc/releases/download/v1.3.6/runc.amd64',
                b'runc\n',
                '/usr/local/sbin/runc',
            ),
            (
                'crictl',
                '1.36.0',
                'https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
                self.archive_bytes([('crictl', b'crictl\n')]),
                '/usr/local/bin/crictl',
            ),
            (
                'helm',
                '3.21.0',
                'https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
                self.archive_bytes([('linux-amd64/helm', b'helm\n')]),
                '/usr/local/bin/helm',
            ),
            (
                'gateway-api',
                '1.6.1',
                'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml',
                b'gateway\n',
                'kubernetes://gateway-api/standard',
            ),
            (
                'cilium-chart',
                '1.20.0',
                'https://helm.cilium.io/cilium-1.20.0.tgz',
                b'cilium\n',
                'kubernetes://kube-system/cilium',
            ),
        ]

    def run_stage(
        self, environment: dict[str, str], mode: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', str(STAGE_ARTIFACTS), mode], env=environment
        )

    def staged_path(self, host: Path, basename: str) -> Path:
        return (
            host
            / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
            / basename
        )

    def stage_records(
        self, host: Path, records: list[tuple[str, str, str, bytes, str]]
    ) -> Path:
        staging = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
        staging.mkdir(parents=True, mode=0o700)
        staging.parent.chmod(0o700)
        staging.chmod(0o700)
        for _, _, url, artifact, _ in records:
            staged = staging / Path(url).name
            staged.write_bytes(artifact)
            staged.chmod(0o600)
        return staging

    def compliant_environment(
        self,
    ) -> tuple[dict[str, str], Path, list[tuple[str, str, str, bytes, str]], Path]:
        records = self.approved_records()
        environment, host, _, _ = self.make_environment(b'ignored\n', records=records)
        staging = self.stage_records(host, records)
        return environment, host, records, staging

    def archive_bytes(self, members: list[tuple[str, bytes | str]]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, content in members:
                member = tarfile.TarInfo(name)
                if isinstance(content, str):
                    member.type = tarfile.SYMTYPE
                    member.linkname = content
                    member.size = 0
                    archive.addfile(member)
                else:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        return stream.getvalue()

    def assert_structured_terminal(
        self,
        output: str,
        *,
        mode: str,
        result: str,
        reason: str,
        next_step: str,
    ) -> None:
        expected = {
            'PHASE': 'stage-artifacts',
            'MODE': mode,
            'RESULT': result,
            'REASON': reason,
            'EVIDENCE': 'NONE',
            'EXIT_CODE': '0',
            'NEXT': next_step,
            'SHA256': 'NONE',
        }
        lines = output.splitlines()
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(
                    [line for line in lines if line.startswith(f'{key}=')],
                    [f'{key}={value}'],
                )

    def test_compliant_check_has_one_structured_terminal_result(self) -> None:
        environment, _, _, _ = self.compliant_environment()

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_structured_terminal(
            result.stdout,
            mode='CHECK',
            result='ALREADY_COMPLIANT',
            reason='artifacts-ready',
            next_step='stages/20-prepare-kernel/run.sh --check',
        )

    def test_apply_required_check_has_one_structured_terminal_result(self) -> None:
        environment, _, _, _ = self.make_environment(b'ignored\n')

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_structured_terminal(
            result.stdout,
            mode='CHECK',
            result='PASS_ARTIFACTS_CHECK',
            reason='apply-required',
            next_step='stages/10-stage-artifacts/run.sh --apply',
        )

    def test_successful_apply_separates_artifact_and_terminal_digests(self) -> None:
        environment, _, _, _ = self.make_environment(b'ignored\n')

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_structured_terminal(
            result.stdout,
            mode='APPLY',
            result='PASS_ARTIFACTS_STAGED',
            reason='artifacts-staged',
            next_step='stages/20-prepare-kernel/run.sh --check',
        )
        lines = result.stdout.splitlines()
        self.assertEqual(
            len(
                [
                    line
                    for line in lines
                    if line.startswith('ARTIFACT_SHA256=')
                ]
            ),
            6,
        )
        self.assertEqual(
            [line for line in lines if line.startswith('SHA256=')],
            ['SHA256=NONE'],
        )

    def test_check_does_not_create_staging_directory(self) -> None:
        environment, _, _, curl_log = self.make_environment(b'runc fixture\n')
        host = Path(environment['BOOTSTRAP_TEST_ROOT'])

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_ARTIFACTS_CHECK', result.stdout)
        self.assertFalse((host / 'root/dev-infra-artifacts').exists())
        self.assertFalse(curl_log.exists())

    def test_apply_stages_verified_artifact(self) -> None:
        artifact = b'runc fixture\n'
        environment, host, _, _ = self.make_environment(artifact)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_ARTIFACTS_STAGED', result.stdout)
        staged = self.staged_path(host, 'runc.amd64')
        self.assertEqual(staged.read_bytes(), artifact)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)

    def test_apply_rejects_download_digest_mismatch(self) -> None:
        environment, host, _, _ = self.make_environment(b'runc fixture\n')
        Path(environment['FAKE_DOWNLOAD_FIXTURES'], 'runc.amd64').write_bytes(
            b'tampered runc fixture\n'
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertFalse(self.staged_path(host, 'runc.amd64').exists())

    def test_check_rejects_lock_digest_that_matches_malicious_payload(self) -> None:
        malicious = b'malicious runc payload\n'
        malicious_digest = hashlib.sha256(malicious).hexdigest()
        environment, host, _, curl_log = self.make_environment(
            malicious,
            digest=malicious_digest,
        )
        self.stage_records(
            host,
            [
                (
                    name,
                    version,
                    url,
                    malicious if name == 'runc' else artifact,
                    target,
                )
                for name, version, url, artifact, target in self.approved_records()
            ],
        )

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertFalse(curl_log.exists())

    def test_check_refuses_existing_same_name_with_different_digest(self) -> None:
        environment, host, _, staging = self.compliant_environment()
        staged = self.staged_path(host, 'runc.amd64')
        self.assertEqual(staged.parent, staging)
        staged.write_bytes(b'unknown\n')

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertEqual(staged.read_bytes(), b'unknown\n')

    def test_check_rejects_non_official_url_before_curl(self) -> None:
        environment, _, _, curl_log = self.make_environment(
            b'payload\n', url='https://example.com/v1.3.6/runc.amd64'
        )

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertFalse(curl_log.exists())

    def test_check_rejects_http_url_before_curl(self) -> None:
        environment, _, _, curl_log = self.make_environment(
            b'payload\n', url='http://github.com/opencontainers/runc/runc.amd64'
        )

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertFalse(curl_log.exists())

    def test_apply_rejects_archive_path_traversal(self) -> None:
        artifact = self.archive_bytes([('../escape', b'escape\n')])
        environment, host, _, _ = self.make_environment(
            artifact,
            name='containerd',
            version='2.3.1',
            url='https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
            target='/usr/local/bin',
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
        self.assertFalse(
            self.staged_path(host, 'containerd-2.3.1-linux-amd64.tar.gz').exists()
        )

    def test_apply_rejects_helm_archive_path_traversal(self) -> None:
        artifact = self.archive_bytes([('linux-amd64/../../escape', b'escape\n')])
        environment, host, _, _ = self.make_environment(
            artifact,
            name='helm',
            version='3.21.0',
            url='https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
            target='/usr/local/bin/helm',
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
        self.assertFalse(self.staged_path(host, 'helm-v3.21.0-linux-amd64.tar.gz').exists())

    def test_apply_rejects_archive_symlink_escaping_member_root(self) -> None:
        artifact = self.archive_bytes(
            [('bin/containerd', b'binary\n'), ('bin/escape', '../../outside')]
        )
        environment, host, _, _ = self.make_environment(
            artifact,
            name='containerd',
            version='2.3.1',
            url='https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
            target='/usr/local/bin',
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
        self.assertFalse(
            self.staged_path(host, 'containerd-2.3.1-linux-amd64.tar.gz').exists()
        )

    def test_apply_rejects_archive_missing_required_member(self) -> None:
        artifact = self.archive_bytes([('linux-amd64/README.md', b'missing helm\n')])
        environment, host, _, _ = self.make_environment(
            artifact,
            name='helm',
            version='3.21.0',
            url='https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
            target='/usr/local/bin/helm',
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
        self.assertFalse(self.staged_path(host, 'helm-v3.21.0-linux-amd64.tar.gz').exists())

    def test_check_rejects_five_record_lock_without_crictl(self) -> None:
        """捕获 staging 接受缺少 crictl 的五项 schema 的缺陷。"""
        records = [
            record
            for record in self.approved_records()
            if record[0] != 'crictl'
        ]
        environment, host, _, _ = self.make_environment(
            b'ignored\n', records=records
        )
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertIn('REASON=lock-record-count-invalid', result.stdout)

    def test_apply_stages_locked_crictl_archive(self) -> None:
        """捕获 staging 拒绝批准 crictl 或未验证其 regular 成员的缺陷。"""
        artifact = self.archive_bytes([('crictl', b'crictl\n')])
        environment, host, _, _ = self.make_environment(
            artifact,
            name='crictl',
            version='1.36.0',
            url='https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
            target='/usr/local/bin/crictl',
        )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_ARTIFACTS_STAGED', result.stdout)
        self.assertEqual(
            self.staged_path(
                host, 'crictl-v1.36.0-linux-amd64.tar.gz'
            ).read_bytes(),
            artifact,
        )

    def test_apply_rejects_crictl_archive_missing_regular_member(self) -> None:
        """捕获接受缺成员或同名 symlink 冒充 crictl binary 的缺陷。"""
        fixtures = (
            self.archive_bytes([('README.md', b'missing\n')]),
            self.archive_bytes([('crictl', 'bin/crictl')]),
        )
        for artifact in fixtures:
            with self.subTest(artifact=hashlib.sha256(artifact).hexdigest()):
                environment, host, _, _ = self.make_environment(
                    artifact,
                    name='crictl',
                    version='1.36.0',
                    url='https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
                    target='/usr/local/bin/crictl',
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20)
                self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
                self.assertFalse(
                    self.staged_path(
                        host, 'crictl-v1.36.0-linux-amd64.tar.gz'
                    ).exists()
                )

    def test_apply_stages_archives_with_required_members(self) -> None:
        fixtures = [
            (
                'containerd',
                '2.3.1',
                'https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
                '/usr/local/bin',
                [('bin/containerd', b'containerd\n'), ('bin/ctr', b'ctr\n'), ('bin/containerd-shim-runc-v2', b'shim\n')],
            ),
            (
                'helm',
                '3.21.0',
                'https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
                '/usr/local/bin/helm',
                [('linux-amd64/helm', b'helm\n')],
            ),
            (
                'crictl',
                '1.36.0',
                'https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
                '/usr/local/bin/crictl',
                [('crictl', b'crictl\n')],
            ),
        ]
        for name, version, url, target, members in fixtures:
            with self.subTest(name=name):
                artifact = self.archive_bytes(members)
                environment, host, _, _ = self.make_environment(
                    artifact,
                    name=name,
                    version=version,
                    url=url,
                    target=target,
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('RESULT=PASS_ARTIFACTS_STAGED', result.stdout)
                self.assertEqual(self.staged_path(host, Path(url).name).read_bytes(), artifact)

    def test_check_reports_exact_existing_artifact_as_compliant(self) -> None:
        environment, _, _, _ = self.compliant_environment()

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_check_rejects_unknown_staging_entries(self) -> None:
        for entry_type in ('file', 'directory', 'symlink'):
            with self.subTest(entry_type=entry_type):
                environment, _, _, staging = self.compliant_environment()
                unknown = staging / 'unapproved'
                if entry_type == 'file':
                    unknown.write_bytes(b'unknown\n')
                elif entry_type == 'directory':
                    unknown.mkdir()
                else:
                    unknown.symlink_to('runc.amd64')

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertTrue(unknown.exists() or unknown.is_symlink())

    def test_check_rejects_existing_artifact_directory_mode_drift(self) -> None:
        environment, _, _, staging = self.compliant_environment()
        staging.chmod(0o755)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 30)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertEqual(staging.stat().st_mode & 0o777, 0o755)

    def test_check_discards_failed_bsd_stat_stdout_before_gnu_mode(self) -> None:
        """捕获失败 BSD probe 的 stdout 污染 GNU mode 结果的缺陷。"""
        environment, _, _, _ = self.compliant_environment()
        environment['FAKE_STAT_CONTAMINATE_BSD'] = '1'

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_apply_rejects_existing_artifact_root_mode_drift(self) -> None:
        environment, host, _, _ = self.compliant_environment()
        artifact_root = host / 'root/dev-infra-artifacts'
        artifact_root.chmod(0o755)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertEqual(artifact_root.stat().st_mode & 0o777, 0o755)

    def test_check_rejects_truncated_lock_even_when_its_artifacts_match(self) -> None:
        records = self.approved_records()[:-1]
        environment, host, _, _ = self.make_environment(b'ignored\n', records=records)
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_check_rejects_duplicate_lock_basename(self) -> None:
        records = self.approved_records()
        records[-1] = (
            'cilium-chart',
            '1.20.0',
            'https://helm.cilium.io/helm-v3.21.0-linux-amd64.tar.gz',
            records[3][3],
            'kubernetes://kube-system/cilium',
        )
        environment, host, _, _ = self.make_environment(b'ignored\n', records=records)
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertIn('REASON=lock-basename-duplicate', result.stdout)

    def test_check_rejects_unapproved_lock_name(self) -> None:
        records = self.approved_records()
        name, version, url, artifact, target = records[-1]
        records[-1] = ('unexpected-chart', version, url, artifact, target)
        environment, host, _, _ = self.make_environment(b'ignored\n', records=records)
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_check_accepts_six_artifacts_without_cni_archive(self) -> None:
        """捕获 stager 继续要求第七项 CNI artifact 的双重 ownership 缺陷。"""
        records = [
            record for record in self.approved_records()
            if record[0] != 'cni-plugins'
        ]
        environment, host, _, _ = self.make_environment(
            b'ignored\n', records=records
        )
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_check_rejects_reintroduced_cni_archive(self) -> None:
        """捕获 stager 再次批准 cni-plugins release artifact 的缺陷。"""
        records = self.approved_records()
        records.append(
            (
                'cni-plugins',
                '1.9.1',
                'https://github.com/containernetworking/plugins/releases/'
                'download/v1.9.1/cni-plugins-linux-amd64-v1.9.1.tgz',
                self.archive_bytes([('bridge', b'bridge\n')]),
                '/opt/cni/bin',
            )
        )
        environment, host, _, _ = self.make_environment(
            b'ignored\n', records=records
        )
        self.stage_records(host, records)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)


class ContainerdInstallTest(BootstrapTestCase):
    endpoint = 'unix:///run/containerd/containerd.sock'
    containerd_version = b'''#!/bin/sh
[ "$1" = "--version" ] || exit 64
printf '%s\n' "${FAKE_CONTAINERD_VERSION:-containerd github.com/containerd/containerd/v2 v2.3.1 test}"
'''
    ctr_binary = b'''#!/bin/sh
printf 'ctr %s\n' "$*" >>"$FAKE_COMMAND_LOG"
[ "$*" = "plugins ls" ] || exit 64
printf '%s\n' "${FAKE_CTR_OUTPUT:-TYPE ID PLATFORMS STATUS
io.containerd.snapshotter.v1 overlayfs linux/amd64 ok
io.containerd.cri.v1 images - ok
io.containerd.cri.v1 runtime linux/amd64 ok}"
'''
    shim_binary = b'#!/bin/sh\nexit 0\n'
    runc_binary = b'''#!/bin/sh
[ "$1" = "--version" ] || exit 64
printf '%s\n' "${FAKE_RUNC_VERSION:-runc version 1.3.6}"
'''
    crictl_binary = b'''#!/bin/sh
printf 'crictl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
printf '%s\n' "${FAKE_CANARY:-}" >&2
case "$*" in
  --version) printf '%s\n' "${FAKE_CRICTL_VERSION:-crictl version v1.36.0}" ;;
  "--runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info --output json")
    printf '%s\n' "$FAKE_CRICTL_INFO"
    ;;
  *) exit 64 ;;
esac
'''
    def write_executable(self, path: Path, source: str | bytes) -> None:
        if isinstance(source, bytes):
            path.write_bytes(source)
        else:
            path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def create_cri_socket(self, host: Path) -> Path:
        socket_path = host / 'run/containerd/containerd.sock'
        socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o711)
        socket_path.parent.chmod(0o711)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(socket_path))
        listener.close()
        socket_path.chmod(0o660)
        return socket_path

    def archive_bytes(self, members: list[tuple[str, bytes | str]]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, content in members:
                member = tarfile.TarInfo(name)
                if isinstance(content, str):
                    member.type = tarfile.SYMTYPE
                    member.linkname = content
                    member.size = 0
                else:
                    member.mode = 0o755
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                    continue
                archive.addfile(member)
        return stream.getvalue()

    def artifact_records(
        self, overrides: dict[str, bytes] | None = None
    ) -> list[tuple[str, str, str, bytes, str]]:
        artifacts = {
            'containerd': self.archive_bytes(
                [
                    ('bin/containerd', self.containerd_version),
                    ('bin/ctr', self.ctr_binary),
                    ('bin/containerd-shim-runc-v2', self.shim_binary),
                ]
            ),
            'runc': self.runc_binary,
            'crictl': self.archive_bytes([('crictl', self.crictl_binary)]),
            'helm': self.archive_bytes([('linux-amd64/helm', b'helm\n')]),
            'gateway-api': b'gateway\n',
            'cilium-chart': b'cilium\n',
        }
        artifacts.update(overrides or {})
        return [
            (
                'containerd',
                '2.3.1',
                'https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
                artifacts['containerd'],
                '/usr/local/bin',
            ),
            (
                'runc',
                '1.3.6',
                'https://github.com/opencontainers/runc/releases/download/v1.3.6/runc.amd64',
                artifacts['runc'],
                '/usr/local/sbin/runc',
            ),
            (
                'crictl',
                '1.36.0',
                'https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
                artifacts['crictl'],
                '/usr/local/bin/crictl',
            ),
            (
                'helm',
                '3.21.0',
                'https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
                artifacts['helm'],
                '/usr/local/bin/helm',
            ),
            (
                'gateway-api',
                '1.6.1',
                'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml',
                artifacts['gateway-api'],
                'kubernetes://gateway-api/standard',
            ),
            (
                'cilium-chart',
                '1.20.0',
                'https://helm.cilium.io/cilium-1.20.0.tgz',
                artifacts['cilium-chart'],
                'kubernetes://kube-system/cilium',
            ),
        ]

    def valid_info(self, *, runtime_ready: object = True) -> str:
        import json

        return json.dumps(
            {
                'status': {
                    'conditions': [
                        {'type': 'RuntimeReady', 'status': runtime_ready},
                        {
                            'type': 'NetworkReady',
                            'status': False,
                            'reason': 'SECRET_CANARY_REASON',
                            'message': 'SECRET_CANARY_MESSAGE',
                        },
                    ]
                },
                'config': {
                    'containerd': {
                        'defaultRuntimeName': 'runc',
                        'runtimes': {
                            'runc': {
                                'runtimeType': 'io.containerd.runc.v2',
                                'options': {'SystemdCgroup': True},
                            }
                        },
                    }
                },
                'unapprovedExtra': 'SECRET_CANARY_EXTRA',
            }
        )

    def make_environment(
        self, overrides: dict[str, bytes] | None = None
    ) -> tuple[dict[str, str], Path, Path, dict[str, bytes]]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        command_log = directory / 'commands.log'
        lock = directory / 'artifacts.lock.tsv'
        approved_lock = directory / 'approved-artifacts.lock.tsv'
        staging = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
        for path in (
            host / 'root/dev-infra-evidence',
            host / 'usr/local/bin',
            host / 'usr/local/sbin',
            host / 'usr/local/lib/systemd/system',
            host / 'etc/containerd',
            host / 'var/lib',
            host / 'run',
            fake_bin,
            staging,
        ):
            path.mkdir(parents=True, exist_ok=True)
        (host / 'root/dev-infra-artifacts').chmod(0o700)
        staging.chmod(0o700)
        (host / 'swap.img').write_bytes(b'preserve swap\n')

        records = self.artifact_records(overrides)
        artifact_map: dict[str, bytes] = {}
        lock_lines = []
        for name, version, url, artifact, target in records:
            artifact_map[name] = artifact
            staged = staging / Path(url).name
            staged.write_bytes(artifact)
            staged.chmod(0o600)
            lock_lines.append(
                '\t'.join(
                    (
                        name,
                        version,
                        url,
                        hashlib.sha256(artifact).hexdigest(),
                        target,
                    )
                )
            )
        lock.write_text('\n'.join(lock_lines) + '\n', encoding='utf-8')
        approved_lock.write_text('\n'.join(lock_lines) + '\n', encoding='utf-8')

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'install',
            '''
            #!/bin/sh
            printf 'install %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            exec /usr/bin/install "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'mktemp',
            '''
            #!/bin/sh
            temporary=$(/usr/bin/mktemp "$@") || exit
            printf '%s\n' "$temporary"
            case "$temporary" in
              *"${FAKE_MKTEMP_RACE_MATCH:-}"*) matched=1 ;;
              *) matched=0 ;;
            esac
            if [ -n "${FAKE_MKTEMP_RACE_PARENT:-}" ] && [ "$matched" = 1 ]; then
              case "${FAKE_MKTEMP_RACE_ACTION:-mode}" in
                mode) chmod 0700 "$FAKE_MKTEMP_RACE_PARENT" ;;
                owner) : >"$FAKE_MKTEMP_RACE_OWNER_MARKER" ;;
                type)
                  /bin/mv "$FAKE_MKTEMP_RACE_PARENT" "$FAKE_MKTEMP_RACE_PARENT.raced"
                  ln -s /tmp "$FAKE_MKTEMP_RACE_PARENT"
                  ;;
              esac
            fi
            case "$temporary" in
              *"${FAKE_PHASE_RACE_MKTEMP_MATCH:-not-a-real-match}"*) phase_matched=1 ;;
              *) phase_matched=0 ;;
            esac
            if [ "${FAKE_PHASE_RACE_PHASE:-}" = post-mktemp ] && [ "$phase_matched" = 1 ]; then
              : >"$FAKE_PHASE_RACE_OWNER_MARKER"
              printf 'race-trigger %s %s\n' "$FAKE_PHASE_RACE_PHASE" "$FAKE_PHASE_RACE_COMPONENT" >>"$FAKE_COMMAND_LOG"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'mv',
            '''
            #!/bin/sh
            printf 'mv %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            eval "last=\${${#}}"
            if [ -n "${FAKE_MV_RACE_TARGET:-}" ]; then
              if [ "$last" = "$FAKE_MV_RACE_TARGET" ]; then
                printf 'concurrent\n' >"$last"
                [ "${FAKE_MV_RACE_RC:-0}" = 0 ] && exit 0
                exit "$FAKE_MV_RACE_RC"
              fi
            fi
            [ "${FAKE_MV_FAIL_TARGET:-}" != "$last" ] || exit 1
            /bin/mv "$@" || exit
            if [ "${FAKE_PHASE_RACE_PHASE:-}" = pre-publish ] && [ "$last" = "${FAKE_PHASE_RACE_AFTER_MV:-}" ]; then
              : >"$FAKE_PHASE_RACE_OWNER_MARKER"
              printf 'race-trigger %s %s\n' "$FAKE_PHASE_RACE_PHASE" "$FAKE_PHASE_RACE_COMPONENT" >>"$FAKE_COMMAND_LOG"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'sync',
            '''
            #!/bin/sh
            printf 'sync %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "${FAKE_SYNC_FAIL:-0}" != 1 ]
            ''',
        )
        self.write_executable(
            fake_bin / 'tar',
            '''
            #!/bin/sh
            [ "$1" != "-xzf" ] || printf 'tar-write %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            /usr/bin/tar "$@" || exit
            if [ "$1" = -xzf ] && [ "${FAKE_PHASE_RACE_PHASE:-}" = pre-tar ] && [ "${2##*/}" = "${FAKE_PHASE_RACE_AFTER_TAR:-}" ]; then
              : >"$FAKE_PHASE_RACE_OWNER_MARKER"
              printf 'race-trigger %s %s\n' "$FAKE_PHASE_RACE_PHASE" "$FAKE_PHASE_RACE_COMPONENT" >>"$FAKE_COMMAND_LOG"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'make-cri-socket',
            '''
            #!/usr/bin/python3
            import os
            import socket
            import sys

            path = sys.argv[1]
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(path)
            listener.close()
            os.chmod(path, 0o660)
            ''',
        )
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            printf 'systemctl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            case "$1" in
              is-enabled) [ -f "$FAKE_SERVICE_ENABLED" ] ;;
              is-active) [ -f "$FAKE_SERVICE_ACTIVE" ] && printf 'active\n' ;;
              show)
                [ "$*" = "show --all --property=LoadState --property=FragmentPath --property=DropInPaths containerd.service" ] || exit 64
                [ "${FAKE_SYSTEMCTL_SHOW_FAIL:-0}" != 1 ] || exit 1
                [ "${FAKE_SYSTEMCTL_SHOW_EMPTY:-0}" != 1 ] || exit 0
                if [ "${FAKE_SYSTEMCTL_SHOW_CUSTOM:-0}" = 1 ]; then
                  printf '%s\n' "$FAKE_SYSTEMCTL_SHOW_OUTPUT"
                  exit 0
                fi
                if [ -f "$FAKE_SERVICE_UNIT_LOADED" ]; then
                  load_state=${FAKE_LOAD_STATE:-loaded}
                  fragment_path=$FAKE_FRAGMENT_PATH
                else
                  load_state=${FAKE_LOAD_STATE:-not-found}
                  fragment_path=${FAKE_NONLOADED_FRAGMENT_PATH:-}
                fi
                [ "${FAKE_LOAD_STATE_EMPTY:-0}" != 1 ] || load_state=
                printf 'LoadState=%s\nFragmentPath=%s\nDropInPaths=%s\n' \
                  "$load_state" "$fragment_path" "${FAKE_DROP_IN_PATHS:-}"
                ;;
              daemon-reload)
                [ ! -f "$FAKE_UNIT_TARGET" ] || : >"$FAKE_SERVICE_UNIT_LOADED"
                ;;
              enable) : >"$FAKE_SERVICE_ENABLED" ;;
              start)
                : >"$FAKE_SERVICE_ACTIVE"
                mkdir -p -m 0711 "$FAKE_HOST_ROOT/run/containerd"
                mkdir -p -m 0700 "$FAKE_HOST_ROOT/var/lib/containerd"
                "$FAKE_SOCKET_HELPER" "$FAKE_HOST_ROOT/run/containerd/containerd.sock"
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_LOCK_FILE': str(lock),
                'BOOTSTRAP_TEST_APPROVED_LOCK_FILE': str(approved_lock),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_HOST_ROOT': str(host),
                'FAKE_SERVICE_ENABLED': str(directory / 'service-enabled'),
                'FAKE_SERVICE_ACTIVE': str(directory / 'service-active'),
                'FAKE_SERVICE_UNIT_LOADED': str(directory / 'service-unit-loaded'),
                'FAKE_UNIT_TARGET': str(
                    host / 'usr/local/lib/systemd/system/containerd.service'
                ),
                'FAKE_FRAGMENT_PATH': str(
                    host / 'usr/local/lib/systemd/system/containerd.service'
                ),
                'FAKE_SOCKET_HELPER': str(fake_bin / 'make-cri-socket'),
                'FAKE_CRICTL_INFO': self.valid_info(),
            }
        )
        return environment, host, command_log, artifact_map

    def run_stage(
        self, environment: dict[str, str], mode: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', str(INSTALL_CONTAINERD), mode], env=environment
        )

    def managed_targets(self, host: Path) -> dict[str, Path]:
        return {
            'containerd': host / 'usr/local/bin/containerd',
            'ctr': host / 'usr/local/bin/ctr',
            'shim': host / 'usr/local/bin/containerd-shim-runc-v2',
            'runc': host / 'usr/local/sbin/runc',
            'crictl': host / 'usr/local/bin/crictl',
            'config': host / 'etc/containerd/config.toml',
            'unit': host / 'usr/local/lib/systemd/system/containerd.service',
        }

    def test_apply_succeeds_without_creating_or_managing_cni_path(self) -> None:
        """捕获 Task 5 仍解析、解包或发布 CNI payload 的双重 ownership 缺陷。"""
        environment, host, command_log, _ = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CONTAINERD_INSTALLED', result.stdout)
        self.assertFalse((host / 'opt/cni/bin').exists())
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('.cni.extract.', commands)
        self.assertNotIn('cni-plugins-linux-amd64-v1.9.1.tgz', commands)

    def install_compliant_targets(
        self, environment: dict[str, str], host: Path
    ) -> None:
        targets = self.managed_targets(host)
        binaries = {
            'containerd': self.containerd_version,
            'ctr': self.ctr_binary,
            'shim': self.shim_binary,
            'runc': self.runc_binary,
            'crictl': self.crictl_binary,
        }
        for name, content in binaries.items():
            targets[name].write_bytes(content)
            targets[name].chmod(0o755)
        targets['config'].write_bytes(
            (ROOT / 'bootstrap/containerd/config.toml').read_bytes()
        )
        targets['unit'].write_bytes(
            (ROOT / 'bootstrap/containerd/containerd.service').read_bytes()
        )
        targets['config'].chmod(0o644)
        targets['unit'].chmod(0o644)
        (host / 'var/lib/containerd').mkdir(mode=0o700)
        self.create_cri_socket(host)
        Path(environment['FAKE_SERVICE_ENABLED']).touch()
        Path(environment['FAKE_SERVICE_ACTIVE']).touch()
        Path(environment['FAKE_SERVICE_UNIT_LOADED']).touch()

    def test_check_is_read_only_for_clean_missing_state(self) -> None:
        """捕获 CHECK 解包、安装、启动服务、创建 evidence 或改 swap 的缺陷。"""
        environment, host, command_log, _ = self.make_environment()

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CONTAINERD_CHECK', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        for forbidden in (
            'install ', 'mv ', 'sync ', 'tar-write ', 'daemon-reload',
            ' enable ', ' start ', ' restart ',
        ):
            self.assertNotIn(forbidden, commands)
        self.assertTrue(all(not path.exists() for path in self.managed_targets(host).values()))
        self.assertEqual((host / 'swap.img').read_bytes(), b'preserve swap\n')
        self.assertEqual(list((host / 'root/dev-infra-evidence').iterdir()), [])

    def test_check_rejects_unknown_and_partial_managed_targets(self) -> None:
        """捕获覆盖 binary/config/unit 漂移或把部分安装误判为幂等成功的缺陷。"""
        for name, drift in (
            ('containerd', 'content'),
            ('runc', 'symlink'),
            ('crictl', 'mode'),
            ('config', 'content'),
            ('unit', 'mode'),
        ):
            with self.subTest(name=name, drift=drift):
                environment, host, _, _ = self.make_environment()
                target = self.managed_targets(host)[name]
                if drift == 'symlink':
                    target.symlink_to('/tmp/escape')
                elif drift == 'directory':
                    target.mkdir()
                else:
                    target.write_bytes(b'unknown\n')
                    target.chmod(0o600 if drift == 'mode' else 0o755)
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

        environment, host, _, _ = self.make_environment()
        target = self.managed_targets(host)['containerd']
        target.write_bytes(self.containerd_version)
        target.chmod(0o755)
        result = self.run_stage(environment, '--check')
        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_unsafe_or_nonempty_data_root(self) -> None:
        """捕获接管非空、文件或 symlink data root 的缺陷。"""
        for drift in ('nonempty', 'file', 'symlink'):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                data_root = host / 'var/lib/containerd'
                if drift == 'nonempty':
                    data_root.mkdir()
                    (data_root / 'unknown').write_text('preserve\n', encoding='utf-8')
                elif drift == 'file':
                    data_root.write_text('preserve\n', encoding='utf-8')
                else:
                    data_root.symlink_to('/tmp/escape')
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_unsafe_run_directory_before_install(self) -> None:
        """捕获 targets 尚缺时忽略 run dir 类型、mode 或 owner 漂移的缺陷。"""
        for drift in ('file', 'symlink', 'mode', 'owner'):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                run_dir = host / 'run/containerd'
                if drift == 'file':
                    run_dir.write_bytes(b'unknown\n')
                elif drift == 'symlink':
                    run_dir.symlink_to('/tmp/escape')
                else:
                    run_dir.mkdir(mode=0o711)
                    run_dir.chmod(0o755 if drift == 'mode' else 0o711)
                    if drift == 'owner':
                        environment['BOOTSTRAP_TEST_OWNER_DRIFT_PATH'] = str(
                            run_dir
                        )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_untrusted_run_parent(self) -> None:
        """捕获未验证 `/run` 类型、symlink、0755 mode 或 owner 的缺陷。"""
        for drift in ('file', 'symlink', 'mode', 'owner'):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                run_parent = host / 'run'
                if drift in ('file', 'symlink'):
                    run_parent.rmdir()
                    if drift == 'file':
                        run_parent.write_bytes(b'unknown\n')
                    else:
                        run_parent.symlink_to('/tmp')
                elif drift == 'mode':
                    run_parent.chmod(0o700)
                else:
                    environment['BOOTSTRAP_TEST_OWNER_DRIFT_PATH'] = str(
                        run_parent
                    )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_orphan_socket_before_install(self) -> None:
        """捕获 targets/service 尚缺时把孤立 socket entry 当作 fresh state 的缺陷。"""
        for drift in ('socket', 'file', 'symlink'):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                run_dir = host / 'run/containerd'
                run_dir.mkdir(mode=0o711)
                run_dir.chmod(0o711)
                socket_path = run_dir / 'containerd.sock'
                if drift == 'socket':
                    self.create_cri_socket(host)
                elif drift == 'file':
                    socket_path.write_bytes(b'orphan\n')
                else:
                    socket_path.symlink_to('/tmp/escape')

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_shadow_unit_or_dropin_before_install(self) -> None:
        """捕获 targets 尚缺时忽略已加载 shadow unit 或 drop-in 的缺陷。"""
        for drift in ('fragment', 'dropin'):
            with self.subTest(drift=drift):
                environment, _, _, _ = self.make_environment()
                Path(environment['FAKE_SERVICE_UNIT_LOADED']).touch()
                if drift == 'fragment':
                    environment['FAKE_FRAGMENT_PATH'] = (
                        '/etc/systemd/system/containerd.service'
                    )
                else:
                    environment['FAKE_DROP_IN_PATHS'] = (
                        '/etc/systemd/system/containerd.service.d/override.conf'
                    )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_accepts_load_state_not_found_as_clean_fresh_host(self) -> None:
        """捕获用 systemctl show exit0 误判 LoadState=not-found 为已加载 unit 的缺陷。"""
        environment, _, command_log, _ = self.make_environment()

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CONTAINERD_CHECK', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn('systemctl show ', commands)
        for forbidden in ('daemon-reload', ' enable ', ' start ', ' restart '):
            self.assertNotIn(forbidden, commands)

    def test_check_rejects_unknown_empty_or_failed_unit_state(self) -> None:
        """捕获接受非 not-found/loaded、空输出或 show command failure 的缺陷。"""
        cases = (
            ('FAKE_LOAD_STATE', 'bad-setting'),
            ('FAKE_LOAD_STATE', 'error'),
            ('FAKE_LOAD_STATE', 'masked'),
            ('FAKE_LOAD_STATE_EMPTY', '1'),
            ('FAKE_SYSTEMCTL_SHOW_EMPTY', '1'),
            ('FAKE_SYSTEMCTL_SHOW_FAIL', '1'),
        )
        for variable, value in cases:
            with self.subTest(variable=variable, value=value):
                environment, host, _, _ = self.make_environment()
                environment[variable] = value

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertTrue(
                    all(
                        not path.exists()
                        for path in self.managed_targets(host).values()
                    )
                )

    def test_check_rejects_malformed_systemd_property_output(self) -> None:
        """捕获缺失、重复或非 allowlist systemctl property 被宽松接受的缺陷。"""
        cases = {
            'missing-load-state': 'FragmentPath=\nDropInPaths=',
            'missing-fragment-path': 'LoadState=not-found\nDropInPaths=',
            'missing-drop-in-paths': 'LoadState=not-found\nFragmentPath=',
            'duplicate-load-state': (
                'LoadState=not-found\nLoadState=not-found\n'
                'FragmentPath=\nDropInPaths='
            ),
            'extra-property': (
                'LoadState=not-found\nFragmentPath=\nDropInPaths=\n'
                'UnitFileState=disabled'
            ),
            'non-property-line': (
                'LoadState=not-found\nFragmentPath=\nDropInPaths=\n'
                'unexpected output'
            ),
        }
        for case, output in cases.items():
            with self.subTest(case=case):
                environment, host, _, _ = self.make_environment()
                environment.update(
                    {
                        'FAKE_SYSTEMCTL_SHOW_CUSTOM': '1',
                        'FAKE_SYSTEMCTL_SHOW_OUTPUT': output,
                    }
                )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertTrue(
                    all(
                        not path.exists()
                        for path in self.managed_targets(host).values()
                    )
                )

    def test_check_allows_managed_runtime_data_after_successful_apply(self) -> None:
        """捕获首次启动填充 data root 后把精确安装误判为未知状态的缺陷。"""
        environment, host, command_log, _ = self.make_environment()

        applied = self.run_stage(environment, '--apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        data_root = host / 'var/lib/containerd'
        (data_root / 'io.containerd.metadata.v1.bolt').mkdir(parents=True)
        (data_root / 'io.containerd.metadata.v1.bolt/meta.db').write_bytes(
            b'runtime managed\n'
        )
        command_log.write_text('', encoding='utf-8')

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', checked.stdout)
        commands = command_log.read_text(encoding='utf-8')
        for forbidden in (
            'install ', 'mv ', 'tar-write ', 'daemon-reload',
            ' enable ', ' start ', ' restart ',
        ):
            self.assertNotIn(forbidden, commands)

    def test_check_revalidates_every_staged_digest_and_file_safety(self) -> None:
        """捕获信任前序结果、遗漏六项 digest 或接受不安全 staging 文件的缺陷。"""
        for name in ('containerd', 'runc', 'crictl', 'helm', 'gateway-api', 'cilium-chart'):
            with self.subTest(name=name):
                environment, host, _, _ = self.make_environment()
                lock_line = next(
                    line
                    for line in Path(environment['BOOTSTRAP_TEST_LOCK_FILE']).read_text(encoding='utf-8').splitlines()
                    if line.startswith(f'{name}\t')
                )
                url = lock_line.split('\t')[2]
                staged = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1' / Path(url).name
                staged.write_bytes(b'drift\n')
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

        environment, host, _, _ = self.make_environment()
        staged = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1/crictl-v1.36.0-linux-amd64.tar.gz'
        staged.chmod(0o644)
        result = self.run_stage(environment, '--check')
        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_active_lock_digest_not_in_approved_contract(self) -> None:
        """捕获把 active lock 的任意匹配 digest 当作批准 digest 的缺陷。"""
        environment, host, command_log, _ = self.make_environment()
        lock = Path(environment['BOOTSTRAP_TEST_LOCK_FILE'])
        staged = (
            host
            / 'root/dev-infra-artifacts/pcs-2026-08-10.1/runc.amd64'
        )
        tampered = b'tampered but internally consistent\n'
        staged.write_bytes(tampered)
        staged.chmod(0o600)
        digest = hashlib.sha256(tampered).hexdigest()
        lines = [
            '\t'.join(
                [*line.split('\t')[:3], digest, line.split('\t')[4]]
            )
            if line.startswith('runc\t')
            else line
            for line in lock.read_text(encoding='utf-8').splitlines()
        ]
        lock.write_text('\n'.join(lines) + '\n', encoding='utf-8')

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        self.assertTrue(
            all(not path.exists() for path in self.managed_targets(host).values())
        )
        self.assertFalse(command_log.exists())

    def test_check_rejects_unsafe_target_parent(self) -> None:
        """捕获沿父目录 symlink 逃逸或容忍父目录权限漂移的缺陷。"""
        for drift in ('symlink', 'mode'):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                parent = host / 'etc/containerd'
                parent.rmdir()
                if drift == 'symlink':
                    parent.symlink_to('/tmp')
                else:
                    parent.mkdir(mode=0o700)
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_rejects_archive_missing_or_unsafe_expected_member(self) -> None:
        """捕获 archive 缺成员、路径逃逸或 symlink 冒充 executable 的缺陷。"""
        cases = {
            'containerd': self.archive_bytes([('bin/containerd', self.containerd_version)]),
            'crictl': self.archive_bytes([('crictl', 'bin/crictl')]),
            'escape': self.archive_bytes([('../escape', b'escape\n')]),
        }
        for name, artifact in cases.items():
            with self.subTest(name=name):
                artifact_name = 'containerd' if name == 'escape' else name
                environment, host, _, _ = self.make_environment(
                    {artifact_name: artifact}
                )
                result = self.run_stage(environment, '--apply')
                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_ARCHIVE_UNSAFE', result.stdout)
                self.assertTrue(all(not path.exists() for path in self.managed_targets(host).values()))

    def test_apply_installs_exact_targets_and_verifies_health_without_leak(self) -> None:
        """捕获漏装 crictl、错误 endpoint、宽松健康解析或 raw output 泄漏的缺陷。"""
        environment, host, command_log, _ = self.make_environment()
        environment['FAKE_CANARY'] = 'SECRET_CANARY_STDERR'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CONTAINERD_INSTALLED', result.stdout)
        self.assertNotIn('SECRET_CANARY', result.stdout + result.stderr)
        for path in self.managed_targets(host).values():
            self.assertTrue(path.is_file(), path)
        self.assertEqual(self.managed_targets(host)['crictl'].stat().st_mode & 0o777, 0o755)
        self.assertEqual((host / 'swap.img').read_bytes(), b'preserve swap\n')
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            f'crictl --runtime-endpoint {self.endpoint} --image-endpoint {self.endpoint} info --output json\n',
            commands,
        )
        self.assertIn('systemctl daemon-reload\n', commands)
        self.assertIn('systemctl enable containerd.service\n', commands)
        self.assertIn('systemctl start containerd.service\n', commands)
        evidence = list((host / 'root/dev-infra-evidence').glob('10-containerd-*.txt'))
        self.assertEqual(len(evidence), 1)
        evidence_text = evidence[0].read_text(encoding='utf-8')
        self.assertNotIn('SECRET_CANARY', evidence_text)
        evidence_keys = {line.split('=', 1)[0] for line in evidence_text.splitlines()}
        self.assertEqual(
            evidence_keys,
            {
                'ARTIFACT_SET', 'CONTAINERD_VERSION', 'RUNC_VERSION',
                'CRICTL_VERSION', 'CRI_RUNTIME_READY', 'SNAPSHOTTER',
                'RUNTIME_NAME', 'RUNTIME_TYPE', 'SYSTEMD_CGROUP',
                'SERVICE_ACTIVE', 'SERVICE_ENABLED', 'CRI_SOCKET',
                'PHASE', 'MODE', 'RESULT', 'REASON', 'EVIDENCE',
                'EXIT_CODE', 'NEXT',
            },
        )

    def test_apply_fails_closed_on_sync_or_concurrent_target(self) -> None:
        """捕获忽略 sync 失败或覆盖并发出现目标的缺陷。"""
        environment, host, _, _ = self.make_environment()
        environment['FAKE_SYNC_FAIL'] = '1'
        result = self.run_stage(environment, '--apply')
        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertTrue(all(not path.exists() for path in self.managed_targets(host).values()))

        for conflict_rc in ('0', '1'):
            with self.subTest(conflict_rc=conflict_rc):
                environment, host, _, _ = self.make_environment()
                target = self.managed_targets(host)['containerd']
                environment.update(
                    {
                        'FAKE_MV_RACE_TARGET': str(target),
                        'FAKE_MV_RACE_RC': conflict_rc,
                    }
                )
                result = self.run_stage(environment, '--apply')
                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertEqual(target.read_bytes(), b'concurrent\n')

    def test_apply_keeps_non_conflict_mv_failure_as_apply_failed(self) -> None:
        """捕获把没有并发目标的 mv I/O 失败误分类为 UNKNOWN 的缺陷。"""
        environment, host, _, _ = self.make_environment()
        target = self.managed_targets(host)['containerd']
        environment['FAKE_MV_FAIL_TARGET'] = str(target)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertFalse(target.exists())

    def test_check_exact_install_is_idempotent_without_service_restart(self) -> None:
        """捕获精确已安装状态仍重写文件、reload、enable 或 restart 的缺陷。"""
        environment, host, command_log, _ = self.make_environment()
        self.install_compliant_targets(environment, host)

        result = self.run_stage(environment, '--check')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        for forbidden in ('install ', 'mv ', 'tar-write ', 'daemon-reload', ' enable ', ' start ', ' restart '):
            self.assertNotIn(forbidden, commands)

    def test_check_rejects_exact_files_with_service_state_drift(self) -> None:
        """捕获自动修复 inactive/disabled 精确安装而非 STOP 的缺陷。"""
        for missing_state in ('active', 'enabled'):
            with self.subTest(missing_state=missing_state):
                environment, host, _, _ = self.make_environment()
                self.install_compliant_targets(environment, host)
                Path(environment[f'FAKE_SERVICE_{missing_state.upper()}']).unlink()
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_shadow_unit_dropins_and_socket_drift(self) -> None:
        """捕获只看 active/enabled 而接受 shadow unit、drop-in 或伪 socket 的缺陷。"""
        cases = ('fragment', 'dropin', 'missing', 'file', 'symlink', 'mode')
        for drift in cases:
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                self.install_compliant_targets(environment, host)
                socket_path = host / 'run/containerd/containerd.sock'
                if drift == 'fragment':
                    environment['FAKE_FRAGMENT_PATH'] = (
                        '/etc/systemd/system/containerd.service'
                    )
                elif drift == 'dropin':
                    environment['FAKE_DROP_IN_PATHS'] = (
                        '/etc/systemd/system/containerd.service.d/override.conf'
                    )
                else:
                    socket_path.unlink()
                    if drift == 'file':
                        socket_path.write_bytes(b'not a socket\n')
                    elif drift == 'symlink':
                        socket_path.symlink_to('/tmp/escape')
                    elif drift == 'mode':
                        self.create_cri_socket(host).chmod(0o600)

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_check_rejects_owner_and_runtime_directory_mode_drift(self) -> None:
        """捕获 staging/target/data/run/socket owner 或 runtime dir mode 漂移的缺陷。"""
        cases = (
            'artifact-root', 'staged-file', 'target-parent', 'managed-target',
            'data-root', 'run-dir', 'socket', 'data-missing', 'data-mode',
            'run-mode',
        )
        for drift in cases:
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                if drift in {
                    'managed-target', 'data-root', 'run-dir', 'socket',
                    'data-missing', 'data-mode', 'run-mode',
                }:
                    self.install_compliant_targets(environment, host)
                paths = {
                    'artifact-root': host / 'root/dev-infra-artifacts',
                    'staged-file': (
                        host / 'root/dev-infra-artifacts/pcs-2026-08-10.1/runc.amd64'
                    ),
                    'target-parent': host / 'usr/local/bin',
                    'managed-target': self.managed_targets(host)['containerd'],
                    'data-root': host / 'var/lib/containerd',
                    'run-dir': host / 'run/containerd',
                    'socket': host / 'run/containerd/containerd.sock',
                }
                if drift == 'data-missing':
                    (host / 'var/lib/containerd').rmdir()
                elif drift == 'data-mode':
                    (host / 'var/lib/containerd').chmod(0o755)
                elif drift == 'run-mode':
                    (host / 'run/containerd').chmod(0o755)
                else:
                    environment['BOOTSTRAP_TEST_OWNER_DRIFT_PATH'] = str(
                        paths[drift]
                    )

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_revalidates_target_parent_after_mktemp_race(self) -> None:
        """捕获 extract/publish mktemp 后 parent 漂移仍继续安装的缺陷。"""
        environment, host, _, _ = self.make_environment()
        parent = host / 'usr/local/bin'
        environment['FAKE_MKTEMP_RACE_PARENT'] = str(parent)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertTrue(
            all(not path.exists() for path in self.managed_targets(host).values())
        )

    def assert_extract_parent_race_stops_before_writes(
        self, *, match: str, parent_path: str
    ) -> None:
        for drift in ('mode', 'owner', 'type'):
            with self.subTest(match=match, drift=drift):
                environment, host, command_log, _ = self.make_environment()
                parent = host / parent_path
                marker = host.parent / f'{match.strip(".")}-{drift}.marker'
                environment.update(
                    {
                        'FAKE_MKTEMP_RACE_PARENT': str(parent),
                        'FAKE_MKTEMP_RACE_MATCH': match,
                        'FAKE_MKTEMP_RACE_ACTION': drift,
                        'FAKE_MKTEMP_RACE_OWNER_MARKER': str(marker),
                        'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH': str(parent),
                        'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER': str(marker),
                    }
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                for forbidden in ('tar-write ', 'install ', 'mv '):
                    self.assertNotIn(forbidden, commands)
                self.assertTrue(
                    all(
                        not path.exists()
                        for path in self.managed_targets(host).values()
                    )
                )

    def test_apply_revalidates_crictl_parent_after_its_mktemp(self) -> None:
        """捕获 crictl mktemp 后 parent mode/owner/type 漂移仍 tar 或发布的缺陷。"""
        self.assert_extract_parent_race_stops_before_writes(
            match='.crictl.extract.', parent_path='usr/local/bin'
        )

    def assert_phase_parent_race_stops_followup_writes(
        self, *, phase: str, component: str
    ) -> None:
        environment, host, command_log, _ = self.make_environment()
        parent_path = 'usr/local/bin'
        parent = host / parent_path
        marker = host.parent / f'{phase}-{component}-owner.marker'
        environment.update(
            {
                'FAKE_PHASE_RACE_PHASE': phase,
                'FAKE_PHASE_RACE_COMPONENT': component,
                'FAKE_PHASE_RACE_OWNER_MARKER': str(marker),
                'BOOTSTRAP_TEST_DEFERRED_OWNER_DRIFT_PATH': str(parent),
                'BOOTSTRAP_TEST_OWNER_DRIFT_AFTER_MARKER': str(marker),
            }
        )
        if phase == 'post-mktemp':
            environment['FAKE_PHASE_RACE_MKTEMP_MATCH'] = (
                f'.{component}.extract.'
            )
        elif phase == 'pre-tar':
            environment['FAKE_PHASE_RACE_AFTER_TAR'] = (
                'containerd-2.3.1-linux-amd64.tar.gz'
            )
        else:
            environment['FAKE_PHASE_RACE_AFTER_MV'] = str(
                host / 'usr/local/sbin/runc'
            )

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        reason_phase = {
            'post-mktemp': 'state-raced',
            'pre-tar': 'pre-tar-raced',
            'pre-publish': 'pre-publish-raced',
        }[phase]
        self.assertIn(
            f'REASON={component}-extract-{reason_phase}', result.stdout
        )
        trigger = f'race-trigger {phase} {component}\n'
        commands = command_log.read_text(encoding='utf-8')
        self.assertEqual(commands.count(trigger), 1, commands)
        followup = commands.split(trigger, 1)[1]
        for forbidden in ('tar-write ', 'install ', 'mv '):
            self.assertNotIn(forbidden, followup)
        targets = self.managed_targets(host)
        unpublished = (
            targets.values()
            if phase != 'pre-publish'
            else (targets['crictl'], targets['config'], targets['unit'])
        )
        self.assertTrue(all(not path.exists() for path in unpublished))

    def test_apply_post_mktemp_parent_gate_is_load_bearing(self) -> None:
        """捕获绕过 crictl post-mktemp owner Gate 后继续写入的 mutation。"""
        self.assert_phase_parent_race_stops_followup_writes(
            phase='post-mktemp', component='crictl'
        )

    def test_apply_pre_tar_parent_gate_is_load_bearing(self) -> None:
        """捕获绕过 crictl pre-tar owner Gate 后继续解压的 mutation。"""
        self.assert_phase_parent_race_stops_followup_writes(
            phase='pre-tar', component='crictl'
        )

    def test_apply_pre_publish_parent_gate_is_load_bearing(self) -> None:
        """捕获绕过 crictl pre-publish owner Gate 后继续发布的 mutation。"""
        self.assert_phase_parent_race_stops_followup_writes(
            phase='pre-publish', component='crictl'
        )

    def test_health_rejects_version_and_plugin_drift(self) -> None:
        """捕获宽松接受 containerd/runc/crictl 版本或 CRI/overlayfs plugin 漂移的缺陷。"""
        cases = {
            'FAKE_CONTAINERD_VERSION': 'containerd v2.3.0',
            'FAKE_RUNC_VERSION': 'runc version 1.3.5',
            'FAKE_CRICTL_VERSION': 'crictl version v1.35.0',
            'FAKE_CTR_OUTPUT': 'io.containerd.snapshotter.v1 overlayfs linux/amd64 error',
        }
        for variable, value in cases.items():
            with self.subTest(variable=variable):
                environment, host, _, _ = self.make_environment()
                self.install_compliant_targets(environment, host)
                environment[variable] = value
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)

    def test_health_strictly_parses_runtime_ready_and_allowlisted_json(self) -> None:
        """捕获 RuntimeReady 非唯一/非 boolean、runtime config 漂移或 malformed JSON 被接受及泄漏的缺陷。"""
        duplicate = self.valid_info()
        import json

        duplicate_data = json.loads(duplicate)
        duplicate_data['status']['conditions'].append(
            {'type': 'RuntimeReady', 'status': True}
        )
        drifted = json.loads(self.valid_info())
        drifted['config']['containerd']['runtimes']['runc']['options'][
            'SystemdCgroup'
        ] = False
        cases = (
            self.valid_info(runtime_ready=False),
            self.valid_info(runtime_ready='true'),
            json.dumps(duplicate_data),
            json.dumps(drifted),
            '{SECRET_CANARY_MALFORMED',
        )
        for info in cases:
            with self.subTest(info=hashlib.sha256(info.encode()).hexdigest()):
                environment, host, _, _ = self.make_environment()
                self.install_compliant_targets(environment, host)
                environment['FAKE_CRICTL_INFO'] = info
                result = self.run_stage(environment, '--check')
                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                self.assertNotIn('SECRET_CANARY', result.stdout + result.stderr)


class KubernetesInstallTest(BootstrapTestCase):
    version = '1.36.3-1.1'
    cni_version = '1.9.1-1.1'
    release_key_digest = (
        '7627818cf7bae52f9008c93e8b1f961f53dea11d40891778de216fb1b43be54d'
    )
    kubelet_default_sha256 = (
        '2737f011e1fc6995aeeb6a2071e268e37b1437481bbdb205f5075939f40d7ae7'
    )
    kubelet_default_md5 = '9ba5cd2e9a1e368fa51e13f1dd6a5ec1'
    package_metadata = {
        'kubeadm': (
            'amd64/kubeadm_1.36.3-1.1_amd64.deb',
            '12558824',
            '7225b4b7928de8bb9b7a69b75524c2df1a6f78fcbb40724f7e5b49926119c2af',
        ),
        'kubectl': (
            'amd64/kubectl_1.36.3-1.1_amd64.deb',
            '11766348',
            '22c1bbcecfdee50ad013ab7ab9e90ea9d3aaa01d3ac38ac578534976f856c330',
        ),
        'kubelet': (
            'amd64/kubelet_1.36.3-1.1_amd64.deb',
            '13386608',
            '99c77d7c814ac0b0f1f346c11074160fbbab8243c27ba4236f84f2e536c8eaca',
        ),
        'kubernetes-cni': (
            'amd64/kubernetes-cni_1.9.1-1.1_amd64.deb',
            '38991216',
            '4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93',
        ),
    }
    # 已安装 Cilium 由 agent 写入的 CNI 插件：不属于 kubernetes-cni 包，装 CNI 后才出现。
    cilium_cni_manifest = {
        'cilium-cni': (0o755, 17270840, '6b7c1300294f522f5731629c9c53c756c2c55f6aace656fe08e95418769796ce'),
    }
    cni_manifest = {
        'LICENSE': (0o644, 11357, 'b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1'),
        'README.md': (0o644, 2343, '43c32d29316a4a9fe23af500917bd89e51d6a84fa0dcbfcc75b5fbd834c3145a'),
        'bandwidth': (0o755, 5042926, '01c59cee777ade0608361d94bf3bfe01bda82bc8da276d8be917e225aa660639'),
        'bridge': (0o755, 5698763, '3553f5e8f47ed62aec728ab6f7444f6bf1624f916769852c6deb52cd216e22ba'),
        'dhcp': (0o755, 13725422, 'bf0552ff2ef54fbd8846b21ffe149f4de63dcd98d86d6b91de5e0bd94473870d'),
        'dummy': (0o755, 5251069, '88f9c9d018681a2b806db2c33184a0a4a532773cb71a60e975a9bf2f017199f6'),
        'firewall': (0o755, 5702145, 'ecbd112d77192a125e85ab1fa4ded6cfaf4e9732172e072ee248caa81eba7aed'),
        'host-device': (0o755, 5159967, 'a891bd77c5e25b6c4dfa65c8b78cf7f0a00be5ba5d5bbeccd902c08d7f0ea7f3'),
        'host-local': (0o755, 4350778, 'ac5ff19b1120bd1d58203b20d45165f244691fcf9776ba55d6dd1747f043c90f'),
        'ipvlan': (0o755, 5274322, '40ceded59770a0f28e7a45a0ed5f8c49044e786bc728f34d6c9de7bc5d3fb660'),
        'loopback': (0o755, 4302030, '02956bdd03b9b71693b3efd72afce88384e4472b644a1c6410fe817f618c1a83'),
        'macvlan': (0o755, 5307111, '33d2730d229dea786c56465a1a96db84ca27b3d5ac552bbc9aa5cdc942622814'),
        'portmap': (0o755, 5108385, '10cc11a28d9c16465889eb59968be76cf04fa884939edf70c27b722cec2c0156'),
        'ptp': (0o755, 5475470, '1cbbce28e96accfef5fe6021762a55ad2b114705f410b8837361a201df6c0b03'),
        'sbr': (0o755, 4525826, 'bb886c24182afbad535f158b585524b08a9f1cf0618679987d6b0e11ebf50bb5'),
        'static': (0o755, 3776708, '7bf980bedb303f6d314239413fd4aca5479a9affcd38509057ae203b0da67058'),
        'tap': (0o755, 5453308, 'ebff11573fa4ed5793cc08776b8811a3c0f44705b2b530fd5014e6bf69275c1a'),
        'tuning': (0o755, 4389084, '4659e9129d8c669c21c932cd778dc1ac17a717d100768ea23242883401cbb536'),
        'vlan': (0o755, 5267679, '5f6973d15ad2b0d44d1dc0e59982ed05e34e4709630ecd367f766202f9034ac8'),
        'vrf': (0o755, 4685012, '3f3363182c4777bd0d3ead028147f9ecebd60bb32f2d47b7c181877a00ae049b'),
    }

    def packages_index_text(self) -> str:
        paragraphs: list[str] = []
        for package, (filename, size, digest) in self.package_metadata.items():
            version = self.cni_version if package == 'kubernetes-cni' else self.version
            fields = [
                f'Package: {package}',
                f'Version: {version}',
                'Architecture: amd64',
                f'Filename: {filename}',
                f'Size: {size}',
                f'SHA256: {digest}',
            ]
            if package == 'kubelet':
                fields.append(
                    'Depends: iptables (>= 1.4.21),kubernetes-cni (>= 1.2.0),'
                    'mount,util-linux,libc6'
                )
            paragraphs.append('\n'.join(fields))
        return '\n\n'.join(paragraphs) + '\n'

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def make_environment(self) -> tuple[dict[str, str], Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        command_log = directory / 'commands.log'
        cni_manifest = directory / 'cni-manifest.tsv'
        packages_index = directory / 'Packages'
        isolated_home = directory / 'home'
        for path in (
            host / 'etc/apt/keyrings',
            host / 'etc/apt/sources.list.d',
            host / 'root/dev-infra-evidence',
            host / 'var/lib/apt/lists',
            host / 'var/lib/dpkg',
            host / 'var/tmp',
            host / 'opt',
            host / 'usr/bin',
            host / 'usr/sbin',
            host / 'usr/lib/systemd/system/kubelet.service.d',
            fake_bin,
            isolated_home,
        ):
            path.mkdir(parents=True)
        (host / 'etc/apt/keyrings').chmod(0o755)
        (host / 'etc/apt/sources.list.d').chmod(0o755)
        (host / 'var/tmp').chmod(0o1777)
        (host / 'opt').chmod(0o755)
        kubelet_fragment = host / 'usr/lib/systemd/system/kubelet.service'
        kubelet_dropin = (
            host / 'usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf'
        )
        kubelet_fragment.write_text('[Service]\n', encoding='utf-8')
        kubelet_dropin.write_text('[Service]\n', encoding='utf-8')
        kubelet_fragment.chmod(0o644)
        kubelet_dropin.chmod(0o644)
        for binary_name in ('kubeadm', 'kubectl', 'kubelet'):
            binary = host / 'usr/bin' / binary_name
            binary.write_text(f'approved-{binary_name}\n', encoding='utf-8')
            binary.chmod(0o755)
        (host / 'etc/apt/sources.list').write_text('', encoding='utf-8')
        (host / 'var/lib/dpkg/status').write_text(
            'Status: install ok installed\n', encoding='utf-8'
        )
        cni_manifest.write_text(
            ''.join(
                f'{name}\t{mode:o}\t{size}\t{digest}\n'
                for name, (mode, size, digest) in self.cni_manifest.items()
            ),
            encoding='utf-8',
        )
        cilium_cni_manifest = directory / 'cilium-cni-manifest.tsv'
        cilium_cni_manifest.write_text(
            ''.join(
                f'{name}\t{mode:o}\t{size}\t{digest}\n'
                for name, (mode, size, digest) in self.cilium_cni_manifest.items()
            ),
            encoding='utf-8',
        )
        packages_index.write_text(self.packages_index_text(), encoding='utf-8')

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'stat',
            '''
            #!/bin/sh
            last=
            for last do :; done
            if [ -f "${FAKE_KUBELET_DEFAULT_DRIFTED:-/nonexistent}" ] && \
               [ "${FAKE_KUBELET_DEFAULT_POST_MD5_DRIFT:-}" = owner ] && \
               [ "$last" = "$FAKE_HOST_ROOT/etc/default/kubelet" ]; then
              case "$*" in
                *'%u:%g'*) printf '999:999\n'; exit 0 ;;
              esac
            fi
            if [ "$last" = "${FAKE_STAT_OWNER_DRIFT:-}" ]; then
              case "$*" in
                *'%u:%g'*) printf '999:999\n'; exit 0 ;;
              esac
            fi
            exec /usr/bin/stat "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'readlink',
            '''
            #!/bin/sh
            last=
            for last do :; done
            if [ "${FAKE_READLINK_DIFFERENT_ALIAS:-0}" = 1 ] && \
               [ "$1" = -f ] && \
               [ "$last" = "$FAKE_HOST_ROOT/lib/systemd/system/kubelet.service" ]; then
              printf '%s\n' "$FAKE_HOST_ROOT/unapproved-kubelet.service"
              exit 0
            fi
            exec /usr/bin/readlink "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'curl',
            '''
            #!/bin/sh
            printf 'curl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            output=
            while [ "$#" -gt 0 ]; do
              [ "$1" != --output ] || { output=$2; shift; }
              shift
            done
            [ -n "$output" ] || exit 64
            printf 'official-release-key\n' >"$output"
            ''',
        )
        self.write_executable(
            fake_bin / 'gpg',
            '''
            #!/bin/sh
            printf 'gpg %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            case " $* " in
              *' --homedir '*) ;;
              *) mkdir -p "$HOME/.gnupg" ;;
            esac
            case " $* " in
              *' --dearmor '*)
                while [ "$#" -gt 0 ]; do
                  [ "$1" != --output ] || { output=$2; shift; }
                  shift
                done
                printf 'approved-keyring\n' >"$output"
                ;;
              *' --show-keys '*)
                last=
                for last do :; done
                case "$(tail -c +1 "$last")" in
                  approved-keyring*|official-release-key*) fingerprint=${FAKE_KEY_FINGERPRINT:?} ;;
                  *) fingerprint=0000000000000000000000000000000000000000 ;;
                esac
                case "${FAKE_GPG_STRUCTURE:-primary}" in
                  primary)
                    printf 'pub:-:2048:1:AAAAAAAAAAAAAAAA:0:0::::::scESC::::::23::0:\n'
                    printf 'fpr:::::::::%s:\n' "$fingerprint"
                    ;;
                  sub-only)
                    printf 'sub:-:2048:1:BBBBBBBBBBBBBBBB:0:0::::::s::::::23:\n'
                    printf 'fpr:::::::::%s:\n' "$fingerprint"
                    ;;
                  second-primary)
                    printf 'pub:-:2048:1:AAAAAAAAAAAAAAAA:0:0::::::scESC::::::23::0:\n'
                    printf 'fpr:::::::::%s:\n' "$fingerprint"
                    printf 'pub:-:2048:1:BBBBBBBBBBBBBBBB:0:0::::::scESC::::::23::0:\n'
                    printf 'fpr:::::::::0000000000000000000000000000000000000000:\n'
                    ;;
                  subkey)
                    printf 'pub:-:2048:1:AAAAAAAAAAAAAAAA:0:0::::::scESC::::::23::0:\n'
                    printf 'fpr:::::::::%s:\n' "$fingerprint"
                    printf 'sub:-:2048:1:BBBBBBBBBBBBBBBB:0:0::::::s::::::23:\n'
                    printf 'fpr:::::::::0000000000000000000000000000000000000000:\n'
                    ;;
                  *) exit 64 ;;
                esac
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'validate-apt-config',
            '''
            #!/bin/sh
            config=$1
            [ -f "$config" ] && [ ! -L "$config" ] || exit 1
            [ "$(wc -l <"$config" | tr -d ' ')" = 13 ] || exit 1
            value() {
              awk -F '"' -v directive="$1" '
                $1 == directive " " {value=$2; count++}
                END {if (count != 1) exit 1; print value}
              ' "$config"
            }
            source=$(value 'Dir::Etc::sourcelist') || exit 1
            main=$(value 'Dir::Etc::main') || exit 1
            parts=$(value 'Dir::Etc::parts') || exit 1
            sourceparts=$(value 'Dir::Etc::sourceparts') || exit 1
            lists=$(value 'Dir::State::lists') || exit 1
            status=$(value 'Dir::State::status') || exit 1
            extended=$(value 'Dir::State::extended_states') || exit 1
            archives=$(value 'Dir::Cache::archives') || exit 1
            pkgcache=$(value 'Dir::Cache::pkgcache') || exit 1
            srcpkgcache=$(value 'Dir::Cache::srcpkgcache') || exit 1
            parent=${config%/apt.conf}
            [ "$main" = - ] && [ "$parts" = - ] || exit 1
            [ "$source" = "$FAKE_HOST_ROOT/etc/apt/sources.list.d/kubernetes.list" ] || exit 1
            [ "$sourceparts" = - ] || exit 1
            [ "$lists" = "$parent/lists" ] || exit 1
            [ "$status" = "$FAKE_HOST_ROOT/var/lib/dpkg/status" ] || exit 1
            [ "$extended" = "$parent/state/extended_states" ] || exit 1
            [ "$archives" = "$parent/archives" ] || exit 1
            [ -z "$pkgcache" ] && [ -z "$srcpkgcache" ] || exit 1
            [ -f "$source" ] && [ ! -L "$source" ] || exit 1
            [ "$(cat "$source")" = 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /' ] || exit 1
            [ -d "$lists" ] && [ -f "$status" ] && [ -d "${extended%/*}" ] && [ -d "$archives" ] || exit 1
            ''',
        )
        self.write_executable(
            fake_bin / 'apt-config',
            '''
            #!/bin/sh
            printf 'apt-config %s APT_CONFIG=%s\n' "$*" "${APT_CONFIG:-}" >>"$FAKE_COMMAND_LOG"
            [ "$#" = 1 ] && [ "$1" = dump ] || exit 64
            [ -n "${APT_CONFIG:-}" ] || exit 71
            case " $* " in *' -c '*) exit 71 ;; esac
            "$FAKE_APT_CONFIG_CHECK" "$APT_CONFIG" || exit 71
            cat "$APT_CONFIG"
            case "${FAKE_APT_DUMP_HOOK:-0}" in
              1) printf 'DPkg::Pre-Invoke:: "unapproved-hook";\n' ;;
              post-invoke-success)
                printf 'APT::Update::Post-Invoke-Success:: "unapproved-hook";\n'
                ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'apt-cache',
            '''
            #!/bin/sh
            printf 'apt-cache %s APT_CONFIG=%s\n' "$*" "${APT_CONFIG:-}" >>"$FAKE_COMMAND_LOG"
            if [ "${FAKE_REQUIRE_ISOLATED_APT:-0}" = 1 ]; then
              [ -n "${APT_CONFIG:-}" ] || exit 71
              case " $* " in *' -c '*) exit 71 ;; esac
              "$FAKE_APT_CONFIG_CHECK" "$APT_CONFIG" || exit 71
            fi
            case "$1" in
              policy)
                if [ "$2" = kubernetes-cni ]; then
                  default_candidate=1.9.1-1.1
                else
                  default_candidate=1.36.3-1.1
                fi
                candidate=${FAKE_CANDIDATE_VERSION:-$default_candidate}
                printf '%s:\n  Installed: (none)\n  Candidate: %s\n' "$2" "$candidate"
                printf '  Version table:\n'
                if [ "${FAKE_POLICY_MULTIVERSION:-0}" = 1 ] && [ "$2" != kubernetes-cni ]; then
                  for version in "$candidate" 1.36.3-1.1 1.36.2-2.1 1.36.1-1.1; do
                    printf '     %s 500\n' "$version"
                    printf '        500 https://pkgs.k8s.io/core:/stable:/v1.36/deb  Packages\n'
                  done
                else
                  printf ' *** %s 100\n' "$candidate"
                  printf '        100 https://pkgs.k8s.io/core:/stable:/v1.36/deb  Packages\n'
                fi
                ;;
              show)
                package=${3%%=*}
                case "$package" in
                  kubeadm)
                    filename=amd64/kubeadm_1.36.3-1.1_amd64.deb
                    size=12558824
                    digest=7225b4b7928de8bb9b7a69b75524c2df1a6f78fcbb40724f7e5b49926119c2af
                    ;;
                  kubectl)
                    filename=amd64/kubectl_1.36.3-1.1_amd64.deb
                    size=11766348
                    digest=22c1bbcecfdee50ad013ab7ab9e90ea9d3aaa01d3ac38ac578534976f856c330
                    ;;
                  kubelet)
                    filename=amd64/kubelet_1.36.3-1.1_amd64.deb
                    size=13386608
                    digest=99c77d7c814ac0b0f1f346c11074160fbbab8243c27ba4236f84f2e536c8eaca
                    ;;
                  kubernetes-cni)
                    filename=amd64/kubernetes-cni_1.9.1-1.1_amd64.deb
                    size=38991216
                    digest=4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93
                    ;;
                  *) exit 64 ;;
                esac
                [ "${FAKE_INDEX_DIGEST_DRIFT:-}" != "$package" ] || digest=$(printf '0%.0s' $(seq 1 64))
                if [ "$package" = kubernetes-cni ]; then version=1.9.1-1.1; else version=1.36.3-1.1; fi
                printf 'Package: %s\nVersion: %s\nArchitecture: amd64\n' "$package" "$version"
                printf 'Filename: %s\nSize: %s\nSHA256: %s\n' "$filename" "$size" "$digest"
                [ "${FAKE_INDEX_DUPLICATE:-}" != "$package" ] || printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nFilename: %s\nSize: %s\nSHA256: %s\n' "$package" "$version" "$filename" "$size" "$digest"
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'apt-get',
            '''
            #!/bin/sh
            printf 'apt-get %s APT_CONFIG=%s\n' "$*" "${APT_CONFIG:-}" >>"$FAKE_COMMAND_LOG"
            config=${APT_CONFIG:-}
            exact_cached_transaction() {
              [ -n "$config" ] || return 1
              case " $* " in *' --no-download '*) ;; *) return 1 ;; esac
              archives=$(awk -F '"' '$1 == "Dir::Cache::archives " {print $2}' "$config") || return 1
              [ -d "$archives" ] && [ ! -L "$archives" ] || return 1
              actual=$(find "$archives" -mindepth 1 -maxdepth 1 -print 2>/dev/null | sed 's#.*/##' | sort) || return 1
              expected=$(printf '%s\n' \
                kubeadm_1.36.3-1.1_amd64.deb \
                kubectl_1.36.3-1.1_amd64.deb \
                kubelet_1.36.3-1.1_amd64.deb \
                kubernetes-cni_1.9.1-1.1_amd64.deb | sort)
              [ "$actual" = "$expected" ] || return 1
              for archive in $archives/*.deb; do
                [ -f "$archive" ] && [ ! -L "$archive" ] || return 1
              done
              kubeadm_seen=0
              kubectl_seen=0
              kubelet_seen=0
              cni_seen=0
              for argument in "$@"; do
                case "$argument" in
                  kubeadm=1.36.3-1.1) kubeadm_seen=$((kubeadm_seen + 1)) ;;
                  kubectl=1.36.3-1.1) kubectl_seen=$((kubectl_seen + 1)) ;;
                  kubelet=1.36.3-1.1) kubelet_seen=$((kubelet_seen + 1)) ;;
                  kubernetes-cni=1.9.1-1.1) cni_seen=$((cni_seen + 1)) ;;
                  *.deb|kubeadm|kubectl|kubelet|kubernetes-cni) return 1 ;;
                esac
              done
              [ "$kubeadm_seen" = 1 ] && [ "$kubectl_seen" = 1 ] && \
                [ "$kubelet_seen" = 1 ] && [ "$cni_seen" = 1 ]
            }
            if [ "${FAKE_REQUIRE_ISOLATED_APT:-0}" = 1 ]; then
              [ -n "$config" ] || exit 71
              case " $* " in *' -c '*) exit 71 ;; esac
              "$FAKE_APT_CONFIG_CHECK" "$config" || exit 71
            fi
            case " $* " in
              *' update '*)
                case " $* " in *' -o APT::Update::Error-Mode=any '*) ;; *) exit 66 ;; esac
                [ "${FAKE_APT_UPDATE_FAIL:-0}" != 1 ] || exit 67
                if [ -n "$config" ]; then
                  lists=$(awk -F '"' '$1 == "Dir::State::lists " {print $2}' "$config")
                  [ -d "$lists" ] || exit 72
                  /bin/cp "$FAKE_PACKAGES_INDEX" "$lists/kubernetes_Packages"
                  if [ "${FAKE_INDEX_NEWER_VERSION:-0}" = 1 ]; then
                    {
                      printf '\n'
                      printf 'Package: kubeadm\n'
                      printf 'Version: 1.36.4-1.1\n'
                      printf 'Architecture: amd64\n'
                      printf 'Filename: amd64/kubeadm_1.36.4-1.1_amd64.deb\n'
                      printf 'Size: 1\n'
                      printf 'SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n'
                      printf 'Depends: cri-tools (>= 1.30.0)\n'
                    } >>"$lists/kubernetes_Packages"
                  fi
                  if [ -n "${FAKE_INDEX_MISSING:-}" ]; then
                    case "$FAKE_INDEX_MISSING" in
                      kubernetes-cni) missing_version=1.9.1-1.1 ;;
                      kubeadm|kubectl|kubelet) missing_version=1.36.3-1.1 ;;
                      *) exit 72 ;;
                    esac
                    awk -v package="$FAKE_INDEX_MISSING" -v version="$missing_version" '
                      BEGIN {RS=""; FS="\n"; ORS="\n\n"}
                      {
                        stanza_package=""
                        stanza_version=""
                        for (i=1; i<=NF; i++) {
                          if ($i ~ /^Package: /) stanza_package=substr($i, 10)
                          if ($i ~ /^Version: /) stanza_version=substr($i, 10)
                        }
                        if (stanza_package == package && stanza_version == version) next
                        print
                      }
                    ' "$lists/kubernetes_Packages" >"$lists/kubernetes_Packages.missing"
                    /bin/mv "$lists/kubernetes_Packages.missing" "$lists/kubernetes_Packages"
                  fi
                  if [ -n "${FAKE_INDEX_DIGEST_DRIFT:-}" ]; then
                    awk -v package="$FAKE_INDEX_DIGEST_DRIFT" '
                      BEGIN {RS=""; ORS="\n\n"}
                      {
                        if ($0 ~ ("^Package: " package "\n")) {
                          sub(/SHA256: [0-9a-f]+/, "SHA256: 0000000000000000000000000000000000000000000000000000000000000000")
                        }
                        print
                      }
                    ' "$lists/kubernetes_Packages" >"$lists/kubernetes_Packages.mutated"
                    /bin/mv "$lists/kubernetes_Packages.mutated" "$lists/kubernetes_Packages"
                  fi
                  if [ -n "${FAKE_INDEX_DUPLICATE:-}" ]; then
                    printf '\n' >>"$lists/kubernetes_Packages"
                    sed -n "/^Package: ${FAKE_INDEX_DUPLICATE}\$/,/^\$/p" \
                      "$FAKE_PACKAGES_INDEX" >>"$lists/kubernetes_Packages"
                  fi
                fi
                : >"$FAKE_APT_UPDATED"
                ;;
              *' indextargets '*)
                [ -n "$config" ] || exit 72
                lists=$(awk -F '"' '$1 == "Dir::State::lists " {print $2}' "$config")
                case " $* " in
                  *'$(SUITE)'*)
                    if [ "${FAKE_FLAT_INDEX_METADATA:-0}" = 1 ]; then
                      printf 'Packages|https://pkgs.k8s.io/core:/stable:/v1.36/deb/Packages|$(SUITE)|$(COMPONENT)|$(ARCHITECTURE)|%s/kubernetes_Packages\n' "$lists"
                    else
                      printf 'Packages|https://pkgs.k8s.io/core:/stable:/v1.36/deb/Packages|/||amd64|%s/kubernetes_Packages\n' "$lists"
                    fi
                    ;;
                  *)
                    printf 'Packages|https://pkgs.k8s.io/core:/stable:/v1.36/deb/Packages|%s/kubernetes_Packages\n' "$lists"
                    ;;
                esac
                if [ "${FAKE_SECOND_INDEX:-0}" = 1 ]; then
                  /bin/cp "$FAKE_PACKAGES_INDEX" "$lists/evil_Packages"
                  case " $* " in
                    *'$(SUITE)'*)
                      printf 'Packages|https://evil.invalid/Packages|stable|main|amd64|%s/evil_Packages\n' "$lists"
                      ;;
                    *)
                      printf 'Packages|https://evil.invalid/Packages|%s/evil_Packages\n' "$lists"
                      ;;
                  esac
                fi
                ;;
              *' download '*)
                request=
                request_count=0
                for argument in "$@"; do
                  case "$argument" in
                    kubeadm|kubectl|kubelet|kubernetes-cni|kubeadm=*|kubectl=*|kubelet=*|kubernetes-cni=*)
                      request=$argument
                      request_count=$((request_count + 1))
                      ;;
                  esac
                done
                [ "$request_count" = 1 ] || exit 64
                [ -f "$FAKE_APT_UPDATED" ] || exit 65
                case "$request" in
                  kubeadm=1.36.3-1.1)
                    package=kubeadm; version=1.36.3-1.1; size=12558824
                    ;;
                  kubectl=1.36.3-1.1)
                    package=kubectl; version=1.36.3-1.1; size=11766348
                    ;;
                  kubelet=1.36.3-1.1)
                    package=kubelet; version=1.36.3-1.1; size=13386608
                    ;;
                  kubernetes-cni=1.9.1-1.1)
                    package=kubernetes-cni; version=1.9.1-1.1; size=38991216
                    ;;
                  *) exit 64 ;;
                esac
                /usr/bin/python3 -c 'import os,sys; p=sys.argv[1]; open(p,"wb").close(); os.truncate(p,int(sys.argv[2]))' "${package}_${version}_amd64.deb" "$size"
                [ "${FAKE_DOWNLOAD_EXTRA:-0}" != 1 ] || printf 'extra\n' >unexpected.deb
                ;;
              *' -s install '*)
                exact_cached_transaction "$@" || exit 73
                printf 'Inst kubeadm (1.36.3-1.1 official [%s])\n' "${FAKE_SIMULATION_ARCH:-amd64}"
                printf 'Inst kubectl (1.36.3-1.1 official [amd64])\n'
                printf 'Inst kubelet (1.36.3-1.1 official [amd64])\n'
                printf 'Inst kubernetes-cni (1.9.1-1.1 official [amd64])\n'
                printf 'Conf kubeadm (1.36.3-1.1 official [amd64])\n'
                printf 'Conf kubectl (1.36.3-1.1 official [amd64])\n'
                printf 'Conf kubelet (1.36.3-1.1 official [amd64])\n'
                printf 'Conf kubernetes-cni (1.9.1-1.1 official [amd64])\n'
                case "${FAKE_SIMULATION_TRANSACTION:-exact}" in
                  exact) ;;
                  fifth) printf 'Inst cri-tools (1.36.0-1.1 evil [amd64])\n' ;;
                  configure-fifth) printf 'Conf cri-tools (1.36.0-1.1 evil [amd64])\n' ;;
                  remove) printf 'Remv iptables [1.8.10-3ubuntu2]\n' ;;
                  upgrade) printf 'Inst libc6 [2.39] (2.40 evil [amd64])\n' ;;
                  wrong-version) printf 'Inst kubelet (1.36.2-1.1 evil [amd64])\n' ;;
                  *) exit 64 ;;
                esac
                if [ -n "${FAKE_CNI_RACE_OUTSIDE:-}" ]; then
                  mkdir -p "$FAKE_CNI_RACE_OUTSIDE"
                  ln -s "$FAKE_CNI_RACE_OUTSIDE" "${FAKE_CNI_ROOT%/bin}"
                fi
                if [ "${FAKE_APT_ARCHIVE_RACE:-0}" = 1 ]; then
                  archives=$(awk -F '"' '$1 == "Dir::Cache::archives " {print $2}' "$config")
                  printf 'unapproved\n' >"$archives/cri-tools.deb"
                fi
                ;;
              *' install '*)
                exact_cached_transaction "$@" || exit 73
                case " $* " in *cri-tools*) exit 70 ;; esac
                : >"$FAKE_PACKAGES_INSTALLED"
                "$FAKE_CNI_INSTALL_HELPER"
                if [ -n "${FAKE_CNI_POST_DRIFT_TARGET:-}" ]; then
                  chmod 0777 "$FAKE_CNI_POST_DRIFT_TARGET"
                fi
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'install-cni-fixture',
            '''
            #!/bin/sh
            mkdir -p "$FAKE_CNI_ROOT"
            chmod 0755 "${FAKE_CNI_ROOT%/bin}" "$FAKE_CNI_ROOT"
            while IFS='\t' read -r name mode size digest; do
              : "$digest"
              /usr/bin/python3 -c 'import os,sys; p=sys.argv[1]; open(p,"wb").close(); os.truncate(p,int(sys.argv[2]))' "$FAKE_CNI_ROOT/$name" "$size"
              chmod "$mode" "$FAKE_CNI_ROOT/$name"
            done <"$FAKE_CNI_MANIFEST"
            ''',
        )
        self.write_executable(
            fake_bin / 'apt-mark',
            '''
            #!/bin/sh
            printf 'apt-mark %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            case "$1" in
              showhold)
                if [ "${FAKE_APT_MARK_REDIRECT:-0}" = 1 ]; then
                  printf 'kubeadm\nkubectl\nkubelet\nkubernetes-cni\n'
                elif [ -f "$FAKE_PACKAGES_HELD" ]; then
                  printf 'kubeadm\nkubectl\nkubelet\nkubernetes-cni\n'
                elif [ -n "${FAKE_HOLDS:-}" ]; then
                  printf '%s\n' "$FAKE_HOLDS"
                fi
                ;;
              hold)
                : >"$FAKE_PACKAGES_HELD"
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg-query',
            '''
            #!/bin/sh
            if [ "$#" = 3 ] && [ "$1" = -W ] && [ "$2" = '-f=${Conffiles}' ] && [ "$3" = kubelet ]; then
              printf 'dpkg-query %s\n' "$*" >>"$FAKE_COMMAND_LOG"
              [ "${FAKE_KUBELET_CONFFILES_QUERY_FAIL:-0}" != 1 ] || exit 1
              case "${FAKE_KUBELET_CONFFILES_SHAPE:-exact}" in
                exact) printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n' ;;
                missing) printf '' ;;
                duplicate)
                  printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n'
                  printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n'
                  ;;
                malformed) printf ' /etc/default/kubelet not-a-digest extra\n' ;;
                digest-drift) printf ' /etc/default/kubelet 00000000000000000000000000000000\n' ;;
                *) exit 64 ;;
              esac
              exit 0
            fi
            if [ "$#" = 2 ] && [ "$1" = -W ]; then
              case "$2" in
                *'${Package}'*'${Architecture}'*'${db:Status-Want}'*) ;;
                *) exit 64 ;;
              esac
              printf 'dpkg-query %s\n' "$*" >>"$FAKE_COMMAND_LOG"
              count=0
              [ ! -f "$FAKE_HOLD_ENUM_COUNT" ] || count=$(cat "$FAKE_HOLD_ENUM_COUNT")
              count=$((count + 1))
              printf '%s\n' "$count" >"$FAKE_HOLD_ENUM_COUNT"
              [ "${FAKE_DPKG_HOLD_ENUM_FAIL_AT:-0}" != "$count" ] || exit 1
              [ "${FAKE_DPKG_HOLD_ENUM_FAIL:-0}" != 1 ] || exit 1
              if [ -f "$FAKE_PACKAGES_HELD" ]; then
                holds='kubeadm
kubectl
kubelet
kubernetes-cni'
              else
                holds=${FAKE_HOLDS:-}
              fi
              [ -n "$holds" ] || exit 0
              printf '%s\n' "$holds" | while IFS= read -r held; do
                [ -n "$held" ] || continue
                printf '%s\tamd64\thold\n' "$held"
              done
              exit 0
            fi
            package=
            for package do :; done
            case "$1" in
              -S)
                [ -f "$FAKE_PACKAGES_INSTALLED" ] || [ "${FAKE_INSTALLED_STATE:-}" = exact ] || exit 1
                logical=${2#"$FAKE_HOST_ROOT"}
                case "$logical" in
                  /usr/lib/systemd/system/kubelet.service|/lib/systemd/system/kubelet.service)
                    if [ "${FAKE_DPKG_UNIT_PATH_STYLE:-both}" = lib-only ] && \
                       [ "$logical" = /usr/lib/systemd/system/kubelet.service ]; then
                      exit 1
                    fi
                    owner=kubelet
                    [ "${FAKE_KUBELET_OWNER_DRIFT:-}" != fragment ] || owner=unapproved
                    ;;
                  /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf|/lib/systemd/system/kubelet.service.d/10-kubeadm.conf)
                    if [ "${FAKE_DPKG_UNIT_PATH_STYLE:-both}" = lib-only ] && \
                       [ "$logical" = /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf ]; then
                      exit 1
                    fi
                    owner=kubeadm
                    [ "${FAKE_KUBELET_OWNER_DRIFT:-}" != dropin ] || owner=unapproved
                    ;;
                  /usr/bin/kubeadm) owner=kubeadm ;;
                  /usr/bin/kubectl) owner=kubectl ;;
                  /usr/bin/kubelet) owner=kubelet ;;
                  /etc/default/kubelet)
                    case "${FAKE_KUBELET_DEFAULT_OWNER_SHAPE:-exact}" in
                      exact) owner=kubelet ;;
                      fail) exit 1 ;;
                      other) owner=unapproved ;;
                      duplicate)
                        printf 'kubelet: /etc/default/kubelet\n'
                        printf 'kubelet: /etc/default/kubelet\n'
                        exit 0
                        ;;
                      no-final-newline)
                        printf 'kubelet: /etc/default/kubelet'
                        exit 0
                        ;;
                      trailing-blank)
                        printf 'kubelet: /etc/default/kubelet\n\n'
                        exit 0
                        ;;
                      *) exit 64 ;;
                    esac
                    ;;
                  /opt/cni/bin/cilium-cni)
                    [ "${FAKE_CILIUM_CNI_OWNED:-0}" = 1 ] || exit 1
                    owner=kubernetes-cni
                    ;;
                  /opt/cni/bin/*) owner=kubernetes-cni ;;
                  *) exit 1 ;;
                esac
                if [ "${FAKE_DPKG_CANONICAL_OWNER_DRIFT:-0}" = 1 ] && \
                   [ "$logical" = /usr/lib/systemd/system/kubelet.service ]; then
                  owner=unapproved
                fi
                [ "${FAKE_PACKAGE_BINARY_OWNER_DRIFT:-}" != "$logical" ] || owner=unapproved
                printf '%s: %s\n' "$owner" "$logical"
                exit 0
                ;;
            esac
            case "$package" in
              iptables|mount|util-linux|libc6)
                [ "${FAKE_BASE_DEP_MISSING:-}" != "$package" ] || exit 1
                if [ "$package" = iptables ]; then version=1.8.10-3ubuntu2; else version=1.0; fi
                architecture=amd64
                [ "${FAKE_BASE_DEP_VERSION_DRIFT:-}" != "$package" ] || version=1.4.20
                [ "${FAKE_BASE_DEP_ARCH_DRIFT:-}" != "$package" ] || architecture=arm64
                case "$2" in
                  *'${Version}'*) printf 'install ok installed\t%s\t%s\n' "$version" "$architecture" ;;
                  *) printf 'install ok installed\n' ;;
                esac
                exit 0
                ;;
              cri-tools)
                [ "${FAKE_CRI_TOOLS_INSTALLED:-0}" = 1 ] || exit 1
                printf 'install ok installed\t1.36.0-1.1\tamd64\n'
                exit 0
                ;;
            esac
            if [ -f "$FAKE_PACKAGES_INSTALLED" ] || [ "${FAKE_INSTALLED_STATE:-}" = exact ]; then
              if [ "$package" = kubernetes-cni ]; then version=1.9.1-1.1; else version=1.36.3-1.1; fi
              status_want=install
              if [ -f "$FAKE_PACKAGES_HELD" ] || [ "${FAKE_INSTALLED_STATE:-}" = exact ]; then
                status_want=hold
              fi
              printf '%s ok installed\t%s\tamd64\n' "$status_want" "$version"
            elif [ "${FAKE_INSTALLED_STATE:-}" = partial ] && [ "$package" = kubeadm ]; then
              printf 'install ok installed\t1.36.3-1.1\tamd64\n'
            elif [ "${FAKE_INSTALLED_STATE:-}" = drift ] && [ "$package" = kubeadm ]; then
              printf 'install ok installed\t1.35.0-1.1\tamd64\n'
            else
              exit 1
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg',
            '''
            #!/bin/sh
            if [ "$1" = --verify ]; then
              printf 'dpkg %s\n' "$*" >>"$FAKE_COMMAND_LOG"
              case "$2" in kubelet|kubeadm|kubectl|kubernetes-cni) ;; *) exit 64 ;; esac
              if [ "${FAKE_PACKAGE_VERIFY_DOC_EXCLUDES:-0}" = 1 ]; then
                case "${FAKE_PACKAGE_VERIFY_DOC_SHAPE:-exact}" in
                  exact)
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                    ;;
                  single)
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    ;;
                  duplicate)
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                    ;;
                  other-package)
                    printf 'missing     /usr/share/doc/unapproved/LICENSE\n'
                    printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                    ;;
                  extra-missing)
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                    printf 'missing     /usr/bin/%s\n' "$2"
                    ;;
                  checksum)
                    printf '??5??????   /usr/bin/%s\n' "$2"
                    ;;
                  nonzero)
                    printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                    printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                    exit 1
                    ;;
                  *) exit 64 ;;
                esac
                exit 0
              fi
              drift=0
              [ "$2" != kubelet ] || drift=${FAKE_KUBELET_VERIFY_DRIFT:-0}
              [ "$2" != kubeadm ] || drift=${FAKE_KUBEADM_VERIFY_DRIFT:-0}
              [ "${FAKE_PACKAGE_VERIFY_DRIFT:-}" != "$2" ] || drift=1
              [ "$drift" != 1 ] || {
                printf '??5??????   /usr/bin/kubelet\n'
                exit 1
              }
              exit 0
            fi
            [ "$1" = --compare-versions ] || exit 64
            [ "$3" = ge ] || exit 64
            [ "$4" = 1.4.21 ] || exit 64
            [ "$2" != 1.4.20 ]
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg-deb',
            '''
            #!/bin/sh
            printf 'dpkg-deb %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            file=$2
            package=${file##*/}
            package=${package%%_*}
            [ -z "${FAKE_DEB_PACKAGE_DRIFT:-}" ] || package=wrong-package
            if [ "$package" = kubernetes-cni ]; then version=1.9.1-1.1; else version=1.36.3-1.1; fi
            shift 2
            for field in "$@"; do
              case "$field" in
                Package) value=$package ;;
                Version) value=$version ;;
                Architecture) value=amd64 ;;
                Depends)
                  if [ "$package" = kubelet ]; then
                    value='iptables (>= 1.4.21), kubernetes-cni (>= 1.2.0), mount, util-linux, libc6'
                    case "${FAKE_DEB_DEPENDS_DRIFT:-none}" in
                      none) ;;
                      extra) value="$value, cri-tools" ;;
                      missing) value='iptables (>= 1.4.21), kubernetes-cni (>= 1.2.0), mount, util-linux' ;;
                      version) value='iptables (>= 1.4.21), kubernetes-cni (>= 1.1.0), mount, util-linux, libc6' ;;
                      order) value='kubernetes-cni (>= 1.2.0), iptables (>= 1.4.21), mount, util-linux, libc6' ;;
                      *) exit 64 ;;
                    esac
                  else
                    value=
                  fi
                  ;;
                Pre-Depends|Recommends|Suggests|Conflicts|Breaks|Replaces|Provides)
                  value=
                  ;;
                *) exit 64 ;;
              esac
              if [ "$#" -eq 1 ]; then
                printf '%s\n' "$value"
              else
                printf '%s: %s\n' "$field" "$value"
              fi
            done
            ''',
        )
        self.write_executable(
            fake_bin / 'md5sum',
            '''
            #!/bin/sh
            [ "$#" = 1 ] && [ "$1" = "$FAKE_HOST_ROOT/etc/default/kubelet" ] || exit 64
            [ "${FAKE_KUBELET_DEFAULT_MD5_FAIL:-0}" != 1 ] || exit 1
            digest=9ba5cd2e9a1e368fa51e13f1dd6a5ec1
            [ "${FAKE_KUBELET_DEFAULT_MD5_DRIFT:-0}" != 1 ] || digest=00000000000000000000000000000000
            case "${FAKE_KUBELET_DEFAULT_POST_MD5_DRIFT:-none}" in
              none) ;;
              mode) /bin/chmod 0666 "$1" ;;
              owner) : >"$FAKE_KUBELET_DEFAULT_DRIFTED" ;;
              size) printf 'KUBELET_EXTRA_ARGS=\n\n' >"$1" ;;
              bytes) printf 'XUBELET_EXTRA_ARGS=\n' >"$1" ;;
              *) exit 64 ;;
            esac
            printf '%s  %s\n' "$digest" "$1"
            ''',
        )
        self.write_executable(
            fake_bin / 'sha256sum',
            '''
            #!/bin/sh
            if [ "${1##*/}" = kubelet ]; then
              case "$1" in
                */etc/default/kubelet)
                  [ "${FAKE_KUBELET_DEFAULT_SHA256_FAIL:-0}" != 1 ] || exit 1
                  ;;
              esac
            fi
            case "${1##*/}" in
              kubeadm_*) digest=7225b4b7928de8bb9b7a69b75524c2df1a6f78fcbb40724f7e5b49926119c2af ;;
              kubectl_*) digest=22c1bbcecfdee50ad013ab7ab9e90ea9d3aaa01d3ac38ac578534976f856c330 ;;
              kubelet_*) digest=99c77d7c814ac0b0f1f346c11074160fbbab8243c27ba4236f84f2e536c8eaca ;;
              kubernetes-cni_*) digest=4cd72d8cef4499d3dc410874287b40e8b4241e0772938c5820cbee37986c1d93 ;;
              *.armored.*) digest=7627818cf7bae52f9008c93e8b1f961f53dea11d40891778de216fb1b43be54d ;;
              kubernetes-apt-keyring.gpg|*.decoded.*)
                case "$(cat "$1")" in
                  approved-keyring*) digest=5c463ffcfcb24088da4b049ac7b2c7b61dd9d6a7fa4f24e74eb0a533c53bfa17 ;;
                  *) exec /usr/bin/shasum -a 256 "$@" ;;
                esac
                ;;
              *)
                digest=$(awk -F '\t' -v name="${1##*/}" '$1 == name {print $4}' "$FAKE_CNI_MANIFEST")
                [ -n "$digest" ] || digest=$(awk -F '\t' -v name="${1##*/}" '$1 == name {print $4}' "$FAKE_CILIUM_CNI_MANIFEST")
                [ -n "$digest" ] || exec /usr/bin/shasum -a 256 "$@"
                ;;
            esac
            if [ -n "${FAKE_RELEASE_KEY_DIGEST_DRIFT:-}" ] && [ "${1##*/}" != "${1##*.armored.}" ]; then digest=$(printf '0%.0s' $(seq 1 64)); fi
            case "${1##*/}" in
              "${FAKE_DEB_DIGEST_DRIFT:-__no_deb__}"_*.deb)
                digest=$(printf '0%.0s' $(seq 1 64))
                ;;
            esac
            [ "${FAKE_CNI_FILE_DIGEST_DRIFT:-}" != "${1##*/}" ] || digest=$(printf '0%.0s' $(seq 1 64))
            printf '%s  %s\n' "$digest" "$1"
            ''',
        )
        self.write_executable(
            fake_bin / 'sync',
            '''
            #!/bin/sh
            printf 'sync %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "${FAKE_SYNC_FAIL:-0}" != 1 ]
            ''',
        )
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            printf 'systemctl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            if [ "$*" = 'restart kubelet.service' ]; then
              [ "${FAKE_KUBELET_RESTART_FAIL:-0}" != 1 ] || exit 1
              [ "${FAKE_KUBELET_RESTART_STAYS_INACTIVE:-0}" = 1 ] || : >"$FAKE_KUBELET_RESTARTED"
              exit 0
            fi
            [ "$*" = 'show kubelet.service --property=LoadState --property=UnitFileState --property=ActiveState --property=SubState --property=FragmentPath --property=DropInPaths --property=Result' ] || exit 64
            if [ -f "$FAKE_KUBELET_RESTARTED" ]; then
              case "${FAKE_KUBELET_RESTART_STATE:-auto-restart}" in
                auto-restart)
                  active_state=activating
                  sub_state=auto-restart
                  result=exit-code
                  ;;
                failed)
                  active_state=failed
                  sub_state=failed
                  result=exit-code
                  ;;
                *) exit 64 ;;
              esac
            else
              active_state=${FAKE_KUBELET_ACTIVE_STATE:-activating}
              sub_state=${FAKE_KUBELET_SUB_STATE:-auto-restart}
              result=${FAKE_KUBELET_RESULT:-success}
            fi
            printf 'LoadState=%s\n' "${FAKE_KUBELET_LOAD_STATE:-loaded}"
            printf 'UnitFileState=%s\n' "${FAKE_KUBELET_UNIT_FILE_STATE:-enabled}"
            printf 'ActiveState=%s\n' "$active_state"
            printf 'SubState=%s\n' "$sub_state"
            printf 'FragmentPath=%s\n' "${FAKE_KUBELET_FRAGMENT_PATH:-/usr/lib/systemd/system/kubelet.service}"
            printf 'DropInPaths=%s\n' "${FAKE_KUBELET_DROPIN_PATHS-/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf}"
            case " $* " in *' --property=Result '*) printf 'Result=%s\n' "$result" ;; esac
            if [ ! -f "$FAKE_KUBELET_SHOW_DRIFTED" ] && \
               [ "${FAKE_KUBELET_DEFAULT_POST_SHOW_DRIFT:-none}" = bytes ]; then
              printf 'XUBELET_EXTRA_ARGS=\n' >"$FAKE_HOST_ROOT/etc/default/kubelet"
              : >"$FAKE_KUBELET_SHOW_DRIFTED"
            fi
            ''',
        )

        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'HOME': str(isolated_home),
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'FAKE_HOST_ROOT': str(host),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_APT_UPDATED': str(directory / 'apt-updated'),
                'FAKE_PACKAGES_INSTALLED': str(directory / 'packages-installed'),
                'FAKE_PACKAGES_HELD': str(directory / 'packages-held'),
                'FAKE_HOLD_ENUM_COUNT': str(directory / 'hold-enumeration-count'),
                'FAKE_CNI_INSTALL_HELPER': str(fake_bin / 'install-cni-fixture'),
                'FAKE_KUBELET_RESTARTED': str(directory / 'kubelet-restarted'),
                'FAKE_KUBELET_DEFAULT_DRIFTED': str(
                    directory / 'kubelet-default-drifted'
                ),
                'FAKE_KUBELET_SHOW_DRIFTED': str(
                    directory / 'kubelet-show-drifted'
                ),
                'FAKE_CNI_MANIFEST': str(cni_manifest),
                'FAKE_CILIUM_CNI_MANIFEST': str(cilium_cni_manifest),
                'FAKE_CNI_ROOT': str(host / 'opt/cni/bin'),
                'FAKE_PACKAGES_INDEX': str(packages_index),
                'FAKE_APT_CONFIG_CHECK': str(fake_bin / 'validate-apt-config'),
                # 官方 Release.key 的 fixture 指纹必须由生产 Gate 精确匹配。
                'FAKE_KEY_FINGERPRINT': 'DE15B14486CD377B9E876E1A234654DA9A296436',
            }
        )
        return environment, host, command_log

    def run_stage(
        self, environment: dict[str, str], mode: str = '--check'
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', str(INSTALL_KUBERNETES), mode], env=environment
        )

    def test_fake_stat_extracts_last_argument_under_posix_shell(self) -> None:
        """捕获 /bin/sh fixture 使用 Bash 间接位置参数扩展的缺陷。"""
        environment, host, _ = self.make_environment()
        fake_stat = Path(environment['PATH'].split(':', 1)[0]) / 'stat'
        target = host / 'etc/os-release'
        target.write_text('fixture\n', encoding='utf-8')
        environment['FAKE_STAT_OWNER_DRIFT'] = str(target)
        posix_shell = next(
            (
                str(path)
                for path in (Path('/bin/dash'), Path('/usr/bin/dash'))
                if path.exists()
            ),
            '/bin/sh',
        )

        result = self.run_command(
            [posix_shell, str(fake_stat), '-c', '%u:%g', str(target)],
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '999:999\n')

    def test_fake_apt_download_rejects_unpinned_or_extra_package_requests(
        self,
    ) -> None:
        """捕获 fake download 忽略额外裸包名而让版本 pin mutation 逃逸。"""
        environment, host, _ = self.make_environment()
        environment['FAKE_REQUIRE_ISOLATED_APT'] = '0'
        Path(environment['FAKE_APT_UPDATED']).touch()
        cases = (
            ('kubeadm',),
            ('kubeadm=1.36.2-1.1',),
            ('kubeadm=1.36.3-1.1', 'kubectl'),
            ('kubeadm=1.36.3-1.1', 'kubectl=1.36.3-1.1'),
        )

        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ['apt-get', 'download', *arguments],
                    cwd=host,
                    env=environment,
                    capture_output=True,
                    check=False,
                    text=True,
                )

                self.assertNotEqual(result.returncode, 0, result.stdout)

    def install_repository_contract(self, host: Path) -> None:
        (host / 'etc/apt/keyrings/kubernetes-apt-keyring.gpg').write_text(
            'approved-keyring\n', encoding='utf-8'
        )
        (host / 'etc/apt/keyrings/kubernetes-apt-keyring.gpg').chmod(0o644)
        (host / 'etc/apt/sources.list.d/kubernetes.list').write_text(
            'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] '
            'https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /\n',
            encoding='utf-8',
        )
        (host / 'etc/apt/sources.list.d/kubernetes.list').chmod(0o644)

    def install_cni_contract(self, host: Path) -> None:
        root = host / 'opt/cni/bin'
        root.mkdir(parents=True, mode=0o755, exist_ok=True)
        root.chmod(0o755)
        for name, (mode, size, _) in self.cni_manifest.items():
            path = root / name
            path.touch()
            os.truncate(path, size)
            path.chmod(mode)

    def install_cilium_cni_plugin(
        self, host: Path, *, mode: int = 0o755, size: int | None = None
    ) -> Path:
        name, (_, default_size, _) = next(iter(self.cilium_cni_manifest.items()))
        path = host / 'opt/cni/bin' / name
        path.touch()
        os.truncate(path, default_size if size is None else size)
        path.chmod(mode)
        return path

    def install_official_kubelet_default_conffile(self, host: Path) -> Path:
        target = host / 'etc/default/kubelet'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'KUBELET_EXTRA_ARGS=\n')
        target.chmod(0o644)
        return target

    def test_check_is_zero_write_on_clean_host(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_CHECK', result.stdout)
        self.assertEqual(
            command_log.read_text(encoding='utf-8'),
            'dpkg-query -W -f=${Package}\\t${Architecture}\\t'
            '${db:Status-Want}\\n\n',
        )
        self.assertFalse(
            (host / 'etc/apt/sources.list.d/kubernetes.list').exists()
        )

    def test_rejects_other_minor_and_unknown_repository_state(self) -> None:
        cases = ('other-minor', 'unknown-source', 'unknown-keyring', 'partial')
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'other-minor':
                    (host / 'etc/apt/sources.list.d/legacy.list').write_text(
                        'deb https://pkgs.k8s.io/core:/stable:/v1.35/deb/ /\n',
                        encoding='utf-8',
                    )
                elif case == 'unknown-source':
                    self.install_repository_contract(host)
                    (host / 'etc/apt/sources.list.d/kubernetes.list').write_text(
                        'deb https://mirror.invalid/kubernetes /\n',
                        encoding='utf-8',
                    )
                elif case == 'unknown-keyring':
                    self.install_repository_contract(host)
                    (host / 'etc/apt/keyrings/kubernetes-apt-keyring.gpg').write_text(
                        'unapproved\n', encoding='utf-8'
                    )
                else:
                    (host / 'etc/apt/keyrings/kubernetes-apt-keyring.gpg').write_text(
                        'approved-keyring\n', encoding='utf-8'
                    )

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_rejects_duplicate_deb822_legacy_and_broken_source_entries(self) -> None:
        cases = ('duplicate', 'deb822', 'legacy', 'broken-symlink')
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                target = host / 'etc/apt/sources.list.d/extra.list'
                if case == 'duplicate':
                    target.write_text(
                        'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] '
                        'https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /\n',
                        encoding='utf-8',
                    )
                elif case == 'deb822':
                    target = target.with_suffix('.sources')
                    target.write_text(
                        'Types: deb\nURIs: https://pkgs.k8s.io/core:/stable:/v1.36/deb/\n'
                        'Suites: /\n',
                        encoding='utf-8',
                    )
                elif case == 'legacy':
                    target.write_text(
                        'deb https://apt.kubernetes.io/ kubernetes-xenial main\n',
                        encoding='utf-8',
                    )
                else:
                    target.symlink_to('/missing/unapproved-source')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_rejects_missing_base_dependency_and_installed_cri_tools(self) -> None:
        cases = (
            {'FAKE_BASE_DEP_MISSING': 'iptables'},
            {'FAKE_CRI_TOOLS_INSTALLED': '1'},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment, _, _ = self.make_environment()
                environment.update(overrides)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_usrmerge_unit_paths_preserve_package_ownership(self) -> None:
        """捕获 systemd canonical /usr/lib 与 dpkg manifest /lib 的合法差异。"""
        environment, host, _ = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        (host / 'lib').symlink_to('usr/lib', target_is_directory=True)
        environment['FAKE_DPKG_UNIT_PATH_STYLE'] = 'lib-only'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_usrmerge_unit_paths_reject_unsafe_alias_root(self) -> None:
        """usrmerge fallback 只接受 root-owned 的相对 /lib -> usr/lib。"""
        for drift in (
            'not-symlink',
            'absolute-target',
            'other-directory',
            'owner',
            'different-file',
            'package-owner',
            'canonical-owner',
        ):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                if drift == 'not-symlink':
                    (host / 'lib').mkdir()
                    (host / 'lib').chmod(0o755)
                else:
                    link_target = {
                        'absolute-target': '/usr/lib',
                        'other-directory': 'opt',
                    }.get(drift, 'usr/lib')
                    (host / 'lib').symlink_to(
                        link_target, target_is_directory=True
                    )
                if drift != 'canonical-owner':
                    environment['FAKE_DPKG_UNIT_PATH_STYLE'] = 'lib-only'
                if drift == 'owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(host / 'lib')
                elif drift == 'different-file':
                    environment['FAKE_READLINK_DIFFERENT_ALIAS'] = '1'
                elif drift == 'package-owner':
                    environment['FAKE_KUBELET_OWNER_DRIFT'] = 'fragment'
                elif drift == 'canonical-owner':
                    environment['FAKE_DPKG_CANONICAL_OWNER_DRIFT'] = '1'

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)

    def test_dpkg_verify_accepts_only_declared_doc_exclusions(self) -> None:
        """捕获 Ubuntu dpkg path-exclude 令批准文档缺失的合法 verify shape。"""
        environment, host, _ = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
        excludes.parent.mkdir(parents=True)
        excludes.write_text(
            'path-exclude=/usr/share/man/*\n'
            'path-exclude=/usr/share/doc/*\n'
            'path-include=/usr/share/doc/*/copyright\n',
            encoding='utf-8',
        )
        excludes.chmod(0o644)
        environment['FAKE_PACKAGE_VERIFY_DOC_EXCLUDES'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_dpkg_verify_rejects_unsafe_doc_exclusion_shapes(self) -> None:
        """缺失/不安全 exclude 合同或额外 payload 缺失都必须拒绝。"""
        for drift in (
            'missing-config',
            'symlink-config',
            'unsafe-mode',
            'owner',
            'single',
            'duplicate',
            'other-package',
            'extra-missing',
            'checksum',
            'nonzero',
        ):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                environment['FAKE_PACKAGE_VERIFY_DOC_EXCLUDES'] = '1'
                excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
                if drift != 'missing-config':
                    excludes.parent.mkdir(parents=True)
                    if drift == 'symlink-config':
                        outside = host.parent / 'unapproved-dpkg-excludes'
                        outside.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        outside.chmod(0o644)
                        excludes.symlink_to(outside)
                    else:
                        excludes.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        excludes.chmod(
                            0o666 if drift == 'unsafe-mode' else 0o644
                        )
                if drift == 'owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(excludes)
                if drift in {
                    'single',
                    'duplicate',
                    'other-package',
                    'extra-missing',
                    'checksum',
                    'nonzero',
                }:
                    environment['FAKE_PACKAGE_VERIFY_DOC_SHAPE'] = drift

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)

    def test_resumes_exact_installed_inactive_kubelet_without_reinstall(
        self,
    ) -> None:
        """捕获官方 postinst 仅 preset 后的 installed START_REQUIRED 状态。"""
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        environment['FAKE_KUBELET_ACTIVE_STATE'] = 'inactive'
        environment['FAKE_KUBELET_SUB_STATE'] = 'dead'
        environment['FAKE_KUBELET_RESULT'] = 'success'

        check = self.run_stage(environment)

        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_CHECK', check.stdout)
        self.assertIn('REASON=apply-required', check.stdout)
        self.assertNotIn('systemctl restart', command_log.read_text(encoding='utf-8'))
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('11-kubernetes-*.txt')),
            [],
        )

        apply = self.run_stage(environment, '--apply')

        self.assertEqual(apply.returncode, 0, apply.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', apply.stdout)
        commands_after_apply = command_log.read_text(encoding='utf-8')
        self.assertEqual(commands_after_apply.count('systemctl restart kubelet.service'), 1)
        self.assertNotIn('apt-get ', commands_after_apply)
        self.assertNotIn('apt-mark hold', commands_after_apply)

        repeated = self.run_stage(environment, '--apply')

        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', repeated.stdout)
        self.assertEqual(
            command_log.read_text(encoding='utf-8').count(
                'systemctl restart kubelet.service'
            ),
            1,
        )
        self.assertNotIn(
            'apt-mark hold', command_log.read_text(encoding='utf-8')
        )

    def test_accepts_unmodified_official_kubelet_default_conffile(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        self.install_official_kubelet_default_conffile(host)
        environment['FAKE_KUBELET_ACTIVE_STATE'] = 'inactive'
        environment['FAKE_KUBELET_SUB_STATE'] = 'dead'
        environment['FAKE_KUBELET_RESULT'] = 'success'

        check = self.run_stage(environment)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_CHECK', check.stdout)
        self.assertIn('REASON=apply-required', check.stdout)
        self.assertNotIn(
            'systemctl restart', command_log.read_text(encoding='utf-8')
        )
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('11-kubernetes-*.txt')),
            [],
        )

        apply = self.run_stage(environment, '--apply')
        self.assertEqual(apply.returncode, 0, apply.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', apply.stdout)
        commands_after_apply = command_log.read_text(encoding='utf-8')
        self.assertEqual(
            commands_after_apply.count('systemctl restart kubelet.service'),
            1,
        )
        self.assertNotIn('apt-get ', commands_after_apply)
        self.assertNotIn('apt-mark hold', commands_after_apply)

        repeated = self.run_stage(environment, '--apply')
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', repeated.stdout)
        self.assertEqual(
            command_log.read_text(encoding='utf-8').count(
                'systemctl restart kubelet.service'
            ),
            1,
        )
        self.assertNotIn(
            'apt-mark hold', command_log.read_text(encoding='utf-8')
        )

    def test_rejects_kubelet_default_conffile_provenance_drift(self) -> None:
        cases = (
            ('directory', {}),
            ('symlink', {}),
            ('mode', {}),
            ('owner', {'FAKE_STAT_OWNER_DRIFT': 'TARGET'}),
            ('content-argument', {}),
            ('content-comment', {}),
            ('content-whitespace', {}),
            ('content-extra-newline', {}),
            ('ownership-query-fail', {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'fail'}),
            ('ownership-other', {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'other'}),
            (
                'ownership-duplicate',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'duplicate'},
            ),
            (
                'ownership-no-final-newline',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'no-final-newline'},
            ),
            (
                'ownership-trailing-blank',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'trailing-blank'},
            ),
            ('conffile-query-fail', {'FAKE_KUBELET_CONFFILES_QUERY_FAIL': '1'}),
            ('conffile-missing', {'FAKE_KUBELET_CONFFILES_SHAPE': 'missing'}),
            (
                'conffile-duplicate',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'duplicate'},
            ),
            (
                'conffile-malformed',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'malformed'},
            ),
            (
                'conffile-digest',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'digest-drift'},
            ),
            ('md5-command-fail', {'FAKE_KUBELET_DEFAULT_MD5_FAIL': '1'}),
            ('md5-drift', {'FAKE_KUBELET_DEFAULT_MD5_DRIFT': '1'}),
            (
                'sha256-command-fail',
                {'FAKE_KUBELET_DEFAULT_SHA256_FAIL': '1'},
            ),
        )
        content_mutations = {
            'content-argument': b'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n',
            'content-comment': b'# package default\nKUBELET_EXTRA_ARGS=\n',
            'content-whitespace': b'KUBELET_EXTRA_ARGS= \n',
            'content-extra-newline': b'KUBELET_EXTRA_ARGS=\n\n',
        }
        for drift, overrides in cases:
            with self.subTest(drift=drift):
                environment, host, command_log = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                default_file = self.install_official_kubelet_default_conffile(host)
                environment.update(
                    {
                        key: str(default_file) if value == 'TARGET' else value
                        for key, value in overrides.items()
                    }
                )
                if drift == 'directory':
                    default_file.unlink()
                    default_file.mkdir()
                elif drift == 'symlink':
                    outside = host.parent / 'outside-default-kubelet'
                    outside.write_bytes(b'KUBELET_EXTRA_ARGS=\n')
                    outside.chmod(0o644)
                    default_file.unlink()
                    default_file.symlink_to(outside)
                elif drift == 'mode':
                    default_file.chmod(0o666)
                elif drift in content_mutations:
                    default_file.write_bytes(content_mutations[drift])

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn('systemctl restart', commands)
                self.assertNotIn('apt-get ', commands)
                self.assertNotIn('apt-mark hold', commands)
                self.assertEqual(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '11-kubernetes-*.txt'
                        )
                    ),
                    [],
                )

    def test_rejects_kubelet_default_conffile_drift_during_validation(
        self,
    ) -> None:
        for drift in ('mode', 'owner', 'size', 'bytes'):
            with self.subTest(drift=drift):
                environment, host, command_log = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                self.install_official_kubelet_default_conffile(host)
                environment['FAKE_KUBELET_DEFAULT_POST_MD5_DRIFT'] = drift

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn('systemctl restart', commands)
                self.assertNotIn('apt-get ', commands)
                self.assertNotIn('apt-mark hold', commands)
                self.assertEqual(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '11-kubernetes-*.txt'
                        )
                    ),
                    [],
                )

    def test_rechecks_installed_payload_before_kubelet_restart(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        self.install_official_kubelet_default_conffile(host)
        environment['FAKE_KUBELET_ACTIVE_STATE'] = 'inactive'
        environment['FAKE_KUBELET_SUB_STATE'] = 'dead'
        environment['FAKE_KUBELET_RESULT'] = 'success'
        environment['FAKE_KUBELET_DEFAULT_POST_SHOW_DRIFT'] = 'bytes'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 50, result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertEqual(commands.count('systemctl restart kubelet.service'), 0)
        self.assertNotIn('apt-get ', commands)
        self.assertNotIn('apt-mark hold', commands)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('11-kubernetes-*.txt')),
            [],
        )

    def test_fresh_install_explicitly_starts_kubelet(self) -> None:
        """捕获 Stage 40 误依赖官方 postinst 自动启动 kubelet 的缺陷。"""
        environment, _, command_log = self.make_environment()
        environment['FAKE_KUBELET_ACTIVE_STATE'] = 'inactive'
        environment['FAKE_KUBELET_SUB_STATE'] = 'dead'
        environment['FAKE_KUBELET_RESULT'] = 'success'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)
        self.assertEqual(
            command_log.read_text(encoding='utf-8').count(
                'systemctl restart kubelet.service'
            ),
            1,
        )

    def test_accepts_preinit_kubelet_restart_loop_result(self) -> None:
        """kubeadm 前 auto-restart 可保留上一轮 exit-code Result。"""
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        environment['FAKE_KUBELET_ACTIVE_STATE'] = 'activating'
        environment['FAKE_KUBELET_SUB_STATE'] = 'auto-restart'
        environment['FAKE_KUBELET_RESULT'] = 'exit-code'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        self.assertNotIn(
            'systemctl restart', command_log.read_text(encoding='utf-8')
        )

    def test_kubelet_start_failures_are_fail_closed(self) -> None:
        """重启失败或重启后仍 inactive 都不得写成功 evidence。"""
        cases = (
            (
                'restart-failed',
                {'FAKE_KUBELET_RESTART_FAIL': '1'},
                40,
                'kubelet-start-failed',
            ),
            (
                'still-inactive',
                {'FAKE_KUBELET_RESTART_STAYS_INACTIVE': '1'},
                50,
                'kubelet-start-verification-failed',
            ),
            (
                'failed-after-restart',
                {'FAKE_KUBELET_RESTART_STATE': 'failed'},
                50,
                'kubelet-start-verification-failed',
            ),
        )
        for name, overrides, expected_exit, expected_reason in cases:
            with self.subTest(name=name):
                environment, host, command_log = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                environment.update(
                    {
                        'FAKE_KUBELET_ACTIVE_STATE': 'inactive',
                        'FAKE_KUBELET_SUB_STATE': 'dead',
                        'FAKE_KUBELET_RESULT': 'success',
                        **overrides,
                    }
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertIn(f'REASON={expected_reason}', result.stdout)
                self.assertEqual(
                    command_log.read_text(encoding='utf-8').count(
                        'systemctl restart kubelet.service'
                    ),
                    1,
                )
                self.assertEqual(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '11-kubernetes-*.txt'
                        )
                    ),
                    [],
                )

    def test_rejects_base_dependency_version_or_architecture_drift(self) -> None:
        for override in (
            {'FAKE_BASE_DEP_VERSION_DRIFT': 'iptables'},
            {'FAKE_BASE_DEP_ARCH_DRIFT': 'libc6'},
        ):
            with self.subTest(override=override):
                environment, host, command_log = self.make_environment()
                environment.update(override)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertFalse(command_log.exists())
                self.assertFalse(
                    (host / 'etc/apt/sources.list.d/kubernetes.list').exists()
                )

    def test_accepts_cilium_cni_plugin_alongside_package_payload(self) -> None:
        """装完 Cilium 后 /opt/cni/bin 多出 agent 写入的 cilium-cni，Stage 40 必须仍判 COMPLIANT。"""
        environment, host, _ = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        self.install_cilium_cni_plugin(host)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_cilium_cni_plugin_exemption_is_exact(self) -> None:
        """cilium-cni 只按钉死的 mode/size/digest、root 属主、非包归属放行；其他一律 fail closed。"""
        for drift in ('mode', 'size', 'symlink', 'package-owned', 'other-extra'):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                if drift == 'mode':
                    self.install_cilium_cni_plugin(host, mode=0o775)
                elif drift == 'size':
                    self.install_cilium_cni_plugin(host, size=1)
                elif drift == 'symlink':
                    outside = host.parent / 'cilium-cni-outside'
                    outside.write_bytes(b'')
                    (host / 'opt/cni/bin/cilium-cni').symlink_to(outside)
                elif drift == 'package-owned':
                    self.install_cilium_cni_plugin(host)
                    environment['FAKE_CILIUM_CNI_OWNED'] = '1'
                else:
                    (host / 'opt/cni/bin/unapproved').write_bytes(b'')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stdout)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertIn('REASON=partial-kubernetes-contract', result.stdout)

    def test_rejects_unknown_or_partial_cni_directory_before_mutation(self) -> None:
        for drift in ('unknown', 'partial', 'extra'):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                root = host / 'opt/cni/bin'
                root.mkdir(parents=True)
                if drift == 'unknown':
                    (root / 'bridge').write_bytes(b'unknown\n')
                elif drift == 'partial':
                    name, (mode, size, _) = next(iter(self.cni_manifest.items()))
                    path = root / name
                    path.touch()
                    os.truncate(path, size)
                    path.chmod(mode)
                else:
                    self.install_cni_contract(host)
                    (root / 'unexpected').write_bytes(b'extra\n')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_rejects_unsafe_cni_path_chain_before_repository_mutation(self) -> None:
        cases = (
            'opt-symlink', 'opt-file', 'opt-mode', 'opt-owner',
            'cni-symlink', 'cni-file', 'cni-mode', 'cni-owner',
            'bin-symlink', 'bin-file', 'bin-mode', 'bin-owner',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                outside = host.parent / f'outside-{case}'
                outside.mkdir()
                opt = host / 'opt'
                cni = opt / 'cni'
                bin_dir = cni / 'bin'
                level = case.split('-', 1)[0]
                drift = case.split('-', 1)[1]
                target = {'opt': opt, 'cni': cni, 'bin': bin_dir}[level]
                if level != 'opt':
                    cni.mkdir(mode=0o755)
                if level == 'bin':
                    bin_dir.mkdir(mode=0o755)
                if drift == 'symlink':
                    target.rmdir()
                    target.symlink_to(outside, target_is_directory=True)
                elif drift == 'file':
                    target.rmdir()
                    target.write_text('unsafe\n', encoding='utf-8')
                elif drift == 'mode':
                    target.chmod(0o777)
                else:
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(target)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertFalse(command_log.exists())
                self.assertFalse(
                    (host / 'etc/apt/sources.list.d/kubernetes.list').exists()
                )
                self.assertEqual(list(outside.iterdir()), [])

    def test_apply_ignores_candidate_and_uses_only_locked_artifacts(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_POLICY_MULTIVERSION'] = '1'
        environment['FAKE_INDEX_NEWER_VERSION'] = '1'
        environment['FAKE_CANDIDATE_VERSION'] = '1.36.4-1.1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('apt-cache policy', commands)
        for request in (
            'kubeadm=1.36.3-1.1',
            'kubectl=1.36.3-1.1',
            'kubelet=1.36.3-1.1',
            'kubernetes-cni=1.9.1-1.1',
        ):
            matching_downloads = [
                line
                for line in commands.splitlines()
                if line.startswith('apt-get ')
                and ' download ' in line
                and request in line
            ]
            self.assertEqual(len(matching_downloads), 1, commands)

    def test_rejects_installed_and_hold_drift(self) -> None:
        cases = {
            'installed': {'FAKE_INSTALLED_STATE': 'drift'},
            'partial': {'FAKE_INSTALLED_STATE': 'partial'},
            'hold': {'FAKE_HOLDS': 'kubeadm'},
        }
        for case, overrides in cases.items():
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment.update(overrides)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_rejects_any_hold_outside_exact_kubernetes_set(self) -> None:
        cases = ('unrelated-only', 'exact-plus-unrelated')
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                if case == 'unrelated-only':
                    environment['FAKE_HOLDS'] = 'unrelated-package'
                else:
                    environment['FAKE_INSTALLED_STATE'] = 'exact'
                    environment['FAKE_HOLDS'] = (
                        'kubeadm\nkubectl\nkubelet\nkubernetes-cni\n'
                        'unrelated-package'
                    )
                    self.install_cni_contract(host)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_hold_enumeration_uses_real_dpkg_state_not_global_apt_config(
        self,
    ) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        environment['FAKE_HOLDS'] = (
            'kubeadm\nkubectl\nkubelet\nkubernetes-cni\nunapproved'
        )
        environment['FAKE_APT_MARK_REDIRECT'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            'dpkg-query -W -f=${Package}\\t${Architecture}\\t'
            '${db:Status-Want}\\n',
            commands,
        )
        self.assertNotIn('apt-mark showhold', commands)

    def test_dpkg_hold_enumeration_failure_has_structured_stop(self) -> None:
        environment, _, _ = self.make_environment()
        environment['FAKE_DPKG_HOLD_ENUM_FAIL'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertIn('REASON=package-hold-state-unreadable', result.stdout)

    def test_post_hold_dpkg_enumeration_failure_has_structured_stop(self) -> None:
        environment, host, command_log = self.make_environment()
        environment['FAKE_DPKG_HOLD_ENUM_FAIL_AT'] = '2'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertIn('REASON=package-hold-state-unreadable', result.stdout)
        self.assertIn('apt-mark hold', command_log.read_text(encoding='utf-8'))
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('11-kubernetes-*.txt')),
            [],
        )

    def test_check_existing_keyring_has_no_gnupg_home_side_effect(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        home = Path(environment['HOME'])
        before = sorted(path.relative_to(home) for path in home.rglob('*'))

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        self.assertEqual(
            sorted(path.relative_to(home) for path in home.rglob('*')), before
        )
        self.assertNotIn('gpg ', command_log.read_text(encoding='utf-8'))

    def test_rejects_unexpected_kubelet_pre_init_unit_state(self) -> None:
        cases = (
            {'FAKE_KUBELET_UNIT_FILE_STATE': 'disabled'},
            {
                'FAKE_KUBELET_ACTIVE_STATE': 'failed',
                'FAKE_KUBELET_SUB_STATE': 'failed',
                'FAKE_KUBELET_RESULT': 'exit-code',
            },
        )
        for override in cases:
            with self.subTest(override=override):
                environment, host, command_log = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                environment.update(override)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                self.assertNotIn(
                    'systemctl restart', command_log.read_text(encoding='utf-8')
                )
                self.assertEqual(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '11-kubernetes-*.txt'
                        )
                    ),
                    [],
                )

    def test_rejects_kubelet_dropin_or_package_payload_provenance_drift(
        self,
    ) -> None:
        cases = (
            {'FAKE_KUBELET_DROPIN_PATHS': ''},
            {
                'FAKE_KUBELET_DROPIN_PATHS': (
                    '/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf '
                    '/etc/systemd/system/kubelet.service.d/99-override.conf'
                )
            },
            {
                'FAKE_KUBELET_DROPIN_PATHS': (
                    '/etc/systemd/system/kubelet.service.d/10-kubeadm.conf'
                )
            },
            {'FAKE_KUBELET_OWNER_DRIFT': 'fragment'},
            {'FAKE_KUBELET_OWNER_DRIFT': 'dropin'},
            {'FAKE_KUBELET_VERIFY_DRIFT': '1'},
            {'FAKE_KUBEADM_VERIFY_DRIFT': '1'},
        )
        for override in cases:
            with self.subTest(override=override):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                environment.update(override)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)

    def test_rejects_kubelet_unit_file_metadata_drift(self) -> None:
        for target_name, drift in (
            ('fragment', 'mode'),
            ('fragment', 'owner'),
            ('fragment', 'symlink'),
            ('dropin', 'mode'),
            ('dropin', 'owner'),
            ('dropin', 'symlink'),
        ):
            with self.subTest(target=target_name, drift=drift):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                targets = {
                    'fragment': host / 'usr/lib/systemd/system/kubelet.service',
                    'dropin': (
                        host
                        / 'usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf'
                    ),
                }
                target = targets[target_name]
                if drift == 'mode':
                    target.chmod(0o666)
                elif drift == 'owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(target)
                else:
                    outside = host.parent / f'outside-{target_name}'
                    outside.write_text('[Service]\n', encoding='utf-8')
                    target.unlink()
                    target.symlink_to(outside)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)

    def test_rejects_kubernetes_binary_or_package_provenance_drift(self) -> None:
        cases: list[tuple[str, str, int]] = []
        for binary_name in ('kubeadm', 'kubectl', 'kubelet'):
            for drift in ('mode', 'owner', 'symlink', 'package-owner'):
                cases.append((binary_name, drift, 50))
        cases.extend(
            (
                ('kubectl', 'package-verify', 50),
                ('kubernetes-cni', 'package-verify', 50),
                ('kubeadm', 'shadow', 30),
                ('kubectl', 'shadow', 30),
            )
        )
        for binary_name, drift, expected_exit in cases:
            with self.subTest(binary=binary_name, drift=drift):
                environment, host, _ = self.make_environment()
                self.install_repository_contract(host)
                environment['FAKE_INSTALLED_STATE'] = 'exact'
                Path(environment['FAKE_PACKAGES_HELD']).touch()
                self.install_cni_contract(host)
                if drift == 'shadow':
                    shadow = host / 'usr/sbin' / binary_name
                    shadow.write_text('unapproved-shadow\n', encoding='utf-8')
                    shadow.chmod(0o755)
                elif drift == 'package-verify':
                    environment['FAKE_PACKAGE_VERIFY_DRIFT'] = binary_name
                else:
                    target = host / 'usr/bin' / binary_name
                    if drift == 'mode':
                        target.chmod(0o777)
                    elif drift == 'owner':
                        environment['FAKE_STAT_OWNER_DRIFT'] = str(target)
                    elif drift == 'package-owner':
                        environment['FAKE_PACKAGE_BINARY_OWNER_DRIFT'] = (
                            f'/usr/bin/{binary_name}'
                        )
                    else:
                        outside = host.parent / f'outside-{binary_name}'
                        outside.write_text('unapproved\n', encoding='utf-8')
                        outside.chmod(0o755)
                        target.unlink()
                        target.symlink_to(outside)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertIn(
                    'RESULT=STOP_UNKNOWN_STATE'
                    if expected_exit == 30
                    else 'RESULT=STOP_VERIFY_FAILED',
                    result.stdout,
                )

    def test_rejects_non_pristine_kubelet_pre_init_mutable_inputs(self) -> None:
        cases = (
            'kubeadm-flags', 'config', 'instance-config', 'pki',
            'root-symlink', 'default-content', 'default-mode', 'default-symlink',
            'unknown-file', 'unknown-dir', 'unknown-broken-symlink',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                kubelet_root = host / 'var/lib/kubelet'
                default_file = host / 'etc/default/kubelet'
                if case == 'root-symlink':
                    outside = host.parent / 'outside-kubelet-root'
                    outside.mkdir()
                    kubelet_root.parent.mkdir(parents=True, exist_ok=True)
                    kubelet_root.symlink_to(outside, target_is_directory=True)
                elif case.startswith('default-'):
                    default_file.parent.mkdir(parents=True, exist_ok=True)
                    if case == 'default-symlink':
                        outside = host.parent / 'outside-default-kubelet'
                        outside.write_text('', encoding='utf-8')
                        default_file.symlink_to(outside)
                    else:
                        default_file.write_text(
                            'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n'
                            if case == 'default-content'
                            else '',
                            encoding='utf-8',
                        )
                        default_file.chmod(
                            0o666 if case == 'default-mode' else 0o644
                        )
                else:
                    kubelet_root.mkdir(parents=True)
                    targets = {
                        'kubeadm-flags': kubelet_root / 'kubeadm-flags.env',
                        'config': kubelet_root / 'config.yaml',
                        'instance-config': kubelet_root / 'instance-config.yaml',
                        'pki': kubelet_root / 'pki',
                        'unknown-file': kubelet_root / 'unknown-state',
                        'unknown-dir': kubelet_root / 'plugins',
                        'unknown-broken-symlink': kubelet_root / 'unknown-link',
                    }
                    target = targets[case]
                    if case in ('pki', 'unknown-dir'):
                        target.mkdir()
                    elif case == 'unknown-broken-symlink':
                        target.symlink_to('/missing')
                    else:
                        target.write_text('stale\n', encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn('apt-get ', commands)
                self.assertNotIn('apt-mark hold', commands)

    def test_fresh_install_rejects_preexisting_kubeadm_generated_state(self) -> None:
        environment, host, command_log = self.make_environment()
        kubelet_root = host / 'var/lib/kubelet'
        kubelet_root.mkdir(parents=True)
        (kubelet_root / 'config.yaml').write_text('stale\n', encoding='utf-8')

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('REASON=kubelet-pre-init-inputs-not-pristine', result.stdout)
        commands = (
            command_log.read_text(encoding='utf-8') if command_log.exists() else ''
        )
        self.assertNotIn('apt-get ', commands)

    def test_exact_packages_allow_kubeadm_owned_generated_state(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        kubelet_root = host / 'var/lib/kubelet'
        kubelet_root.mkdir(parents=True, mode=0o700)
        for name in ('config.yaml', 'instance-config.yaml', 'kubeadm-flags.env'):
            (kubelet_root / name).write_text(
                f'kubeadm-generated-{name}\n', encoding='utf-8'
            )
        (kubelet_root / 'pki').mkdir()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('apt-get ', commands)
        self.assertNotIn('apt-mark hold', commands)

    def test_exact_packages_still_reject_kubelet_operator_override(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        default_file = host / 'etc/default/kubelet'
        default_file.parent.mkdir(parents=True, exist_ok=True)
        default_file.write_text(
            'KUBELET_EXTRA_ARGS=--config=/tmp/unapproved\n', encoding='utf-8'
        )
        default_file.chmod(0o644)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 50, result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('apt-get ', commands)
        self.assertNotIn('apt-mark hold', commands)

    def test_allows_secure_kubelet_root_and_empty_operator_override(self) -> None:
        environment, host, _ = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        kubelet_root = host / 'var/lib/kubelet'
        kubelet_root.mkdir(parents=True)
        kubelet_root.chmod(0o750)
        default_file = host / 'etc/default/kubelet'
        default_file.parent.mkdir(parents=True, exist_ok=True)
        default_file.touch(mode=0o644)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)

    def test_apply_rejects_deb_metadata_and_signed_index_digest_drift(self) -> None:
        cases = (
            {'FAKE_DEB_PACKAGE_DRIFT': '1'},
            {'FAKE_DEB_DIGEST_DRIFT': 'kubeadm'},
            {'FAKE_INDEX_DIGEST_DRIFT': 'kubectl'},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment, _, _ = self.make_environment()
                environment.update(overrides)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_apply_verifies_deb_digest_before_metadata_parser(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_DEB_DIGEST_DRIFT'] = 'kubeadm'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('REASON=deb-digest-drift-kubeadm', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('dpkg-deb ', commands)
        self.assertNotIn('apt-get install', commands)

    def test_apply_accepts_official_dpkg_dependency_serialization(self) -> None:
        environment, _, _ = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)

    def test_apply_rejects_downloaded_deb_dependency_drift(self) -> None:
        for mutation in ('extra', 'missing', 'version', 'order'):
            with self.subTest(mutation=mutation):
                environment, _, command_log = self.make_environment()
                environment['FAKE_DEB_DEPENDS_DRIFT'] = mutation

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
                self.assertIn('REASON=deb-dependency-drift-kubelet', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertFalse(
                    any(
                        line.startswith('apt-get ') and ' install ' in line
                        for line in commands.splitlines()
                    )
                )
                self.assertNotIn('apt-mark hold', commands)

    def test_apply_rejects_release_key_digest_or_fingerprint_drift(self) -> None:
        cases = (
            {'FAKE_RELEASE_KEY_DIGEST_DRIFT': '1'},
            {'FAKE_KEY_FINGERPRINT': '0' * 40},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment, _, _ = self.make_environment()
                environment.update(overrides)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_apply_requires_one_primary_key_without_subkeys(self) -> None:
        for structure in ('sub-only', 'second-primary', 'subkey'):
            with self.subTest(structure=structure):
                environment, _, _ = self.make_environment()
                environment['FAKE_GPG_STRUCTURE'] = structure

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_apply_rejects_missing_or_duplicate_index_stanza_and_extra_download(
        self,
    ) -> None:
        cases = (
            {'FAKE_INDEX_MISSING': 'kubeadm'},
            {'FAKE_INDEX_DUPLICATE': 'kubeadm'},
            {'FAKE_DOWNLOAD_EXTRA': '1'},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment, _, _ = self.make_environment()
                environment.update(overrides)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)

    def test_apply_rejects_second_packages_indextarget(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_SECOND_INDEX'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(' indextargets ', commands)
        self.assertIn(' APT_CONFIG=', commands)
        self.assertNotIn(' -c ', commands)
        self.assertNotIn(' download ', commands)

    def test_apply_accepts_real_flat_repository_indextarget_shape(self) -> None:
        environment, _, _ = self.make_environment()
        environment['FAKE_FLAT_INDEX_METADATA'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)

    def test_apply_uses_fail_on_any_update_error(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_APT_UPDATE_FAIL'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertIn(
            ' -o APT::Update::Error-Mode=any update',
            command_log.read_text(encoding='utf-8'),
        )

    def test_apply_uses_managed_isolated_apt_context(self) -> None:
        environment, host, command_log = self.make_environment()
        environment['FAKE_REQUIRE_ISOLATED_APT'] = '1'
        global_cache = host / 'var/cache/apt/archives'
        global_cache.mkdir(parents=True)
        cache_canary = global_cache / 'unapproved-dependency.deb'
        cache_canary.write_text('GLOBAL_CACHE_CANARY\n', encoding='utf-8')
        list_canary = host / 'var/lib/apt/lists/global-list-canary'
        list_canary.write_text('GLOBAL_LIST_CANARY\n', encoding='utf-8')

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        apt_lines = [
            line
            for line in commands.splitlines()
            if line.startswith(('apt-get ', 'apt-cache '))
        ]
        apt_configs = {
            line.rsplit('APT_CONFIG=', 1)[1]
            for line in apt_lines
            if 'APT_CONFIG=' in line
        }
        self.assertNotIn(' -c ', '\n'.join(apt_lines))
        self.assertEqual(len(apt_configs), 1)
        self.assertEqual(
            cache_canary.read_text(encoding='utf-8'), 'GLOBAL_CACHE_CANARY\n'
        )
        self.assertEqual(
            list_canary.read_text(encoding='utf-8'), 'GLOBAL_LIST_CANARY\n'
        )

    def test_apply_rejects_effective_apt_or_dpkg_hook(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_REQUIRE_ISOLATED_APT'] = '1'
        environment['FAKE_APT_DUMP_HOOK'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn('apt-config dump APT_CONFIG=', commands)
        self.assertNotIn('apt-get ', commands)

    def test_apply_rejects_post_invoke_success_apt_hook(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_REQUIRE_ISOLATED_APT'] = '1'
        environment['FAKE_APT_DUMP_HOOK'] = 'post-invoke-success'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn('apt-config dump APT_CONFIG=', commands)
        self.assertNotIn('apt-get ', commands)

    def test_apply_requires_standard_sticky_download_parent(self) -> None:
        environment, host, _ = self.make_environment()
        (host / 'var/tmp').chmod(0o755)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_installs_exact_local_debs_then_holds_and_records_evidence(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBERNETES_INSTALLED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        update_position = commands.index(
            ' -o APT::Update::Error-Mode=any update'
        )
        download_position = commands.index(' download ')
        install_position = commands.index(' install ')
        self.assertLess(update_position, download_position)
        self.assertLess(commands.rindex(' download '), install_position)
        self.assertLess(install_position, commands.index('apt-mark hold'))
        self.assertIn('kubeadm_1.36.3-1.1_amd64.deb', commands)
        self.assertIn('kubernetes-cni_1.9.1-1.1_amd64.deb', commands)
        install_command = next(
            line for line in commands.splitlines()
            if line.startswith('apt-get ') and ' install ' in line and ' -s ' not in line
        )
        simulation_command = next(
            line for line in commands.splitlines()
            if line.startswith('apt-get ') and ' install ' in line and ' -s ' in line
        )
        self.assertIn('--no-download', install_command)
        self.assertNotIn('.deb', install_command)
        self.assertNotIn('cri-tools', install_command)
        for selection in (
            'kubeadm=1.36.3-1.1',
            'kubectl=1.36.3-1.1',
            'kubelet=1.36.3-1.1',
            'kubernetes-cni=1.9.1-1.1',
        ):
            self.assertEqual(simulation_command.count(selection), 1)
            self.assertEqual(install_command.count(selection), 1)
        self.assertEqual(
            simulation_command.replace(' -s install ', ' install ', 1),
            install_command.replace(' install -y ', ' install ', 1),
        )
        self.assertEqual(
            set((host / 'opt/cni/bin').iterdir()),
            {host / 'opt/cni/bin' / name for name in self.cni_manifest},
        )
        evidence = list(
            (host / 'root/dev-infra-evidence').glob('11-kubernetes-*.txt')
        )
        self.assertEqual(len(evidence), 1)
        evidence_text = evidence[0].read_text(encoding='utf-8')
        for _, _, digest in self.package_metadata.values():
            self.assertIn(digest, evidence_text)

    def test_apply_rejects_non_exact_simulated_transaction(self) -> None:
        for mutation in (
            'fifth', 'configure-fifth', 'remove', 'upgrade', 'wrong-version'
        ):
            with self.subTest(mutation=mutation):
                environment, _, command_log = self.make_environment()
                environment['FAKE_SIMULATION_TRANSACTION'] = mutation

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
                apt_install_lines = [
                    line
                    for line in command_log.read_text(encoding='utf-8').splitlines()
                    if line.startswith('apt-get ') and ' install ' in line
                ]
                self.assertEqual(len(apt_install_lines), 1)
                self.assertIn(' -s ', apt_install_lines[0])
                self.assertNotIn('apt-mark hold', command_log.read_text(encoding='utf-8'))

    def test_apply_rejects_wrong_architecture_simulation(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_SIMULATION_ARCH'] = 'arm64'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        install_lines = [
            line
            for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('apt-get ') and ' install ' in line
        ]
        self.assertEqual(len(install_lines), 1)
        self.assertIn(' -s ', install_lines[0])

    def test_apply_rejects_private_archive_cache_race(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_APT_ARCHIVE_RACE'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 20, result.stderr)
        self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
        install_lines = [
            line
            for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('apt-get ') and ' install ' in line
        ]
        self.assertEqual(len(install_lines), 1)
        self.assertIn(' -s ', install_lines[0])

    def test_apply_rechecks_cni_ancestry_after_simulation(self) -> None:
        environment, host, command_log = self.make_environment()
        outside = host.parent / 'outside-cni-race'
        environment['FAKE_CNI_RACE_OUTSIDE'] = str(outside)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        install_lines = [
            line
            for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('apt-get ') and ' install ' in line
        ]
        self.assertEqual(len(install_lines), 1)
        self.assertIn(' -s ', install_lines[0])
        self.assertNotIn('apt-mark hold', command_log.read_text(encoding='utf-8'))
        self.assertEqual(list(outside.iterdir()), [])

    def test_apply_rechecks_cni_ancestry_after_install_before_hold(self) -> None:
        environment, host, command_log = self.make_environment()
        cni_parent = host / 'opt/cni'
        environment['FAKE_CNI_POST_DRIFT_TARGET'] = str(cni_parent)

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(' --no-download ', commands)
        self.assertIn(
            'apt-mark hold kubeadm kubectl kubelet kubernetes-cni', commands
        )

    def test_exact_state_is_idempotent_without_writes(self) -> None:
        environment, host, command_log = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn('apt-get ', commands)
        self.assertNotIn('apt-mark hold', commands)

    def test_exact_installed_cni_manifest_drift_is_not_idempotent(self) -> None:
        environment, host, _ = self.make_environment()
        self.install_repository_contract(host)
        environment['FAKE_INSTALLED_STATE'] = 'exact'
        Path(environment['FAKE_PACKAGES_HELD']).touch()
        self.install_cni_contract(host)
        (host / 'opt/cni/bin/bridge').chmod(0o644)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_stops_if_atomic_sync_fails(self) -> None:
        environment, host, _ = self.make_environment()
        environment['FAKE_SYNC_FAIL'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertFalse(
            (host / 'etc/apt/keyrings/kubernetes-apt-keyring.gpg').exists()
        )


class KubeadmInitTest(BootstrapTestCase):
    canary = 'SECRET_CANARY_DO_NOT_LOG'

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def seed_official_kubelet_package_footprint(self, host: Path) -> None:
        kubernetes_root = host / 'etc/kubernetes'
        manifests = kubernetes_root / 'manifests'
        manifests.mkdir(parents=True)
        kubernetes_root.chmod(0o775)
        manifests.chmod(0o775)
        keep = manifests / '.kubelet-keep'
        keep.write_bytes(b'')
        keep.chmod(0o644)

    def seed_official_kubelet_state_footprint(self, host: Path) -> None:
        kubelet_root = host / 'var/lib/kubelet'
        kubelet_root.mkdir(parents=True)
        kubelet_root.chmod(0o775)
        keep = kubelet_root / '.kubelet-keep'
        keep.write_bytes(b'')
        keep.chmod(0o644)

    def seed_official_kubelet_default_conffile(self, host: Path) -> Path:
        target = host / 'etc/default/kubelet'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'KUBELET_EXTRA_ARGS=\n')
        target.chmod(0o644)
        return target

    def make_environment(self) -> tuple[dict[str, str], Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        fake_bin = directory / 'bin'
        gates = directory / 'gates'
        command_log = directory / 'commands.log'
        drift_dir = directory / 'drift'
        config_source = directory / 'init.yaml'
        for path in (
            host / 'root/dev-infra-evidence',
            host / 'sys/fs/cgroup',
            host / 'var/tmp',
            host / 'usr/local/bin',
            host / 'usr/bin',
            host / 'usr/sbin',
            fake_bin,
            gates,
            drift_dir,
        ):
            path.mkdir(parents=True)
        (host / 'var/tmp').chmod(0o1777)
        (host / 'etc/os-release').parent.mkdir(parents=True, exist_ok=True)
        (host / 'etc/os-release').write_text(
            'ID=ubuntu\nVERSION_ID="24.04"\n', encoding='utf-8'
        )
        (host / 'swap.img').write_bytes(b'preserve swap\n')
        config_source.write_bytes((ROOT / 'bootstrap/hosts/example-node/kubeadm-init.yaml').read_bytes())
        config_source.chmod(0o644)
        hosts_root = directory / 'hosts'
        hosts_root.mkdir()
        self.write_fixture_host(hosts_root)

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'hostname',
            '#!/bin/sh\nprintf "%s\\n" "${FAKE_HOSTNAME:-example-node}"\n',
        )
        self.write_executable(
            fake_bin / 'uname', '#!/bin/sh\nprintf "%s\\n" "${FAKE_ARCH:-x86_64}"\n'
        )
        self.write_executable(
            fake_bin / 'ip',
            '''
            #!/bin/sh
            node_ip="${FAKE_NODE_IP:-192.0.2.10}"
            node_subnet="${node_ip%.*}.0/24"
            case "$*" in
              *address*)
                if [ -f "$FAKE_DRIFT_DIR/ip" ]; then
                  printf '2: ens160 inet 192.0.2.99/24 scope global ens160\n'
                else
                  printf '%s\n' "${FAKE_IP_ADDRESS:-2: ens160 inet ${node_ip}/24 scope global ens160}"
                fi
                ;;
              *route*)
                if [ -f "$FAKE_DRIFT_DIR/route" ]; then
                  printf '172.21.0.0/24 dev ens160\n'
                else
                  printf '%s\n' "${FAKE_IP_ROUTES:-${node_subnet} dev ens160 src ${node_ip}}"
                fi
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'swapon',
            '''#!/bin/sh
            if [ "$#" = 4 ] &&
               [ "$1" = '--show=NAME,SIZE' ] &&
               [ "$2" = --noheadings ] &&
               [ "$3" = --raw ] &&
               [ "$4" = --bytes ]; then
              :
            elif [ "$#" = 5 ] &&
                 [ "$1" = --show ] &&
                 [ "$2" = --noheadings ] &&
                 [ "$3" = --bytes ] &&
                 [ "$4" = --output ] &&
                 [ "$5" = NAME,SIZE ]; then
              if [ "${FAKE_SWAPON_UTIL_LINUX_239:-0}" = 1 ]; then
                printf '/swap.img file 4106219520    0   -2 fixture-uuid \n'
                exit 0
              fi
            else
              exit 64
            fi
            if [ -f "$FAKE_DRIFT_DIR/swap" ]; then
              printf '/swap.img invalid\n'
            else
              printf '%s\n' "${FAKE_SWAP_OUTPUT:-/swap.img 4294963200}"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'stat',
            '''#!/bin/sh
            last=
            for last do :; done
            if [ "$last" = "$FAKE_HOST_ROOT/etc/default/kubelet" ]; then
              value=
              case "$1:$2" in
                '-c:%a') value=$(/usr/bin/stat -c '%a' "$last" 2>/dev/null) || value= ;;
                '-f:%Lp') value=$(/usr/bin/stat -f '%Lp' "$last" 2>/dev/null) || value= ;;
              esac
              if [ -n "$value" ] && \
                 [ "${FAKE_KUBELET_DEFAULT_MODE_OUTPUT_FAIL:-0}" = 1 ]; then
                printf '%s\n' "$value"
                exit 1
              fi
              value=
              case "$1:$2" in
                '-c:%s') value=$(/usr/bin/stat -c '%s' "$last" 2>/dev/null) || value= ;;
                '-f:%z') value=$(/usr/bin/stat -f '%z' "$last" 2>/dev/null) || value= ;;
              esac
              if [ -n "$value" ] && \
                 [ -n "${FAKE_KUBELET_DEFAULT_SIZE_OUTPUT_FAIL_ON_CALL:-}" ]; then
                calls_file="$FAKE_DRIFT_DIR/kubelet-default-size-calls"
                calls=0
                [ ! -f "$calls_file" ] || IFS= read -r calls <"$calls_file"
                calls=$((calls + 1))
                printf '%s\n' "$calls" >"$calls_file"
                printf '%s\n' "$value"
                [ "$calls" != "$FAKE_KUBELET_DEFAULT_SIZE_OUTPUT_FAIL_ON_CALL" ] || exit 1
                exit 0
              fi
            fi
            if [ "$last" = "${FAKE_STAT_OWNER_DRIFT:-}" ]; then
              case "$*" in *'%u:%g'*) printf '999:999\n'; exit 0 ;; esac
            fi
            if [ "$*" = "-fc %T $FAKE_HOST_ROOT/sys/fs/cgroup" ]; then
              if [ -f "$FAKE_DRIFT_DIR/cgroup" ]; then printf 'tmpfs\n'; else printf 'cgroup2fs\n'; fi
              exit 0
            fi
            exec /usr/bin/stat "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'sha256sum',
            '''
            #!/bin/sh
            last=
            for last do :; done
            if [ "$last" = "$FAKE_HOST_ROOT/etc/default/kubelet" ]; then
              [ "${FAKE_KUBELET_DEFAULT_SHA256_FAIL:-0}" != 1 ] || exit 1
              if [ "${FAKE_KUBELET_DEFAULT_SHA256_DRIFT:-0}" = 1 ]; then
                printf '%064d  %s\n' 0 "$last"
                exit 0
              fi
              if [ -n "${FAKE_KUBELET_DEFAULT_SHA256_OUTPUT_FAIL_ON_CALL:-}" ]; then
                calls_file="$FAKE_DRIFT_DIR/kubelet-default-sha256-calls"
                calls=0
                [ ! -f "$calls_file" ] || IFS= read -r calls <"$calls_file"
                calls=$((calls + 1))
                printf '%s\n' "$calls" >"$calls_file"
                if [ "$calls" = "$FAKE_KUBELET_DEFAULT_SHA256_OUTPUT_FAIL_ON_CALL" ]; then
                  printf '2737f011e1fc6995aeeb6a2071e268e37b1437481bbdb205f5075939f40d7ae7  %s\n' "$last"
                  exit 1
                fi
              fi
            fi
            if [ "${last##*/}" = .kubelet-keep ] &&
               { [ -z "${FAKE_KUBELET_KEEP_SHA256_TARGET:-}" ] ||
                 [ "$FAKE_KUBELET_KEEP_SHA256_TARGET" = "$last" ]; }; then
              [ "${FAKE_KUBELET_KEEP_SHA256_FAIL:-0}" != 1 ] || exit 1
              if [ "${FAKE_KUBELET_KEEP_SHA256_DRIFT:-0}" = 1 ]; then
                printf '%064d  %s\n' 0 "$last"
                exit 0
              fi
            fi
            if [ -x /usr/bin/sha256sum ]; then
              exec /usr/bin/sha256sum "$@"
            fi
            exec /usr/bin/shasum -a 256 "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'cat',
            '''#!/bin/sh
            if [ "$#" = 1 ] && \
               [ "$1" = "$FAKE_HOST_ROOT/etc/default/kubelet" ] && \
               [ "${FAKE_KUBELET_DEFAULT_CONTENT_OUTPUT_FAIL:-0}" = 1 ]; then
              /bin/cat "$1"
              exit 1
            fi
            exec /bin/cat "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'ss',
            '#!/bin/sh\n[ "${FAKE_SS_FAIL:-0}" != 1 ] || exit 1\n[ "${FAKE_6443_LISTENER:-0}" != 1 ] && [ ! -f "$FAKE_LISTENER_MARKER" ] || printf "LISTEN 0 4096 [::]:6443 [::]:*\\n"\n',
        )
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            case "$*" in
              'is-active kubelet.service') printf 'active\n' ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'kubeadm',
            '''
            #!/bin/sh
            printf 'kubeadm %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            if [ "${FAKE_PATH_KUBEADM_SHADOW:-0}" = 1 ] && [ "$0" != "$FAKE_APPROVED_KUBEADM" ]; then
              printf 'shadow-kubeadm invoked\n' >>"$FAKE_COMMAND_LOG"
              exit 42
            fi
            printf '%s\n' "$FAKE_CANARY" >&2
            config=
            for argument in "$@"; do config=$argument; done
            apply_drift() {
              drift=$1
              [ -n "$drift" ] || return 0
              case "$drift" in
                config) printf '\n# drift\n' >>"$FAKE_CONFIG_SOURCE" ;;
                kubelet-package-footprint)
                  printf 'raced\n' >"$FAKE_HOST_ROOT/var/lib/kubelet/unknown-state"
                  ;;
                kubelet-default-conffile)
                  printf 'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n' \
                    >"$FAKE_HOST_ROOT/etc/default/kubelet"
                  ;;
                snapshot-content|snapshot-mode|snapshot-symlink)
                  case "$config" in
                    "$FAKE_HOST_ROOT"/var/tmp/.kubeadm-config.*/*) ;;
                    *) : >"$FAKE_DRIFT_DIR/snapshot-not-private"; return 0 ;;
                  esac
                  if [ "$drift" = snapshot-content ]; then
                    printf '\n# raced\n' >>"$config"
                  elif [ "$drift" = snapshot-mode ]; then
                    chmod 0777 "$config"
                  else
                    rm -f "$config"
                    ln -s "$FAKE_CONFIG_SOURCE" "$config"
                  fi
                  ;;
                *) : >"$FAKE_DRIFT_DIR/$drift" ;;
              esac
            }
            case "$*" in
              'config validate --config '* )
                [ "${FAKE_VALIDATE_FAIL:-0}" != 1 ] || exit 1
                apply_drift "${FAKE_DRIFT_AFTER_VALIDATE:-}"
                ;;
              'init phase preflight --config '* )
                [ "${FAKE_PREFLIGHT_FAIL:-0}" != 1 ] || exit 1
                if [ "${FAKE_PREINIT_RACE:-}" = manifest ]; then
                  mkdir -p "$FAKE_HOST_ROOT/etc/kubernetes/manifests"
                  ln -s /missing "$FAKE_HOST_ROOT/etc/kubernetes/manifests/kube-controller-manager.yaml"
                fi
                if [ "${FAKE_PREINIT_RACE:-}" = kubelet-config ]; then
                  mkdir -p "$FAKE_HOST_ROOT/var/lib/kubelet"
                  printf 'raced\n' >"$FAKE_HOST_ROOT/var/lib/kubelet/config.yaml"
                fi
                [ "${FAKE_PREINIT_RACE:-}" != listener ] || : >"$FAKE_LISTENER_MARKER"
                apply_drift "${FAKE_DRIFT_AFTER_PREFLIGHT:-}"
                ;;
              'init --config '* )
                if [ "${FAKE_INIT_FAIL:-0}" = 1 ]; then
                  mkdir -p "$FAKE_HOST_ROOT/etc/kubernetes/pki"
                  printf 'partial\n' >"$FAKE_HOST_ROOT/etc/kubernetes/pki/partial-init"
                  exit 1
                fi
                printf '%s\n' "$FAKE_CANARY token certificate-key kubeconfig"
                mkdir -p "$FAKE_HOST_ROOT/etc/kubernetes/manifests" "$FAKE_HOST_ROOT/etc/kubernetes/pki"
                printf 'kubeconfig\n' >"$FAKE_HOST_ROOT/etc/kubernetes/admin.conf"
                chmod 0600 "$FAKE_HOST_ROOT/etc/kubernetes/admin.conf"
                for component in kube-apiserver kube-controller-manager kube-scheduler etcd; do
                  printf 'manifest\n' >"$FAKE_HOST_ROOT/etc/kubernetes/manifests/${component}.yaml"
                  chmod 0600 "$FAKE_HOST_ROOT/etc/kubernetes/manifests/${component}.yaml"
                done
                [ "${FAKE_CREATE_KUBE_PROXY:-0}" != 1 ] || printf 'forbidden\n' >"$FAKE_HOST_ROOT/etc/kubernetes/manifests/kube-proxy.yaml"
                if [ "${FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES:-0}" != 1 ]; then
                  chmod 0700 "$FAKE_HOST_ROOT/etc/kubernetes/manifests"
                  chmod 0755 "$FAKE_HOST_ROOT/etc/kubernetes"
                fi
                mkdir -p "$FAKE_HOST_ROOT/var/lib/etcd/member"
                chmod 0700 "$FAKE_HOST_ROOT/var/lib/etcd"
                printf 'certificate\n' >"$FAKE_HOST_ROOT/etc/kubernetes/pki/apiserver.crt"
                : >"$FAKE_LISTENER_MARKER"
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            host / 'usr/bin/kubeadm',
            (fake_bin / 'kubeadm').read_text(encoding='utf-8'),
        )
        self.write_executable(
            fake_bin / 'dpkg-query',
            '''
            #!/bin/sh
            if [ "$#" = 3 ] && [ "$1" = -W ] && \
               [ "$2" = '-f=${Conffiles}' ] && [ "$3" = kubelet ]; then
              [ "${FAKE_KUBELET_CONFFILES_QUERY_FAIL:-0}" != 1 ] || exit 1
              case "${FAKE_KUBELET_CONFFILES_SHAPE:-exact}" in
                exact)
                  printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n'
                  ;;
                missing) printf '' ;;
                duplicate)
                  printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n'
                  printf ' /etc/default/kubelet 9ba5cd2e9a1e368fa51e13f1dd6a5ec1\n'
                  ;;
                malformed)
                  printf ' /etc/default/kubelet not-a-digest extra\n'
                  ;;
                digest-drift)
                  printf ' /etc/default/kubelet 00000000000000000000000000000000\n'
                  ;;
                *) exit 64 ;;
              esac
              exit 0
            fi
            [ "$1" = -S ] || exit 64
            case "$2" in
              /usr/bin/kubeadm) package=kubeadm ;;
              /usr/bin/kubectl) package=kubectl ;;
              /etc/kubernetes|/etc/kubernetes/manifests|/etc/kubernetes/manifests/.kubelet-keep)
                package=kubelet
                ;;
              /var/lib/kubelet|/var/lib/kubelet/.kubelet-keep)
                package=kubelet
                ;;
              /etc/default/kubelet)
                case "${FAKE_KUBELET_DEFAULT_OWNER_SHAPE:-exact}" in
                  exact) package=kubelet ;;
                  fail) exit 1 ;;
                  other) package=unapproved ;;
                  duplicate)
                    printf 'kubelet: /etc/default/kubelet\n'
                    printf 'kubelet: /etc/default/kubelet\n'
                    exit 0
                    ;;
                  no-final-newline)
                    printf 'kubelet: /etc/default/kubelet'
                    exit 0
                    ;;
                  trailing-blank)
                    printf 'kubelet: /etc/default/kubelet\n\n'
                    exit 0
                    ;;
                  *) exit 64 ;;
                esac
                ;;
              *) exit 1 ;;
            esac
            [ "${FAKE_KUBELET_FOOTPRINT_OWNER_FAIL:-}" != "$2" ] || exit 1
            [ "${FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT:-}" != "$2" ] || package=unapproved
            [ "${FAKE_CLIENT_PACKAGE_OWNER_DRIFT:-}" != "$2" ] || package=unapproved
            if [ "${FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE_TARGET:-}" = "$2" ]; then
              case "${FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE:-exact}" in
                exact) ;;
                duplicate)
                  printf '%s: %s\n%s: %s\n' "$package" "$2" "$package" "$2"
                  exit 0
                  ;;
                trailing-blank)
                  printf '%s: %s\n\n' "$package" "$2"
                  exit 0
                  ;;
                extra)
                  printf '%s: %s\nunapproved: %s\n' "$package" "$2" "$2"
                  exit 0
                  ;;
                nonzero-output)
                  printf '%s: %s\n' "$package" "$2"
                  exit 1
                  ;;
                *) exit 64 ;;
              esac
            fi
            printf '%s: %s\n' "$package" "$2"
            ''',
        )
        self.write_executable(
            fake_bin / 'md5sum',
            '''
            #!/bin/sh
            [ "$#" = 1 ] && \
              [ "$1" = "$FAKE_HOST_ROOT/etc/default/kubelet" ] || exit 64
            [ "${FAKE_KUBELET_DEFAULT_MD5_FAIL:-0}" != 1 ] || exit 1
            digest=9ba5cd2e9a1e368fa51e13f1dd6a5ec1
            [ "${FAKE_KUBELET_DEFAULT_MD5_DRIFT:-0}" != 1 ] || \
              digest=00000000000000000000000000000000
            printf '%s  %s\n' "$digest" "$1"
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg',
            '''
            #!/bin/sh
            [ "$1" = --verify ] || exit 64
            case "$2" in kubeadm|kubectl) ;; *) exit 64 ;; esac
            [ "${FAKE_CLIENT_PACKAGE_VERIFY_DRIFT:-}" != "$2" ] || {
              printf '??5??????   /usr/bin/%s\n' "$2"
              exit 1
            }
            if [ "${FAKE_CLIENT_PACKAGE_VERIFY_DOC_EXCLUDES:-0}" = 1 ]; then
              printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
              printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'grep',
            '''
            #!/bin/sh
            if [ "${FAKE_DPKG_EXCLUDES_GREP_ERROR:-0}" = 1 ] &&
               [ "$1" = -Fxc ] &&
               [ "$2" = 'path-exclude=/usr/share/doc/*' ]; then
              printf '1\n'
              exit 2
            fi
            exec /usr/bin/grep "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'openssl',
            '''
            #!/bin/sh
            printf 'openssl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            printf '%s\n' "$FAKE_CANARY" >&2
            case " $* " in
              *' -checkend 0 '*) [ "${FAKE_CERT_EXPIRED:-0}" != 1 ]; exit ;;
            esac
            printf 'subject=CN = kube-apiserver\n'
            printf 'X509v3 Subject Alternative Name:\n    IP Address:192.0.2.10\n'
            printf 'notAfter=Aug 10 00:00:00 2027 GMT\n'
            ''',
        )
        stage_transcripts = {
            'kernel': (
                'PHASE=prepare-kernel\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\n'
                'REASON=kernel-ready\nEVIDENCE=NONE\nEXIT_CODE=0\n'
                'NEXT=30-install-containerd\nSHA256=NONE'
            ),
            'containerd': (
                'PHASE=containerd\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\n'
                'REASON=containerd-ready\nEVIDENCE=NONE\nEXIT_CODE=0\n'
                'NEXT=40-install-kubernetes\nSHA256=NONE'
            ),
            'kubernetes': (
                'PHASE=install-kubernetes\nMODE=CHECK\nRESULT=ALREADY_COMPLIANT\n'
                'REASON=kubernetes-packages-ready\nEVIDENCE=NONE\nEXIT_CODE=0\n'
                'NEXT=stages/50-kubeadm-init/run.sh --check\nSHA256=NONE'
            ),
        }
        for name, result_variable in (
            ('kernel', 'FAKE_KERNEL_GATE_FAIL'),
            ('containerd', 'FAKE_CONTAINERD_GATE_FAIL'),
            ('kubernetes', 'FAKE_KUBERNETES_GATE_FAIL'),
        ):
            output_variable = f'FAKE_{name.upper()}_GATE_OUTPUT'
            self.write_executable(
                gates / name,
                f'''#!/bin/sh
                printf '{name} %s\n' "$*" >>"$FAKE_COMMAND_LOG"
                printf '%s\n' "$FAKE_CANARY" >&2
                [ "${{{result_variable}:-0}}" != 1 ] || exit 1
                [ ! -f "$FAKE_DRIFT_DIR/{name}" ] || exit 1
                printf '%s\n' "${{{output_variable}}}"
                ''',
            )
        self.write_executable(
            gates / 'cidr',
            '''#!/bin/sh
            printf 'cidr %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            printf '%s\n' "$FAKE_CANARY" >&2
            [ "${FAKE_CIDR_GATE_FAIL:-0}" != 1 ] || exit 1
            [ ! -f "$FAKE_DRIFT_DIR/cidr" ] || exit 1
            [ ! -f "$FAKE_DRIFT_DIR/route" ] || exit 1
            if [ -n "${FAKE_KUBELET_DEFAULT_DRIFT_AFTER_CIDR_CALL:-}" ]; then
              calls_file="$FAKE_DRIFT_DIR/cidr-calls"
              calls=0
              [ ! -f "$calls_file" ] || IFS= read -r calls <"$calls_file"
              calls=$((calls + 1))
              printf '%s\n' "$calls" >"$calls_file"
              if [ "$calls" = "$FAKE_KUBELET_DEFAULT_DRIFT_AFTER_CIDR_CALL" ]; then
                printf 'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n' \
                  >"$FAKE_HOST_ROOT/etc/default/kubelet"
              fi
            fi
            printf 'RESULT=PASS_CIDRS\nREASON=no-server-local-overlap\nSCOPE=SERVER_LOCAL_SCOPE_ONLY\n'
            ''',
        )
        self.write_executable(
            host / 'usr/local/bin/crictl',
            '''#!/bin/sh
            printf 'crictl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            printf '%s\n' "$FAKE_CANARY" >&2
            [ "${FAKE_CRICTL_FAIL:-0}" != 1 ] || exit 1
            printf '%s\n' "$FAKE_CRICTL_JSON"
            ''',
        )
        self.write_executable(
            host / 'usr/bin/kubectl',
            '''#!/bin/sh
            printf 'kubectl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            printf '%s\n' "$FAKE_CANARY" >&2
            case " $* " in
              *' config view '*)
                printf '%s' "$FAKE_ADMIN_VIEW_JSON"
                exit 0
                ;;
            esac
            case " $* " in
              *' get daemonset kube-proxy '*) kind=daemonset ;;
              *' get pods '*) kind=pods ;;
              *' get configmap kube-proxy '*) kind=configmap ;;
              *) exit 64 ;;
            esac
            [ "${FAKE_KUBECTL_FAIL:-}" != "$kind" ] || exit 1
            if [ "${FAKE_ADMIN_CONF_SWAP:-0}" = 1 ] && [ "$kind" = daemonset ]; then
              printf 'swapped-during-query\n' >"$FAKE_HOST_ROOT/etc/kubernetes/admin.conf"
              chmod 0600 "$FAKE_HOST_ROOT/etc/kubernetes/admin.conf"
            fi
            case "$kind" in
              daemonset) printf '%s' "${FAKE_KUBE_PROXY_DAEMONSET:-}" ;;
              pods) printf '%s' "${FAKE_KUBE_PROXY_PODS:-}" ;;
              configmap) printf '%s' "${FAKE_KUBE_PROXY_CONFIGMAP:-}" ;;
            esac
            ''',
        )

        environment = self.sanitized_environment()
        component_json = (
            '{"containers":['
            '{"metadata":{"name":"kube-apiserver"},"state":"CONTAINER_RUNNING",'
            '"labels":{"io.kubernetes.pod.namespace":"kube-system"}},'
            '{"metadata":{"name":"kube-controller-manager"},"state":"CONTAINER_RUNNING",'
            '"labels":{"io.kubernetes.pod.namespace":"kube-system"}},'
            '{"metadata":{"name":"kube-scheduler"},"state":"CONTAINER_RUNNING",'
            '"labels":{"io.kubernetes.pod.namespace":"kube-system"}},'
            '{"metadata":{"name":"etcd"},"state":"CONTAINER_RUNNING",'
            '"labels":{"io.kubernetes.pod.namespace":"kube-system"}}]}'
        )
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_KERNEL_SCRIPT': str(gates / 'kernel'),
                'BOOTSTRAP_TEST_CONTAINERD_SCRIPT': str(gates / 'containerd'),
                'BOOTSTRAP_TEST_KUBERNETES_SCRIPT': str(gates / 'kubernetes'),
                'BOOTSTRAP_TEST_CIDR_SCRIPT': str(gates / 'cidr'),
                'BOOTSTRAP_TEST_CONFIG_FILE': str(config_source),
                'BOOTSTRAP_TEST_HOSTS_DIR': str(hosts_root),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_HOST_ROOT': str(host),
                'FAKE_CONFIG_SOURCE': str(config_source),
                'FAKE_APPROVED_KUBEADM': str(host / 'usr/bin/kubeadm'),
                'FAKE_DRIFT_DIR': str(drift_dir),
                'FAKE_CANARY': self.canary,
                # stage 50 采纳 capture_admin_conf 后会跑一次 `kubectl config view`，
                # 其输出要过 admin_conf_json_is_exact；载荷复用基类的同一份定义，
                # 不再另立一份手写 JSON。
                'FAKE_ADMIN_VIEW_JSON': json.dumps(self.admin_config_object()),
                'FAKE_LISTENER_MARKER': str(directory / 'listener-6443'),
                'FAKE_CRICTL_JSON': component_json,
                'FAKE_KERNEL_GATE_OUTPUT': stage_transcripts['kernel'],
                'FAKE_CONTAINERD_GATE_OUTPUT': stage_transcripts['containerd'],
                'FAKE_KUBERNETES_GATE_OUTPUT': stage_transcripts['kubernetes'],
            }
        )
        return environment, host, command_log

    def run_stage(
        self, environment: dict[str, str], mode: str = '--check'
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', str(KUBEADM_INIT), mode], env=environment
        )

    def test_cidr_gate_receives_device_tagged_entries_and_cni_devices(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_IP_ADDRESS'] = (
            '2: ens160 inet 192.0.2.10/24 scope global ens160\n'
            '28264: cilium_host inet 172.21.0.168/32 scope global cilium_host'
        )
        environment['FAKE_IP_ROUTES'] = (
            '192.0.2.0/24 dev ens160 src 192.0.2.10\n'
            '172.21.0.0/24 via 172.21.0.168 dev cilium_host proto kernel src 172.21.0.168'
        )

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        cidr_lines = [
            line for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('cidr ')
        ]
        self.assertTrue(cidr_lines)
        for line in cidr_lines:
            self.assertIn('--address 192.0.2.10/24@ens160', line)
            self.assertIn('--address 172.21.0.168/32@cilium_host', line)
            self.assertIn('--route 192.0.2.0/24@ens160', line)
            self.assertIn('--route 172.21.0.0/24@cilium_host', line)
            self.assertIn('--cni-device cilium_host', line)
            self.assertIn('--cni-device lxc*', line)

    def test_config_pin_and_host_values_come_from_host_directory(self) -> None:
        """CONFIG digest 与主机值必须来自 host 目录，而不是脚本字面量。"""
        environment, _, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        pins = hosts_root / 'example-node' / 'pins.sha256'
        pins.write_text(
            pins.read_text(encoding='utf-8').replace('2f5aa82a', '00000000', 1),
            encoding='utf-8',
        )

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 10, result.stdout)
        self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
        self.assertIn('REASON=kubeadm-config-contract-drift', result.stdout)

    def test_pins_shape_drift_is_fail_closed(self) -> None:
        for name, mutate in (
            ('reversed', lambda t: ''.join(reversed(t.splitlines(keepends=True)))),
            ('third-line', lambda t: t + 'x\n'),
            ('no-newline', lambda t: t.rstrip('\n')),
        ):
            with self.subTest(case=name):
                environment, _, _ = self.make_environment()
                pins = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR']) / 'example-node/pins.sha256'
                pins.write_text(mutate(pins.read_text(encoding='utf-8')), encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 20, result.stdout)
                self.assertIn('REASON=host-pins-invalid', result.stdout)

    def test_registered_second_host_flows_through_kubeadm_check(self) -> None:
        environment, host, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        host_dir = self.write_fixture_host(
            hosts_root, name='fixture-host-b', node_ip='10.200.0.2',
            cluster_name='fixture-b', pod_cidr='10.244.0.0/16',
            service_cidr='10.96.0.0/12', swap_file='/swap-b.img',
            swap_min=3000000000, swap_max=3400000000,
        )
        (host / 'swap-b.img').write_bytes(b'preserve swap\n')
        environment['FAKE_HOSTNAME'] = 'fixture-host-b'
        environment['FAKE_NODE_IP'] = '10.200.0.2'
        environment['FAKE_SWAP_OUTPUT'] = '/swap-b.img 3221225472'
        environment['BOOTSTRAP_TEST_CONFIG_FILE'] = str(host_dir / 'kubeadm-init.yaml')

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)

    def test_exact_initialized_state_is_already_compliant_and_zero_write(self) -> None:
        environment, host, command_log = self.make_environment()
        applied = self.run_stage(environment, '--apply')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        before = self.tree_snapshot(host)
        command_log.write_text('', encoding='utf-8')

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', checked.stdout)
        self.assertIn('REASON=control-plane-initialized', checked.stdout)
        self.assertEqual(self.tree_snapshot(host), before)
        self.assertNotIn('kubeadm init', command_log.read_text(encoding='utf-8'))

    def test_check_tolerates_post_cni_workload_containers_when_initialized(self) -> None:
        """装完 Cilium 后 crictl ps 里多了 cilium-agent/operator/envoy 与 coredns（真机 9 个）；
        resume 判定只要求 4 个控制面容器各恰好一个且 Running 于 kube-system。"""
        environment, host, command_log = self.make_environment()
        self.assertEqual(self.run_stage(environment, '--apply').returncode, 0)
        payload = json.loads(environment['FAKE_CRICTL_JSON'])
        for name in ('coredns', 'coredns', 'cilium-envoy', 'cilium-operator', 'cilium-agent'):
            payload['containers'].insert(0, {
                'metadata': {'name': name}, 'state': 'CONTAINER_RUNNING',
                'labels': {'io.kubernetes.pod.namespace': 'kube-system'},
            })
        environment['FAKE_CRICTL_JSON'] = json.dumps(payload)
        command_log.write_text('', encoding='utf-8')

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', checked.stdout)
        self.assertNotIn('kubeadm init', command_log.read_text(encoding='utf-8'))

    def test_check_still_requires_each_control_plane_container_exactly_once(self) -> None:
        for drift in ('missing-etcd', 'duplicate-apiserver', 'apiserver-outside-kube-system', 'apiserver-not-running'):
            with self.subTest(drift=drift):
                environment, _, _ = self.make_environment()
                self.assertEqual(self.run_stage(environment, '--apply').returncode, 0)
                payload = json.loads(environment['FAKE_CRICTL_JSON'])
                containers = payload['containers']
                # 同时带上真机的 5 个额外容器，确保豁免不会掩盖控制面漂移。
                for name in ('coredns', 'cilium-envoy', 'cilium-operator', 'cilium-agent'):
                    containers.append({
                        'metadata': {'name': name}, 'state': 'CONTAINER_RUNNING',
                        'labels': {'io.kubernetes.pod.namespace': 'kube-system'},
                    })
                apiserver = next(c for c in containers if c['metadata']['name'] == 'kube-apiserver')
                if drift == 'missing-etcd':
                    containers[:] = [c for c in containers if c['metadata']['name'] != 'etcd']
                elif drift == 'duplicate-apiserver':
                    containers.append(json.loads(json.dumps(apiserver)))
                elif drift == 'apiserver-outside-kube-system':
                    apiserver['labels']['io.kubernetes.pod.namespace'] = 'default'
                else:
                    apiserver['state'] = 'CONTAINER_EXITED'
                environment['FAKE_CRICTL_JSON'] = json.dumps(payload)

                checked = self.run_stage(environment, '--check')

                self.assertEqual(checked.returncode, 30, checked.stdout)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', checked.stdout)
                self.assertIn('REASON=control-plane-runtime-set-drift', checked.stdout)

    def test_post_init_verification_still_requires_exactly_the_control_plane(self) -> None:
        """刚 init 完的即时校验保持强断言：除 4 个控制面容器外不得有其他 Running 容器。"""
        environment, _, _ = self.make_environment()
        payload = json.loads(environment['FAKE_CRICTL_JSON'])
        payload['containers'].append({
            'metadata': {'name': 'unexpected'}, 'state': 'CONTAINER_RUNNING',
            'labels': {'io.kubernetes.pod.namespace': 'kube-system'},
        })
        environment['FAKE_CRICTL_JSON'] = json.dumps(payload)

        applied = self.run_stage(environment, '--apply')

        self.assertEqual(applied.returncode, 50, applied.stdout)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', applied.stdout)
        self.assertIn('REASON=control-plane-runtime-set-drift', applied.stdout)

    def test_apply_on_exact_initialized_state_never_reinitializes(self) -> None:
        environment, _, command_log = self.make_environment()
        self.assertEqual(self.run_stage(environment, '--apply').returncode, 0)
        command_log.write_text('', encoding='utf-8')

        repeated = self.run_stage(environment, '--apply')

        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', repeated.stdout)
        self.assertNotIn('kubeadm init', command_log.read_text(encoding='utf-8'))

    def test_accepts_exact_official_kubelet_package_footprint(self) -> None:
        environment, host, command_log = self.make_environment()
        self.seed_official_kubelet_package_footprint(host)
        before = self.tree_snapshot(host)

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', checked.stdout)
        self.assertEqual(self.tree_snapshot(host), before)

        environment['FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES'] = '1'
        applied = self.run_stage(environment, '--apply')

        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_INITIALIZED', applied.stdout)
        self.assertTrue(
            (host / 'etc/kubernetes/manifests/.kubelet-keep').is_file()
        )
        self.assertIn(
            'kubeadm init --config ', command_log.read_text(encoding='utf-8')
        )

    def test_accepts_exact_official_kubelet_state_footprint(self) -> None:
        environment, host, command_log = self.make_environment()
        self.seed_official_kubelet_package_footprint(host)
        self.seed_official_kubelet_state_footprint(host)
        before = self.tree_snapshot(host)

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', checked.stdout)
        self.assertEqual(self.tree_snapshot(host), before)

        environment['FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES'] = '1'
        applied = self.run_stage(environment, '--apply')

        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_INITIALIZED', applied.stdout)
        self.assertTrue((host / 'var/lib/kubelet/.kubelet-keep').is_file())
        self.assertIn(
            'kubeadm init --config ', command_log.read_text(encoding='utf-8')
        )

    def test_accepts_exact_official_kubelet_default_conffile(self) -> None:
        environment, host, command_log = self.make_environment()
        self.seed_official_kubelet_package_footprint(host)
        self.seed_official_kubelet_state_footprint(host)
        default_file = self.seed_official_kubelet_default_conffile(host)
        before = self.tree_snapshot(host)

        checked = self.run_stage(environment, '--check')

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', checked.stdout)
        self.assertEqual(self.tree_snapshot(host), before)
        commands_after_check = command_log.read_text(encoding='utf-8')
        self.assertNotIn('kubeadm ', commands_after_check)

        environment['FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES'] = '1'
        applied = self.run_stage(environment, '--apply')

        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_INITIALIZED', applied.stdout)
        commands_after_apply = command_log.read_text(encoding='utf-8')
        kubeadm_commands = [
            line for line in commands_after_apply.splitlines()
            if line.startswith('kubeadm ')
        ]
        self.assertEqual(len(kubeadm_commands), 3)
        snapshots = [line.rsplit(' ', 1)[1] for line in kubeadm_commands]
        self.assertEqual(len(set(snapshots)), 1)
        config = snapshots[0]
        self.assertEqual(
            kubeadm_commands,
            [
                f'kubeadm config validate --config {config}',
                f'kubeadm init phase preflight --config {config}',
                f'kubeadm init --config {config}',
            ],
        )
        self.assertEqual(
            self.tree_snapshot(host)['etc/default/kubelet'],
            before['etc/default/kubelet'],
        )

    def test_rejects_official_kubelet_default_conffile_drift(self) -> None:
        cases = (
            ('directory', {}),
            ('symlink', {}),
            ('mode', {}),
            ('owner', {'FAKE_STAT_OWNER_DRIFT': 'TARGET'}),
            ('size', {}),
            ('bytes', {}),
            ('no-final-newline', {}),
            ('trailing-blank', {}),
            (
                'ownership-query-fail',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'fail'},
            ),
            (
                'ownership-other',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'other'},
            ),
            (
                'ownership-duplicate',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'duplicate'},
            ),
            (
                'ownership-no-final-newline',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'no-final-newline'},
            ),
            (
                'ownership-trailing-blank',
                {'FAKE_KUBELET_DEFAULT_OWNER_SHAPE': 'trailing-blank'},
            ),
            (
                'conffile-query-fail',
                {'FAKE_KUBELET_CONFFILES_QUERY_FAIL': '1'},
            ),
            (
                'conffile-missing',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'missing'},
            ),
            (
                'conffile-duplicate',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'duplicate'},
            ),
            (
                'conffile-malformed',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'malformed'},
            ),
            (
                'conffile-digest',
                {'FAKE_KUBELET_CONFFILES_SHAPE': 'digest-drift'},
            ),
            ('md5-command-fail', {'FAKE_KUBELET_DEFAULT_MD5_FAIL': '1'}),
            ('md5-drift', {'FAKE_KUBELET_DEFAULT_MD5_DRIFT': '1'}),
            (
                'mode-command-output-then-fail',
                {'FAKE_KUBELET_DEFAULT_MODE_OUTPUT_FAIL': '1'},
            ),
            (
                'content-command-output-then-fail',
                {'FAKE_KUBELET_DEFAULT_CONTENT_OUTPUT_FAIL': '1'},
            ),
            (
                'size-command-output-then-fail',
                {'FAKE_KUBELET_DEFAULT_SIZE_OUTPUT_FAIL_ON_CALL': '2'},
            ),
            (
                'sha256-command-fail',
                {'FAKE_KUBELET_DEFAULT_SHA256_FAIL': '1'},
            ),
            (
                'sha256-drift',
                {'FAKE_KUBELET_DEFAULT_SHA256_DRIFT': '1'},
            ),
            (
                'sha256-command-output-then-fail',
                {'FAKE_KUBELET_DEFAULT_SHA256_OUTPUT_FAIL_ON_CALL': '2'},
            ),
        )
        content_mutations = {
            'size': b'x',
            'bytes': b'XUBELET_EXTRA_ARGS=\n',
            'no-final-newline': b'KUBELET_EXTRA_ARGS=',
            'trailing-blank': b'KUBELET_EXTRA_ARGS=\n\n',
        }

        for drift, overrides in cases:
            with self.subTest(drift=drift):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                self.seed_official_kubelet_state_footprint(host)
                default_file = self.seed_official_kubelet_default_conffile(host)

                baseline = self.run_stage(environment, '--check')
                self.assertEqual(baseline.returncode, 0, baseline.stderr)
                command_log.write_text('', encoding='utf-8')

                environment.update(
                    {
                        key: str(default_file) if value == 'TARGET' else value
                        for key, value in overrides.items()
                    }
                )
                if drift == 'directory':
                    default_file.unlink()
                    default_file.mkdir()
                elif drift == 'symlink':
                    outside = host.parent / 'outside-default-kubelet'
                    outside.write_bytes(b'KUBELET_EXTRA_ARGS=\n')
                    outside.chmod(0o644)
                    default_file.unlink()
                    default_file.symlink_to(outside)
                elif drift == 'mode':
                    default_file.chmod(0o666)
                elif drift in content_mutations:
                    default_file.write_bytes(content_mutations[drift])
                before = self.tree_snapshot(default_file.parent)

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                self.assertIn(
                    'REASON=kubelet-operator-override-present', result.stdout
                )
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn('kubeadm init --config ', commands)
                self.assertEqual(self.tree_snapshot(default_file.parent), before)
                self.assertFalse(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '12-kubeadm-*.txt'
                        )
                    )
                )

    def test_regates_official_kubelet_default_conffile_before_init(
        self,
    ) -> None:
        baseline_environment, baseline_host, _ = self.make_environment()
        self.seed_official_kubelet_package_footprint(baseline_host)
        self.seed_official_kubelet_state_footprint(baseline_host)
        self.seed_official_kubelet_default_conffile(baseline_host)
        baseline = self.run_stage(baseline_environment, '--check')
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

        for seam in ('validate', 'preflight', 'cidr'):
            with self.subTest(seam=seam):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                self.seed_official_kubelet_state_footprint(host)
                self.seed_official_kubelet_default_conffile(host)
                if seam == 'cidr':
                    environment[
                        'FAKE_KUBELET_DEFAULT_DRIFT_AFTER_CIDR_CALL'
                    ] = '3'
                else:
                    environment[f'FAKE_DRIFT_AFTER_{seam.upper()}'] = (
                        'kubelet-default-conffile'
                    )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                self.assertIn(
                    'REASON=kubelet-operator-override-present', result.stdout
                )
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn('kubeadm config validate --config ', commands)
                if seam == 'validate':
                    self.assertNotIn(
                        'kubeadm init phase preflight --config ', commands
                    )
                else:
                    self.assertIn(
                        'kubeadm init phase preflight --config ', commands
                    )
                self.assertNotIn('kubeadm init --config ', commands)
                self.assertEqual(
                    (host / 'etc/default/kubelet').read_bytes(),
                    b'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n',
                )
                self.assertFalse(
                    list(
                        (host / 'root/dev-infra-evidence').glob(
                            '12-kubeadm-*.txt'
                        )
                    )
                )

    def test_rejects_official_kubelet_state_footprint_drift(self) -> None:
        baseline_environment, baseline_host, _ = self.make_environment()
        self.seed_official_kubelet_package_footprint(baseline_host)
        self.seed_official_kubelet_state_footprint(baseline_host)
        baseline = self.run_stage(baseline_environment, '--check')
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

        cases = (
            'extra-entry',
            'root-mode',
            'root-filesystem-owner',
            'root-package-owner',
            'root-package-query',
            'root-symlink',
            'keep-mode',
            'keep-bytes',
            'keep-filesystem-owner',
            'keep-package-owner',
            'keep-package-query',
            'keep-sha256-drift',
            'keep-sha256-fail',
            'keep-symlink',
        )
        shaped_cases = (
            ('root-owner-shape', '/var/lib/kubelet'),
            ('keep-owner-shape', '/var/lib/kubelet/.kubelet-keep'),
        )

        scenarios = [(case, None, None) for case in cases]
        for case, logical in shaped_cases:
            for shape in ('duplicate', 'trailing-blank', 'extra', 'nonzero-output'):
                scenarios.append((case, logical, shape))

        for case, logical, shape in scenarios:
            with self.subTest(case=case, shape=shape):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                self.seed_official_kubelet_state_footprint(host)
                kubelet_root = host / 'var/lib/kubelet'
                keep = kubelet_root / '.kubelet-keep'

                if case == 'extra-entry':
                    (kubelet_root / 'unknown-state').write_text(
                        'unknown\n', encoding='utf-8'
                    )
                elif case == 'root-mode':
                    kubelet_root.chmod(0o755)
                elif case == 'root-filesystem-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(kubelet_root)
                elif case == 'root-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/var/lib/kubelet'
                    )
                elif case == 'root-package-query':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_FAIL'] = (
                        '/var/lib/kubelet'
                    )
                elif case == 'root-symlink':
                    target = host / 'outside-kubelet-state'
                    kubelet_root.rename(target)
                    kubelet_root.symlink_to(target, target_is_directory=True)
                elif case == 'keep-mode':
                    keep.chmod(0o600)
                elif case == 'keep-bytes':
                    keep.write_bytes(b'drift\n')
                elif case == 'keep-filesystem-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(keep)
                elif case == 'keep-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/var/lib/kubelet/.kubelet-keep'
                    )
                elif case == 'keep-package-query':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_FAIL'] = (
                        '/var/lib/kubelet/.kubelet-keep'
                    )
                elif case == 'keep-sha256-drift':
                    environment['FAKE_KUBELET_KEEP_SHA256_TARGET'] = str(keep)
                    environment['FAKE_KUBELET_KEEP_SHA256_DRIFT'] = '1'
                elif case == 'keep-sha256-fail':
                    environment['FAKE_KUBELET_KEEP_SHA256_TARGET'] = str(keep)
                    environment['FAKE_KUBELET_KEEP_SHA256_FAIL'] = '1'
                elif case == 'keep-symlink':
                    target = host / 'outside-kubelet-state-keep'
                    target.write_bytes(b'')
                    keep.unlink()
                    keep.symlink_to(target)
                else:
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE_TARGET'] = (
                        logical
                    )
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE'] = shape

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn('kubeadm init --config ', commands)

    def test_regates_official_kubelet_state_footprint_before_init(self) -> None:
        baseline_environment, baseline_host, _ = self.make_environment()
        self.seed_official_kubelet_package_footprint(baseline_host)
        self.seed_official_kubelet_state_footprint(baseline_host)
        baseline = self.run_stage(baseline_environment, '--check')
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

        for seam in ('validate', 'preflight'):
            with self.subTest(seam=seam):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                self.seed_official_kubelet_state_footprint(host)
                environment[f'FAKE_DRIFT_AFTER_{seam.upper()}'] = (
                    'kubelet-package-footprint'
                )

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                self.assertNotIn(
                    'kubeadm init --config ',
                    command_log.read_text(encoding='utf-8'),
                )

    def test_rejects_official_kubelet_package_footprint_drift(self) -> None:
        cases = (
            'extra-root-entry',
            'extra-manifest-entry',
            'root-mode',
            'manifest-mode',
            'keep-mode',
            'keep-bytes',
            'root-filesystem-owner',
            'root-package-owner',
            'manifest-package-owner',
            'keep-filesystem-owner',
            'keep-package-owner-query',
            'root-symlink',
            'manifest-symlink',
            'keep-symlink',
            'listener',
        )
        for case in cases:
            with self.subTest(case=case):
                baseline_environment, baseline_host, _ = self.make_environment()
                self.seed_official_kubelet_package_footprint(baseline_host)
                baseline = self.run_stage(baseline_environment, '--check')
                self.assertEqual(baseline.returncode, 0, baseline.stderr)

                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                kubernetes_root = host / 'etc/kubernetes'
                manifests = kubernetes_root / 'manifests'
                keep = manifests / '.kubelet-keep'
                if case == 'extra-root-entry':
                    (kubernetes_root / 'pki').mkdir()
                elif case == 'extra-manifest-entry':
                    (manifests / 'unknown.yaml').write_text(
                        'unknown\n', encoding='utf-8'
                    )
                elif case == 'root-mode':
                    kubernetes_root.chmod(0o755)
                elif case == 'manifest-mode':
                    manifests.chmod(0o755)
                elif case == 'keep-mode':
                    keep.chmod(0o600)
                elif case == 'keep-bytes':
                    keep.write_bytes(b'drift\n')
                elif case == 'root-filesystem-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(kubernetes_root)
                elif case == 'root-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/etc/kubernetes'
                    )
                elif case == 'manifest-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/etc/kubernetes/manifests'
                    )
                elif case == 'keep-filesystem-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(keep)
                elif case == 'keep-package-owner-query':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_FAIL'] = (
                        '/etc/kubernetes/manifests/.kubelet-keep'
                    )
                elif case == 'root-symlink':
                    target = host / 'outside-kubernetes'
                    kubernetes_root.rename(target)
                    kubernetes_root.symlink_to(target, target_is_directory=True)
                elif case == 'manifest-symlink':
                    target = host / 'outside-manifests'
                    manifests.rename(target)
                    manifests.symlink_to(target, target_is_directory=True)
                elif case == 'keep-symlink':
                    target = host / 'outside-keep'
                    target.write_bytes(b'')
                    keep.unlink()
                    keep.symlink_to(target)
                else:
                    environment['FAKE_6443_LISTENER'] = '1'

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn(
                    'kubeadm init --config ',
                    commands,
                )

    def test_rejects_malformed_kubelet_package_ownership_output(self) -> None:
        for shape in ('duplicate', 'trailing-blank', 'extra', 'nonzero-output'):
            with self.subTest(shape=shape):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                environment['FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE_TARGET'] = (
                    '/etc/kubernetes/manifests'
                )
                environment['FAKE_KUBELET_FOOTPRINT_OWNER_SHAPE'] = shape

                result = self.run_stage(environment, '--check')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                commands = (
                    command_log.read_text(encoding='utf-8')
                    if command_log.exists()
                    else ''
                )
                self.assertNotIn('kubeadm init --config ', commands)

    def test_rejects_kubelet_package_placeholder_digest_drift(self) -> None:
        for state in ('fresh', 'initialized'):
            for behavior in ('drift', 'fail'):
                with self.subTest(state=state, behavior=behavior):
                    environment, host, command_log = self.make_environment()
                    self.seed_official_kubelet_package_footprint(host)
                    if state == 'initialized':
                        environment['FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES'] = (
                            '1'
                        )
                        applied = self.run_stage(environment, '--apply')
                        self.assertEqual(applied.returncode, 0, applied.stderr)
                        command_log.write_text('', encoding='utf-8')
                    environment[f'FAKE_KUBELET_KEEP_SHA256_{behavior.upper()}'] = (
                        '1'
                    )

                    checked = self.run_stage(environment, '--check')

                    self.assertEqual(checked.returncode, 30, checked.stderr)
                    expected_result = (
                        'STOP_ALREADY_INITIALIZED'
                        if state == 'fresh'
                        else 'STOP_UNKNOWN_STATE'
                    )
                    self.assertIn(f'RESULT={expected_result}', checked.stdout)
                    commands = (
                        command_log.read_text(encoding='utf-8')
                        if command_log.exists()
                        else ''
                    )
                    self.assertNotIn('kubeadm init --config ', commands)

    def test_regates_official_kubelet_package_footprint_before_init(self) -> None:
        baseline_environment, baseline_host, _ = self.make_environment()
        self.seed_official_kubelet_package_footprint(baseline_host)
        baseline = self.run_stage(baseline_environment, '--check')
        self.assertEqual(baseline.returncode, 0, baseline.stderr)

        environment, host, command_log = self.make_environment()
        self.seed_official_kubelet_package_footprint(host)
        environment['FAKE_PREINIT_RACE'] = 'manifest'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertNotIn(
            'kubeadm init --config ', command_log.read_text(encoding='utf-8')
        )

    def test_initialized_state_accepts_only_exact_package_placeholder(
        self,
    ) -> None:
        cases = (
            'exact',
            'absent',
            'unknown-fifth-entry',
            'unknown-sixth-entry',
            'keep-bytes',
            'keep-mode',
            'keep-symlink',
            'keep-package-owner',
            'root-package-owner',
            'manifest-package-owner',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                self.seed_official_kubelet_package_footprint(host)
                environment['FAKE_PRESERVE_PACKAGE_DIRECTORY_MODES'] = '1'
                applied = self.run_stage(environment, '--apply')
                self.assertEqual(applied.returncode, 0, applied.stderr)
                command_log.write_text('', encoding='utf-8')

                manifests = host / 'etc/kubernetes/manifests'
                keep = manifests / '.kubelet-keep'
                if case == 'absent':
                    keep.unlink()
                elif case == 'unknown-fifth-entry':
                    keep.unlink()
                    (manifests / 'unknown.yaml').write_text(
                        'unknown\n', encoding='utf-8'
                    )
                elif case == 'unknown-sixth-entry':
                    (manifests / 'unknown.yaml').write_text(
                        'unknown\n', encoding='utf-8'
                    )
                elif case == 'keep-bytes':
                    keep.write_bytes(b'drift\n')
                elif case == 'keep-mode':
                    keep.chmod(0o600)
                elif case == 'keep-symlink':
                    target = host / 'outside-initialized-keep'
                    target.write_bytes(b'')
                    keep.unlink()
                    keep.symlink_to(target)
                elif case == 'keep-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/etc/kubernetes/manifests/.kubelet-keep'
                    )
                elif case == 'root-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/etc/kubernetes'
                    )
                elif case == 'manifest-package-owner':
                    environment['FAKE_KUBELET_FOOTPRINT_OWNER_DRIFT'] = (
                        '/etc/kubernetes/manifests'
                    )

                checked = self.run_stage(environment, '--check')

                if case in ('exact', 'absent'):
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    self.assertIn('RESULT=ALREADY_COMPLIANT', checked.stdout)
                elif case == 'root-package-owner':
                    self.assertEqual(checked.returncode, 30, checked.stderr)
                    self.assertIn(
                        'RESULT=STOP_ALREADY_INITIALIZED', checked.stdout
                    )
                else:
                    self.assertEqual(checked.returncode, 30, checked.stderr)
                    self.assertIn('RESULT=STOP_UNKNOWN_STATE', checked.stdout)
                self.assertNotIn(
                    'kubeadm init', command_log.read_text(encoding='utf-8')
                )

    def test_initialized_marker_live_symlinks_are_untrusted_footprint(self) -> None:
        for case in ('admin-conf', 'manifests', 'etcd-member'):
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                applied = self.run_stage(environment, '--apply')
                self.assertEqual(applied.returncode, 0, applied.stderr)
                marker = {
                    'admin-conf': host / 'etc/kubernetes/admin.conf',
                    'manifests': host / 'etc/kubernetes/manifests',
                    'etcd-member': host / 'var/lib/etcd/member',
                }[case]
                outside = host.parent / f'outside-{case}'
                marker.rename(outside)
                marker.symlink_to(
                    outside, target_is_directory=case != 'admin-conf'
                )
                evidence_dir = host / 'root/dev-infra-evidence'
                evidence_before = sorted(evidence_dir.iterdir())
                command_log.write_text('', encoding='utf-8')

                checked = self.run_stage(environment, '--check')

                self.assertEqual(checked.returncode, 30, checked.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', checked.stdout)
                self.assertNotIn('RESULT=ALREADY_COMPLIANT', checked.stdout)
                self.assertEqual(sorted(evidence_dir.iterdir()), evidence_before)
                self.assertEqual(command_log.read_text(encoding='utf-8'), '')

    def test_initialized_candidate_drift_stops_unknown(self) -> None:
        for case in (
            'listener', 'listener-query', 'manifest', 'manifest-dir-mode',
            'manifest-dir-owner', 'runtime', 'kube-proxy'
        ):
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                applied = self.run_stage(environment, '--apply')
                self.assertEqual(applied.returncode, 0, applied.stderr)
                command_log.write_text('', encoding='utf-8')
                if case == 'listener':
                    Path(environment['FAKE_LISTENER_MARKER']).unlink()
                elif case == 'listener-query':
                    environment['FAKE_SS_FAIL'] = '1'
                elif case == 'manifest':
                    unknown = host / 'etc/kubernetes/manifests/unknown.yaml'
                    unknown.write_text('unknown\n', encoding='utf-8')
                    unknown.chmod(0o600)
                elif case == 'manifest-dir-mode':
                    (host / 'etc/kubernetes/manifests').chmod(0o755)
                elif case == 'manifest-dir-owner':
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(
                        host / 'etc/kubernetes/manifests'
                    )
                elif case == 'runtime':
                    payload = json.loads(environment['FAKE_CRICTL_JSON'])
                    payload['containers'].pop()
                    environment['FAKE_CRICTL_JSON'] = json.dumps(payload)
                else:
                    environment['FAKE_KUBE_PROXY_DAEMONSET'] = (
                        'daemonset.apps/kube-proxy\n'
                    )

                checked = self.run_stage(environment, '--check')

                self.assertEqual(checked.returncode, 30, checked.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', checked.stdout)
                self.assertNotIn('PASS_KUBEADM_CHECK', checked.stdout)
                self.assertNotIn(
                    'kubeadm init', command_log.read_text(encoding='utf-8')
                )

    def test_check_rejects_every_initialized_or_partial_marker_before_gates(self) -> None:
        cases = (
            'admin', 'apiserver', 'controller-manager', 'scheduler',
            'static-broken-symlink', 'etcd', 'listener',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                if case == 'admin':
                    target = host / 'etc/kubernetes/admin.conf'
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        'existing\n', encoding='utf-8'
                    )
                elif case == 'apiserver':
                    target = host / 'etc/kubernetes/manifests/kube-apiserver.yaml'
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        'existing\n', encoding='utf-8'
                    )
                elif case == 'controller-manager':
                    target = host / 'etc/kubernetes/manifests/kube-controller-manager.yaml'
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        'existing\n', encoding='utf-8'
                    )
                elif case == 'scheduler':
                    target = host / 'etc/kubernetes/manifests/kube-scheduler.yaml'
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        'existing\n', encoding='utf-8'
                    )
                elif case == 'static-broken-symlink':
                    target = host / 'etc/kubernetes/manifests/unknown.yaml'
                    target.parent.mkdir(parents=True)
                    target.symlink_to('/missing')
                elif case == 'etcd':
                    (host / 'var/lib/etcd/member').mkdir(parents=True)
                else:
                    environment['FAKE_6443_LISTENER'] = '1'

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                if command_log.exists():
                    self.assertNotIn(
                        'kubeadm ', command_log.read_text(encoding='utf-8')
                    )

    def test_check_rejects_non_pristine_kubelet_pre_init_inputs(self) -> None:
        for case in (
            'kubeadm-flags', 'config', 'instance-config', 'pki',
            'root-symlink', 'default-content',
            'unknown-file', 'unknown-dir', 'unknown-broken-symlink',
        ):
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                kubelet_root = host / 'var/lib/kubelet'
                if case == 'root-symlink':
                    outside = host.parent / 'outside-kubelet-root'
                    outside.mkdir()
                    kubelet_root.parent.mkdir(parents=True, exist_ok=True)
                    kubelet_root.symlink_to(outside, target_is_directory=True)
                elif case == 'default-content':
                    target = host / 'etc/default/kubelet'
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        'KUBELET_EXTRA_ARGS=--config=/tmp/evil\n',
                        encoding='utf-8',
                    )
                    target.chmod(0o644)
                else:
                    kubelet_root.mkdir(parents=True)
                    target = {
                        'kubeadm-flags': kubelet_root / 'kubeadm-flags.env',
                        'config': kubelet_root / 'config.yaml',
                        'instance-config': kubelet_root / 'instance-config.yaml',
                        'pki': kubelet_root / 'pki',
                        'unknown-file': kubelet_root / 'unknown-state',
                        'unknown-dir': kubelet_root / 'plugins',
                        'unknown-broken-symlink': kubelet_root / 'unknown-link',
                    }[case]
                    if case in ('pki', 'unknown-dir'):
                        target.mkdir()
                    elif case == 'unknown-broken-symlink':
                        target.symlink_to('/missing')
                    else:
                        target.write_text('stale\n', encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                if command_log.exists():
                    self.assertNotIn(
                        'kubeadm ', command_log.read_text(encoding='utf-8')
                    )

    def test_check_allows_secure_kubelet_root_and_empty_operator_file(self) -> None:
        environment, host, command_log = self.make_environment()
        kubelet_root = host / 'var/lib/kubelet'
        kubelet_root.mkdir(parents=True)
        kubelet_root.chmod(0o700)
        default_file = host / 'etc/default/kubelet'
        default_file.parent.mkdir(parents=True, exist_ok=True)
        default_file.touch(mode=0o644)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)
        self.assertNotIn(
            'kubeadm ', command_log.read_text(encoding='utf-8')
        )

    def test_check_accepts_canonical_ubuntu_os_release_symlink(self) -> None:
        """捕获 Stage 50 误拒绝 Ubuntu 标准 os-release 符号链接。"""
        environment, host, command_log = self.make_environment()
        canonical = host / 'usr/lib/os-release'
        canonical.parent.mkdir(parents=True)
        (host / 'etc/os-release').replace(canonical)
        (host / 'etc/os-release').symlink_to('../usr/lib/os-release')

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)
        self.assertNotIn(
            'kubeadm ', command_log.read_text(encoding='utf-8')
        )

    def test_check_declares_readlink_dependency(self) -> None:
        """共享 os-release resolver 的命令依赖必须在 Stage 50 前置声明。"""
        required_commands = next(
            line for line in KUBEADM_INIT.read_text(encoding='utf-8').splitlines()
            if line.startswith('for required_command in ')
        )

        self.assertIn('readlink', required_commands.split())

    def test_check_accepts_declared_client_doc_exclusions(self) -> None:
        """捕获 Stage 50 把官方 dpkg 文档排除输出误判为 payload 漂移。"""
        environment, host, command_log = self.make_environment()
        excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
        excludes.parent.mkdir(parents=True)
        excludes.write_text(
            'path-exclude=/usr/share/man/*\n'
            'path-exclude=/usr/share/doc/*\n'
            'path-include=/usr/share/doc/*/copyright\n'
            'path-include=/usr/share/doc/*/changelog.*\n',
            encoding='utf-8',
        )
        excludes.chmod(0o644)
        environment['FAKE_CLIENT_PACKAGE_VERIFY_DOC_EXCLUDES'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)
        self.assertNotIn(
            'kubeadm ', command_log.read_text(encoding='utf-8')
        )

    def test_check_rejects_dpkg_excludes_grep_error(self) -> None:
        """grep 输出合法计数但读取失败时仍必须 fail closed。"""
        environment, host, _ = self.make_environment()
        excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
        excludes.parent.mkdir(parents=True)
        excludes.write_text(
            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
        )
        excludes.chmod(0o644)
        environment['FAKE_CLIENT_PACKAGE_VERIFY_DOC_EXCLUDES'] = '1'
        environment['FAKE_DPKG_EXCLUDES_GREP_ERROR'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertIn(
            'REASON=kubernetes-client-package-content-drift', result.stdout
        )

    def test_check_rejects_client_provenance_or_usr_sbin_shadow(self) -> None:
        cases = (
            ('kubeadm', 'shadow'), ('kubectl', 'shadow'),
            ('kubeadm', 'mode'), ('kubeadm', 'owner'),
            ('kubeadm', 'symlink'), ('kubeadm', 'package-owner'),
            ('kubeadm', 'package-verify'), ('kubectl', 'package-verify'),
        )
        for binary_name, drift in cases:
            with self.subTest(binary=binary_name, drift=drift):
                environment, host, _ = self.make_environment()
                if drift == 'shadow':
                    target = host / 'usr/sbin' / binary_name
                    target.write_text('unapproved-shadow\n', encoding='utf-8')
                    target.chmod(0o755)
                else:
                    target = host / 'usr/bin' / binary_name
                    if drift == 'mode':
                        target.chmod(0o777)
                    elif drift == 'owner':
                        environment['FAKE_STAT_OWNER_DRIFT'] = str(target)
                    elif drift == 'symlink':
                        outside = host.parent / f'outside-{binary_name}'
                        outside.write_text('unapproved\n', encoding='utf-8')
                        outside.chmod(0o755)
                        target.unlink()
                        target.symlink_to(outside)
                    elif drift == 'package-owner':
                        environment['FAKE_CLIENT_PACKAGE_OWNER_DRIFT'] = (
                            f'/usr/bin/{binary_name}'
                        )
                    else:
                        environment['FAKE_CLIENT_PACKAGE_VERIFY_DRIFT'] = (
                            binary_name
                        )

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)

    def test_apply_uses_absolute_approved_kubeadm_not_path_shadow(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_PATH_KUBEADM_SHADOW'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_INITIALIZED', result.stdout)
        self.assertNotIn(
            'shadow-kubeadm invoked', command_log.read_text(encoding='utf-8')
        )

    def test_check_reruns_all_prior_gates_without_kubeadm_or_writes(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        for gate in ('kernel --check', 'containerd --check', 'kubernetes --check'):
            self.assertIn(gate, commands)
        self.assertIn('cidr --service-cidr 172.20.0.0/16', commands)
        self.assertNotIn('00-preflight', commands)
        self.assertNotIn('kubeadm ', commands)
        self.assertFalse(
            list((host / 'root/dev-infra-evidence').glob('12-kubeadm-*.txt'))
        )
        self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_check_requires_exact_already_compliant_stage_transcripts(self) -> None:
        variables = (
            'FAKE_KERNEL_GATE_OUTPUT',
            'FAKE_CONTAINERD_GATE_OUTPUT',
            'FAKE_KUBERNETES_GATE_OUTPUT',
        )
        for variable in variables:
            with self.subTest(variable=variable):
                environment, _, command_log = self.make_environment()
                environment[variable] = (
                    'PHASE=unexpected\nMODE=CHECK\nRESULT=PASS_CHECK\n'
                    'REASON=apply-required\nEVIDENCE=NONE\nEXIT_CODE=0\n'
                    'NEXT=NONE\nSHA256=NONE'
                )

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                self.assertNotIn('kubeadm ', command_log.read_text(encoding='utf-8'))

    def test_check_requires_cgroup_v2_and_exact_swap_contract(self) -> None:
        cases = ('cgroup', 'swap-nonnumeric', 'swap-small')
        for case in cases:
            with self.subTest(case=case):
                environment, _, command_log = self.make_environment()
                if case == 'cgroup':
                    (Path(environment['FAKE_DRIFT_DIR']) / 'cgroup').touch()
                elif case == 'swap-nonnumeric':
                    environment['FAKE_SWAP_OUTPUT'] = '/swap.img unknown'
                else:
                    environment['FAKE_SWAP_OUTPUT'] = '/swap.img 3999999999'

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                self.assertFalse(command_log.exists())

    def test_check_uses_raw_swap_columns_on_util_linux_239(self) -> None:
        """捕获 util-linux 2.39.3 忽略旧 --output 组合并回退六列。"""
        environment, _, command_log = self.make_environment()
        environment['FAKE_SWAPON_UTIL_LINUX_239'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_KUBEADM_CHECK', result.stdout)
        self.assertNotIn(
            'kubeadm ', command_log.read_text(encoding='utf-8')
        )

    def test_check_rejects_any_existing_kubernetes_or_etcd_state(self) -> None:
        cases = (
            'bootstrap-kubelet', 'pki-key', 'arbitrary-dir',
            'broken-symlink', 'etcd-content',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                if case == 'bootstrap-kubelet':
                    target = host / 'etc/kubernetes/bootstrap-kubelet.conf'
                    target.parent.mkdir(parents=True)
                    target.write_text('state\n', encoding='utf-8')
                elif case == 'pki-key':
                    target = host / 'etc/kubernetes/pki/ca.key'
                    target.parent.mkdir(parents=True)
                    target.write_text('state\n', encoding='utf-8')
                elif case == 'arbitrary-dir':
                    (host / 'etc/kubernetes/arbitrary').mkdir(parents=True)
                elif case == 'broken-symlink':
                    target = host / 'etc/kubernetes/unknown'
                    target.parent.mkdir(parents=True)
                    target.symlink_to('/missing')
                else:
                    target = host / 'var/lib/etcd/db'
                    target.parent.mkdir(parents=True)
                    target.write_text('state\n', encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                self.assertFalse(command_log.exists())

    def test_listener_query_failure_stops_before_prior_gates(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_SS_FAIL'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
        self.assertFalse(command_log.exists())

    def test_prior_gate_failure_stops_before_kubeadm(self) -> None:
        for variable in (
            'FAKE_KERNEL_GATE_FAIL',
            'FAKE_CONTAINERD_GATE_FAIL',
            'FAKE_KUBERNETES_GATE_FAIL',
            'FAKE_CIDR_GATE_FAIL',
        ):
            with self.subTest(variable=variable):
                environment, _, command_log = self.make_environment()
                environment[variable] = '1'

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                self.assertNotIn(
                    'kubeadm ', command_log.read_text(encoding='utf-8')
                )

    def test_validate_and_preflight_failure_never_reaches_init(self) -> None:
        cases = (
            ('FAKE_VALIDATE_FAIL', 'config validate'),
            ('FAKE_PREFLIGHT_FAIL', 'init phase preflight'),
        )
        for variable, expected_command in cases:
            with self.subTest(variable=variable):
                environment, _, command_log = self.make_environment()
                environment[variable] = '1'

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 40, result.stderr)
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn(expected_command, commands)
                self.assertNotIn('kubeadm init --config', commands)
                self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_check_rejects_unsafe_or_drifted_repo_config(self) -> None:
        cases = ('symlink', 'mode', 'digest', 'owner')
        for case in cases:
            with self.subTest(case=case):
                environment, _, command_log = self.make_environment()
                config = Path(environment['BOOTSTRAP_TEST_CONFIG_FILE'])
                if case == 'symlink':
                    target = config.with_name('config-target.yaml')
                    target.write_bytes(config.read_bytes())
                    config.unlink()
                    config.symlink_to(target)
                elif case == 'mode':
                    config.chmod(0o666)
                elif case == 'digest':
                    config.write_text(
                        config.read_text(encoding='utf-8') + '\n# drift\n',
                        encoding='utf-8',
                    )
                else:
                    environment['FAKE_STAT_OWNER_DRIFT'] = str(config)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                self.assertFalse(command_log.exists())

    def test_apply_uses_one_private_config_snapshot_for_exact_kubeadm_argv(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        kubeadm_commands = [
            line for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('kubeadm ')
        ]
        self.assertEqual(len(kubeadm_commands), 3)
        snapshots = [line.rsplit(' ', 1)[1] for line in kubeadm_commands]
        self.assertEqual(len(set(snapshots)), 1)
        snapshot = Path(snapshots[0])
        self.assertTrue(
            str(snapshot).startswith(str(host / 'var/tmp/.kubeadm-config.')),
            snapshots[0],
        )
        self.assertEqual(snapshot.name, 'init.yaml')
        self.assertFalse(snapshot.parent.exists())
        self.assertNotEqual(
            snapshots[0], environment['BOOTSTRAP_TEST_CONFIG_FILE']
        )

    def test_apply_rejects_private_config_snapshot_race(self) -> None:
        for race in ('snapshot-content', 'snapshot-mode', 'snapshot-symlink'):
            with self.subTest(race=race):
                environment, _, command_log = self.make_environment()
                environment['FAKE_DRIFT_AFTER_VALIDATE'] = race

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn('kubeadm config validate --config', commands)
                self.assertNotIn('kubeadm init phase preflight --config', commands)
                self.assertNotIn('kubeadm init --config', commands)

    def test_apply_reruns_complete_gate_set_after_validate_and_preflight(self) -> None:
        cases = [('validate', 'ip')]
        cases.extend(
            ('preflight', drift)
            for drift in (
                'ip', 'route', 'swap', 'cgroup', 'config',
                'kernel', 'containerd', 'kubernetes',
            )
        )
        for phase, drift in cases:
            with self.subTest(phase=phase, drift=drift):
                environment, _, command_log = self.make_environment()
                environment[
                    'FAKE_DRIFT_AFTER_VALIDATE'
                    if phase == 'validate'
                    else 'FAKE_DRIFT_AFTER_PREFLIGHT'
                ] = drift

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn('kubeadm config validate --config', commands)
                if phase == 'preflight':
                    self.assertIn('kubeadm init phase preflight --config', commands)
                self.assertNotIn('kubeadm init --config', commands)

    def test_preinit_second_gate_catches_manifest_or_listener_race(self) -> None:
        for race in ('manifest', 'listener', 'kubelet-config'):
            with self.subTest(race=race):
                environment, _, command_log = self.make_environment()
                environment['FAKE_PREINIT_RACE'] = race

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_ALREADY_INITIALIZED', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn('kubeadm init phase preflight --config', commands)
                self.assertNotIn('kubeadm init --config', commands)
                self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_apply_uses_only_fixed_config_sequence_and_redacts_raw_output(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_KUBEADM_INITIALIZED', result.stdout)
        self.assertIn('NEXT=stages/60-install-cilium/run.sh --check', result.stdout)
        commands = [
            line for line in command_log.read_text(encoding='utf-8').splitlines()
            if line.startswith('kubeadm ')
        ]
        snapshots = [line.rsplit(' ', 1)[1] for line in commands]
        self.assertEqual(len(set(snapshots)), 1)
        config = snapshots[0]
        self.assertEqual(commands, [
            f'kubeadm config validate --config {config}',
            f'kubeadm init phase preflight --config {config}',
            f'kubeadm init --config {config}',
        ])
        evidence = list((host / 'root/dev-infra-evidence').glob('12-kubeadm-*.txt'))
        self.assertEqual(len(evidence), 1)
        all_output = result.stdout + result.stderr + evidence[0].read_text(
            encoding='utf-8'
        )
        self.assertNotIn(self.canary, all_output)
        self.assertNotIn('token', all_output)
        self.assertNotIn('certificate-key', all_output)
        self.assertNotIn('kubeconfig\n', all_output)
        self.assertIn('CERTIFICATE_SUBJECT=CN = kube-apiserver', all_output)

    def test_init_failure_does_not_leak_raw_output_or_claim_success(self) -> None:
        environment, host, _ = self.make_environment()
        environment['FAKE_INIT_FAIL'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 40, result.stderr)
        self.assertIn('RESULT=STOP_APPLY_FAILED', result.stdout)
        self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)
        self.assertNotIn(self.canary, result.stdout + result.stderr)
        self.assertNotIn('kubeadm reset', result.stdout + result.stderr)
        self.assertTrue(
            (host / 'etc/kubernetes/pki/partial-init').is_file(),
            '失败后的 partial state 必须保留供人工审计',
        )

    def test_post_init_requires_exact_running_control_plane_set(self) -> None:
        for mutation in (
            'missing', 'duplicate', 'extra', 'stopped',
            'wrong-namespace', 'malformed', 'command-failure',
        ):
            with self.subTest(mutation=mutation):
                environment, host, _ = self.make_environment()
                payload = json.loads(environment['FAKE_CRICTL_JSON'])
                containers = payload['containers']
                if mutation == 'missing':
                    containers.pop()
                elif mutation == 'duplicate':
                    containers.append(dict(containers[0]))
                elif mutation == 'extra':
                    extra = json.loads(json.dumps(containers[0]))
                    extra['metadata']['name'] = 'kube-proxy'
                    containers.append(extra)
                elif mutation == 'stopped':
                    containers[0]['state'] = 'CONTAINER_EXITED'
                elif mutation == 'wrong-namespace':
                    containers[0]['labels'][
                        'io.kubernetes.pod.namespace'
                    ] = 'default'
                elif mutation == 'malformed':
                    environment['FAKE_CRICTL_JSON'] = '{not-json'
                else:
                    environment['FAKE_CRICTL_FAIL'] = '1'
                if mutation not in ('malformed', 'command-failure'):
                    environment['FAKE_CRICTL_JSON'] = json.dumps(payload)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)
                self.assertEqual(
                    list((host / 'root/dev-infra-evidence').glob('12-kubeadm-*.txt')),
                    [],
                )

    def test_post_init_requires_kube_proxy_api_objects_absent(self) -> None:
        cases = (
            ('FAKE_KUBE_PROXY_DAEMONSET', 'daemonset.apps/kube-proxy\n'),
            ('FAKE_KUBE_PROXY_PODS', 'pod/kube-proxy-abc\n'),
            ('FAKE_KUBE_PROXY_CONFIGMAP', 'configmap/kube-proxy\n'),
            ('FAKE_KUBECTL_FAIL', 'daemonset'),
            ('FAKE_KUBECTL_FAIL', 'pods'),
            ('FAKE_KUBECTL_FAIL', 'configmap'),
        )
        for variable, value in cases:
            with self.subTest(variable=variable, value=value):
                environment, _, _ = self.make_environment()
                environment[variable] = value

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 50, result.stderr)
                self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
                self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)

    def test_post_init_requires_certificate_checkend_zero(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_CERT_EXPIRED'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 50, result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn('openssl x509 -checkend 0 -noout -in ', commands)
        self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)

    def test_apply_uses_exact_post_init_argv_and_safe_static_commands(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = command_log.read_text(encoding='utf-8').splitlines()
        endpoint = 'unix:///run/containerd/containerd.sock'
        self.assertIn(
            'crictl --runtime-endpoint '
            f'{endpoint} --image-endpoint {endpoint} '
            'ps --state Running --output json',
            commands,
        )
        admin_conf = host / 'etc/kubernetes/admin.conf'
        # 重锚：kubeconfig 不再是磁盘路径，而是进程替换的 fd——这正是 TOCTOU 加固的
        # 要点（Stage 90 早已是此形态）。重锚后的断言比原来更强：既钉住三条查询的
        # 参数逐字不变，也钉住 kubectl 不再从磁盘读 kubeconfig。
        for query in (
            'get daemonset kube-proxy --ignore-not-found --output=name',
            'get pods --selector k8s-app=kube-proxy --output=name',
            'get configmap kube-proxy --ignore-not-found --output=name',
        ):
            with self.subTest(query=query):
                self.assertTrue(
                    any(
                        line.startswith('kubectl --kubeconfig /dev/fd/')
                        and '--namespace kube-system' in line
                        and line.endswith(query)
                        for line in commands
                    ),
                    commands,
                )
        self.assertNotIn(f'--kubeconfig {admin_conf}', '\n'.join(commands))
        script = KUBEADM_INIT.read_text(encoding='utf-8')
        for forbidden in (
            'kubeadm reset', '--ignore-preflight-errors', '--upload-certs',
            '--certificate-key', 'kubeadm token', 'set -x',
            'kubectl config view --raw',
        ):
            self.assertNotIn(forbidden, script)

    def test_admin_conf_swapped_during_a_query_stops_the_stage(self) -> None:
        """捕获 Stage 50 在查询期间 admin.conf 被替换却仍判定通过的缺陷。

        改造前 kubectl 直接读磁盘上的 kubeconfig，读取期间被替换不会被发现；改造后
        它只读已捕获的字节，且每次调用**前后各**校验一次磁盘文件与捕获内容是否仍然
        一致，于是替换必然被发现并 fail-closed。
        """
        environment, _, _ = self.make_environment()
        environment['FAKE_ADMIN_CONF_SWAP'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            'REASON=kube-proxy-daemonset-present-or-unreadable', result.stdout
        )
        self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)

    def test_post_init_rejects_any_kube_proxy_static_manifest(self) -> None:
        environment, _, _ = self.make_environment()
        environment['FAKE_CREATE_KUBE_PROXY'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 50, result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        self.assertNotIn('PASS_KUBEADM_INITIALIZED', result.stdout)


class CiliumInstallTest(BootstrapTestCase):
    canary = 'SECRET_CANARY_CILIUM_DO_NOT_LOG'
    cilium_image = (
        'quay.io/cilium/cilium:v1.20.0@sha256:'
        '383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93'
    )
    operator_image = (
        'quay.io/cilium/operator-generic:v1.20.0@sha256:'
        '80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3'
    )
    envoy_image = (
        'quay.io/cilium/cilium-envoy:'
        'v1.37.5-1782911245-7cffc778c923f68a77954a53b1a98d6b5353f004@sha256:'
        '583057dd4f7d54cd41efff3c413aa0b148ac201f522e2c3336851fa89c78b039'
    )
    desired_values = '''kubeProxyReplacement: true
k8sServiceHost: 192.0.2.10
k8sServicePort: 6443

cgroup:
  autoMount:
    enabled: false
  hostRoot: /sys/fs/cgroup

gatewayAPI:
  enabled: true

hubble:
  enabled: false

image:
  digest: sha256:383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93
  useDigest: true

ipam:
  mode: kubernetes

operator:
  image:
    genericDigest: sha256:80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3
    useDigest: true
  replicas: 1
'''
    desired_values_object = {
        'kubeProxyReplacement': True,
        'k8sServiceHost': '192.0.2.10',
        'k8sServicePort': 6443,
        'cgroup': {
            'autoMount': {'enabled': False},
            'hostRoot': '/sys/fs/cgroup',
        },
        'gatewayAPI': {'enabled': True},
        'hubble': {'enabled': False},
        'image': {
            'digest': (
                'sha256:'
                '383968cd5e8873f7976fa76aa6196045643558f4cc9518a207b9335cb24a0e93'
            ),
            'useDigest': True,
        },
        'ipam': {'mode': 'kubernetes'},
        'operator': {
            'image': {
                'genericDigest': (
                    'sha256:'
                    '80744a8cc7c91c2f9e6347629406844eb35d79b30a732c6d41c15b17232a74f3'
                ),
                'useDigest': True,
            },
            'replicas': 1,
        },
    }
    gateway_names = (
        'backendtlspolicies.gateway.networking.k8s.io',
        'gatewayclasses.gateway.networking.k8s.io',
        'gateways.gateway.networking.k8s.io',
        'grpcroutes.gateway.networking.k8s.io',
        'httproutes.gateway.networking.k8s.io',
        'listenersets.gateway.networking.k8s.io',
        'referencegrants.gateway.networking.k8s.io',
        'tcproutes.gateway.networking.k8s.io',
        'tlsroutes.gateway.networking.k8s.io',
        'udproutes.gateway.networking.k8s.io',
    )

    def write_executable(self, path: Path, source: str | bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(source, bytes):
            path.write_bytes(source)
        else:
            path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def helm_archive(self, member: bytes | None = None) -> bytes:
        if member is None:
            member = textwrap.dedent(
                '''
                #!/usr/bin/python3 -B
                import json
                import os
                from pathlib import Path
                import signal
                import sys
                import time

                args = sys.argv[1:]
                with open(os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8') as log:
                    log.write('helm ' + ' '.join(args) + '\\n')
                sys.stderr.write(os.environ['FAKE_CANARY'] + '\\n')
                if (
                    os.environ.get('FAKE_SIMULATE_CLIENT_CACHE', '0') == '1'
                    and os.environ.get('KUBECACHEDIR') != '/dev/null'
                ):
                    cache = Path(os.environ['HOME']) / '.kube/cache/helm-write'
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text('cache\\n', encoding='utf-8')

                if args == ['version', '--short']:
                    print(os.environ.get('FAKE_HELM_VERSION', 'v3.21.0+gfixture'))
                    raise SystemExit(0)

                if len(args) < 2 or args[0] != '--kubeconfig':
                    raise SystemExit(64)
                try:
                    supplied = Path(args[1]).read_text(encoding='utf-8')
                    # 真实 helm/client-go 会多次加载 kubeconfig；管道第二次读到空。
                    supplied_again = Path(args[1]).read_text(encoding='utf-8')
                except OSError:
                    raise SystemExit(64)
                if supplied != os.environ['FAKE_ADMIN_CONF_CONTENT'] or supplied_again != supplied:
                    raise SystemExit(64)
                if os.environ.get('FAKE_HELM_KILL_PARENT', '0') == '1':
                    # 模拟运维中断：kubeconfig 临时目录还在时杀掉调用 stage 的 shell。
                    os.kill(os.getppid(), signal.SIGTERM)
                    time.sleep(0.5)
                    raise SystemExit(0)
                prefix = ['--kubeconfig', args[1]]
                if args == prefix + ['list', '--all-namespaces', '--all', '--output', 'json']:
                    override = os.environ.get('FAKE_HELM_LIST_JSON')
                    if override is not None:
                        print(override)
                        raise SystemExit(0)
                    state = os.environ.get('FAKE_HELM_LIST_STATE', '')
                    if not state:
                        state = 'exact' if Path(os.environ['FAKE_RELEASE_MARKER']).exists() else 'missing'
                    if state == 'failure':
                        raise SystemExit(1)
                    if state == 'missing':
                        print('[]')
                    elif state == 'exact':
                        print(json.dumps([{
                            'name': 'cilium',
                            'namespace': 'kube-system',
                            'revision': '1',
                            'updated': '2026-08-10 00:00:00.000000000 +0000 UTC',
                            'status': 'deployed',
                            'chart': 'cilium-1.20.0',
                            'app_version': '1.20.0',
                        }]))
                    else:
                        print(json.dumps([{
                            'name': 'cilium', 'namespace': 'kube-system',
                            'revision': '2', 'status': 'failed',
                            'updated': '2026-08-10 00:00:00.000000000 +0000 UTC',
                            'chart': 'cilium-1.19.0', 'app_version': '1.19.0',
                        }]))
                    raise SystemExit(0)

                if args == prefix + [
                    'get', 'values', 'cilium', '--namespace', 'kube-system',
                    '--revision', '1', '--output', 'json',
                ]:
                    if os.environ.get('FAKE_HELM_VALUES_FAIL', '0') == '1':
                        raise SystemExit(1)
                    sys.stdout.write(os.environ['FAKE_HELM_VALUES_JSON'])
                    raise SystemExit(0)

                if len(args) >= 3 and args[:3] == prefix + ['install']:
                    race = os.environ.get('FAKE_INPUT_RACE_AT_CONSUMER', '')
                    if race == 'chart':
                        Path(os.environ['FAKE_CILIUM_CHART']).write_text(
                            'malicious\\n', encoding='utf-8'
                        )
                    elif race == 'values':
                        Path(os.environ['FAKE_VALUES_FILE']).write_text(
                            'malicious\\n', encoding='utf-8'
                        )
                    chart_input = Path(args[4])
                    values_input = Path(args[args.index('--values') + 1])
                    if os.environ.get('FAKE_SNAPSHOT_UNKNOWN_ENTRY', '0') == '1':
                        (chart_input.parent / 'unapproved').write_text(
                            'preserve-me\\n', encoding='utf-8'
                        )
                    if (
                        chart_input.read_text(encoding='utf-8') == 'malicious\\n'
                        or values_input.read_text(encoding='utf-8') == 'malicious\\n'
                    ):
                        with open(
                            os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8'
                        ) as log:
                            log.write('malicious-helm-input-consumed\\n')
                    if os.environ.get('FAKE_HELM_INSTALL_FAIL', '0') == '1':
                        raise SystemExit(1)
                    Path(os.environ['FAKE_RELEASE_MARKER']).touch()
                    Path(os.environ['FAKE_CILIUM_MARKER']).touch()
                    print(os.environ['FAKE_CANARY'])
                    raise SystemExit(0)
                raise SystemExit(64)
                '''
            ).lstrip().encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            entry = tarfile.TarInfo('linux-amd64/helm')
            entry.mode = 0o755
            entry.size = len(member)
            archive.addfile(entry, io.BytesIO(member))
        return stream.getvalue()

    def hostile_helm_archive(self, mutation: str) -> bytes:
        stream = io.BytesIO()
        member = b'#!/bin/sh\nexit 0\n'
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            if mutation != 'absent':
                target = tarfile.TarInfo('linux-amd64/helm')
                target.mode = 0o644 if mutation == 'nonexec' else 0o755
                if mutation == 'target-symlink':
                    target.type = tarfile.SYMTYPE
                    target.linkname = '/tmp/unapproved-helm'
                    archive.addfile(target)
                else:
                    target.size = len(member)
                    archive.addfile(target, io.BytesIO(member))
                    if mutation == 'duplicate':
                        duplicate = tarfile.TarInfo('linux-amd64/helm')
                        duplicate.mode = 0o755
                        duplicate.size = len(member)
                        archive.addfile(duplicate, io.BytesIO(member))
            if mutation == 'absent':
                readme = tarfile.TarInfo('linux-amd64/README.md')
                readme.mode = 0o644
                readme.size = len(member)
                archive.addfile(readme, io.BytesIO(member))
            elif mutation == 'traversal':
                traversal = tarfile.TarInfo('../outside')
                traversal.mode = 0o644
                traversal.size = len(member)
                archive.addfile(traversal, io.BytesIO(member))
            elif mutation == 'unrelated-link':
                link = tarfile.TarInfo('linux-amd64/unapproved-link')
                link.type = tarfile.SYMTYPE
                link.linkname = '/tmp/outside'
                archive.addfile(link)
        return stream.getvalue()

    def gateway_bundle_json(self, *, partial: bool = False) -> str:
        annotations = {
            'gateway.networking.k8s.io/bundle-version': 'v1.6.1',
            'gateway.networking.k8s.io/channel': 'standard',
        }
        crd_annotations = {
            'api-approved.kubernetes.io': (
                'https://github.com/kubernetes-sigs/gateway-api/pull/4530'
            ),
            **annotations,
        }
        items: list[dict[str, object]] = [
            {
                'apiVersion': 'apiextensions.k8s.io/v1',
                'kind': 'CustomResourceDefinition',
                'metadata': {
                    'name': name,
                    'annotations': dict(crd_annotations),
                },
            }
            for name in self.gateway_names
        ]
        items.extend(
            [
                {
                    'apiVersion': 'admissionregistration.k8s.io/v1',
                    'kind': 'ValidatingAdmissionPolicy',
                    'metadata': {
                        'name': 'safe-upgrades.gateway.networking.k8s.io',
                        'annotations': annotations,
                    },
                    'status': {'typeChecking': {'expressionWarnings': []}},
                },
                {
                    'apiVersion': 'admissionregistration.k8s.io/v1',
                    'kind': 'ValidatingAdmissionPolicyBinding',
                    'metadata': {
                        'name': 'safe-upgrades.gateway.networking.k8s.io',
                        'annotations': annotations,
                    },
                    'spec': {'validationActions': ['Deny']},
                },
            ]
        )
        if partial:
            items.pop(0)
        return json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})

    def cilium_workload_json(self, *, partial: bool = False) -> str:
        items: list[dict[str, object]] = [
            {
                'apiVersion': 'apps/v1',
                'kind': 'DaemonSet',
                'metadata': {
                    'name': 'cilium',
                    'namespace': 'kube-system',
                    'labels': {
                        'k8s-app': 'cilium',
                        'app.kubernetes.io/name': 'cilium-agent',
                        'app.kubernetes.io/part-of': 'cilium',
                        'helm.sh/chart': 'cilium-1.20.0',
                    },
                },
                'spec': {
                    'template': {
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-agent',
                                    'image': self.cilium_image,
                                }
                            ]
                        }
                    }
                },
                'status': {
                    'desiredNumberScheduled': 1,
                    'numberReady': 1,
                    'numberAvailable': 1,
                    'numberUnavailable': 0,
                },
            },
            {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'metadata': {
                    'name': 'cilium-operator',
                    'namespace': 'kube-system',
                    'labels': {
                        'io.cilium/app': 'operator',
                        'name': 'cilium-operator',
                        'app.kubernetes.io/name': 'cilium-operator',
                        'app.kubernetes.io/part-of': 'cilium',
                        'helm.sh/chart': 'cilium-1.20.0',
                    },
                },
                'spec': {
                    'replicas': 1,
                    'template': {
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-operator',
                                    'image': self.operator_image,
                                }
                            ]
                        }
                    },
                },
                'status': {
                    'replicas': 1,
                    'updatedReplicas': 1,
                    'readyReplicas': 1,
                    'availableReplicas': 1,
                    'unavailableReplicas': 0,
                },
            },
        ]
        if partial:
            items[0]['status']['numberReady'] = 0  # type: ignore[index]
        return json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})

    def envoy_daemonset_json(self, *, ready: bool = True) -> str:
        return json.dumps(
            {
                'apiVersion': 'apps/v1',
                'kind': 'DaemonSet',
                'metadata': {
                    'name': 'cilium-envoy',
                    'namespace': 'kube-system',
                    'labels': {
                        'k8s-app': 'cilium-envoy',
                        'name': 'cilium-envoy',
                        'app.kubernetes.io/name': 'cilium-envoy',
                        'app.kubernetes.io/part-of': 'cilium',
                        'helm.sh/chart': 'cilium-1.20.0',
                    },
                },
                'spec': {
                    'template': {
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-envoy',
                                    'image': self.envoy_image,
                                }
                            ]
                        }
                    }
                },
                'status': {
                    'desiredNumberScheduled': 1,
                    'numberReady': 1 if ready else 0,
                    'numberAvailable': 1 if ready else 0,
                    'numberUnavailable': 0 if ready else 1,
                },
            }
        )

    def envoy_pods_json(self, *, ready: bool = True) -> str:
        return json.dumps(
            {
                'apiVersion': 'v1',
                'kind': 'List',
                'items': [
                    {
                        'apiVersion': 'v1',
                        'kind': 'Pod',
                        'metadata': {
                            'name': 'cilium-envoy-fixture',
                            'namespace': 'kube-system',
                            'labels': {
                                'k8s-app': 'cilium-envoy',
                                'name': 'cilium-envoy',
                                'app.kubernetes.io/name': 'cilium-envoy',
                                'app.kubernetes.io/part-of': 'cilium',
                                'helm.sh/chart': 'cilium-1.20.0',
                                'controller-revision-hash': 'fixture-hash',
                            },
                        },
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-envoy',
                                    'image': self.envoy_image,
                                }
                            ]
                        },
                        'status': {
                            'phase': 'Running' if ready else 'Pending',
                            'conditions': [
                                {
                                    'type': 'Ready',
                                    'status': 'True' if ready else 'False',
                                }
                            ],
                            'containerStatuses': [{'ready': ready}],
                        },
                    }
                ],
            }
        )

    @staticmethod
    def cilium_config_json() -> str:
        return json.dumps(
            {
                'apiVersion': 'v1',
                'kind': 'ConfigMap',
                'metadata': {
                    'name': 'cilium-config',
                    'namespace': 'kube-system',
                },
                'data': {
                    'kube-proxy-replacement': 'true',
                    'enable-gateway-api': 'true',
                    'ipam': 'kubernetes',
                    'cgroup-root': '/sys/fs/cgroup',
                },
            }
        )

    def helm_secret_json(self, *, extra: bool = False) -> str:
        items: list[dict[str, object]] = [
            {
                'apiVersion': 'v1',
                'kind': 'Secret',
                'metadata': {
                    'name': 'sh.helm.release.v1.cilium.v1',
                    'namespace': 'kube-system',
                    'labels': {
                            'owner': 'helm',
                            'name': 'cilium',
                            'status': 'deployed',
                            'version': '1',
                            'modifiedAt': '1786320001',
                    },
                },
                'type': 'helm.sh/release.v1',
                'data': {'release': 'SECRET_HELM_RELEASE_PAYLOAD'},
            }
        ]
        if extra:
            items.append(
                {
                    'apiVersion': 'v1',
                    'kind': 'Secret',
                    'metadata': {
                        'name': 'sh.helm.release.v1.unknown.v1',
                        'namespace': 'default',
                        'labels': {
                            'owner': 'helm', 'name': 'unknown',
                            'status': 'deployed', 'version': '1',
                        },
                    },
                    'type': 'helm.sh/release.v1',
                }
            )
        return json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})

    def make_environment(self) -> tuple[dict[str, str], Path, Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        home = directory / 'home'
        fake_bin = directory / 'bin'
        command_log = directory / 'commands.log'
        staging = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
        for path in (
            host / 'root/dev-infra-evidence',
            host / 'etc/kubernetes',
            host / 'usr/bin',
            host / 'usr/sbin',
            host / 'usr/local/bin',
            host / 'usr/local/sbin',
            staging,
            fake_bin,
            home,
        ):
            path.mkdir(parents=True, exist_ok=True)
        (host / 'root').chmod(0o700)
        (host / 'root/dev-infra-artifacts').chmod(0o700)
        staging.chmod(0o700)
        (host / 'usr').chmod(0o755)
        (host / 'usr/local').chmod(0o755)
        (host / 'usr/local/bin').chmod(0o755)

        helm_archive = staging / 'helm-v3.21.0-linux-amd64.tar.gz'
        gateway_manifest = staging / 'standard-install.yaml'
        chart = staging / 'cilium-1.20.0.tgz'
        helm_archive.write_bytes(self.helm_archive())
        gateway_manifest.write_text('gateway v1.6.1 fixture\n', encoding='utf-8')
        chart.write_text('cilium 1.20.0 fixture\n', encoding='utf-8')
        for artifact in (helm_archive, gateway_manifest, chart):
            artifact.chmod(0o600)

        values = directory / 'values.yaml'
        values.write_bytes((ROOT / 'bootstrap/hosts/example-node/cilium-values.yaml').read_bytes())
        values.chmod(0o644)
        admin_conf = host / 'etc/kubernetes/admin.conf'
        admin_conf.write_text(self.canary + '\n', encoding='utf-8')
        admin_conf.chmod(0o600)

        gateway_marker = directory / 'gateway-exact'
        release_marker = directory / 'release-exact'
        cilium_marker = directory / 'cilium-exact'
        gateway_exact = directory / 'gateway-exact.json'
        gateway_partial = directory / 'gateway-partial.json'
        cilium_exact = directory / 'cilium-exact.json'
        cilium_partial = directory / 'cilium-partial.json'
        secret_exact = directory / 'helm-secret-exact.json'
        secret_extra = directory / 'helm-secret-extra.json'
        gateway_exact.write_text(self.gateway_bundle_json(), encoding='utf-8')
        gateway_partial.write_text(
            self.gateway_bundle_json(partial=True), encoding='utf-8'
        )
        cilium_exact.write_text(self.cilium_workload_json(), encoding='utf-8')
        cilium_partial.write_text(
            self.cilium_workload_json(partial=True), encoding='utf-8'
        )
        secret_exact.write_text(self.helm_secret_json(), encoding='utf-8')
        secret_extra.write_text(self.helm_secret_json(extra=True), encoding='utf-8')

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'hostname',
            '#!/bin/sh\nprintf "%s\\n" "${FAKE_HOSTNAME:-example-node}"\n',
        )
        hosts_root = directory / 'hosts'
        hosts_root.mkdir()
        self.write_fixture_host(hosts_root)
        self.write_executable(
            fake_bin / 'sha256sum',
            '''
            #!/bin/sh
            path=$1
            case "${path##*/}" in
              helm-v3.21.0-linux-amd64.tar.gz)
                key=helm
                digest=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
                ;;
              standard-install.yaml)
                key=gateway
                digest=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
                ;;
              cilium-1.20.0.tgz)
                key=chart
                digest=c5f013912360d1a334f44ef25f36da59ba3414cdb48f466ee12d0c4fdff27883
                ;;
              values.yaml)
                key=values
                digest=5f598e99c515d0ccca7efdd6069ea515142615520a02e6c4e0b5cba1bf011d8a
                ;;
              *) exec /usr/bin/shasum -a 256 "$path" ;;
            esac
            if [ "${FAKE_DIGEST_DRIFT:-}" = "$key" ]; then
              digest=0000000000000000000000000000000000000000000000000000000000000000
            fi
            if [ "$(/bin/cat "$path")" = raced ] || [ "$(/bin/cat "$path")" = malicious ]; then
              digest=0000000000000000000000000000000000000000000000000000000000000000
            fi
            printf '%s  %s\n' "$digest" "$path"
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg-query',
            '''
            #!/bin/sh
            [ "$1" = -S ] && [ "$2" = /usr/bin/kubectl ] || exit 1
            printf 'kubectl: /usr/bin/kubectl\n'
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg',
            '''
            #!/bin/sh
            [ "$1" = --verify ] && [ "$2" = kubectl ] || exit 64
            if [ "${FAKE_KUBECTL_VERIFY_DOC_EXCLUDES:-0}" = 1 ]; then
              case "${FAKE_KUBECTL_VERIFY_DOC_SHAPE:-exact}" in
                exact)
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                  ;;
                single)
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  ;;
                duplicate)
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                  ;;
                other-package)
                  printf 'missing     /usr/share/doc/unapproved/LICENSE\n'
                  printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                  ;;
                extra-missing)
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                  printf 'missing     /usr/bin/%s\n' "$2"
                  ;;
                checksum)
                  printf '??5??????   /usr/bin/%s\n' "$2"
                  ;;
                nonzero)
                  printf 'missing     /usr/share/doc/%s/LICENSE\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\n' "$2"
                  exit 1
                  ;;
                *) exit 64 ;;
              esac
              exit 0
            fi
            [ "${FAKE_KUBECTL_VERIFY_DRIFT:-0}" != 1 ] || printf '??5?????? /usr/bin/kubectl\n'
            ''',
        )
        self.write_executable(
            fake_bin / 'sync',
            '''
            #!/bin/sh
            [ "${FAKE_SYNC_FAIL:-0}" != 1 ] || exit 1
            case "${FAKE_HELM_TEMP_RACE:-}" in
              symlink)
                /bin/rm -f -- "$1"
                /bin/ln -s "$FAKE_HELM_OUTSIDE" "$1"
                ;;
              mode) chmod 0666 "$1" ;;
              bytes)
                printf '#!/bin/sh\nexit 0\n' >"$1"
                chmod 0755 "$1"
                ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'rm',
            '''
            #!/bin/bash
            target=${!#}
            if [[ "${FAKE_HELM_TEMP_RM_FAIL:-0}" == 1 &&
                  "${target##*/}" == .helm.tmp.* ]]; then
              exit 1
            fi
            exec /bin/rm "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'ln',
            '''
            #!/bin/sh
            target=
            for target do :; done
            if [ -n "${FAKE_LN_RACE_TARGET:-}" ] && [ "$target" = "$FAKE_LN_RACE_TARGET" ]; then
              printf 'raced\n' >"$target"
              chmod 0755 "$target"
            fi
            exec /bin/ln "$@"
            ''',
        )
        self.write_executable(
            host / 'usr/bin/kubectl',
            '''
            #!/usr/bin/python3 -B
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with open(os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8') as log:
                log.write('kubectl ' + ' '.join(args) + '\\n')
            sys.stderr.write(os.environ['FAKE_CANARY'] + '\\n')
            if (
                os.environ.get('FAKE_SIMULATE_CLIENT_CACHE', '0') == '1'
                and '--cache-dir=/dev/null' not in args
            ):
                cache = Path(os.environ['HOME']) / '.kube/cache/kubectl-write'
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text('cache\\n', encoding='utf-8')
            hostile_kuberc = (
                (Path(os.environ['HOME']) / '.kube/kuberc').exists()
                and os.environ.get('KUBECTL_KUBERC') != 'false'
                and os.environ.get('FAKE_HOSTILE_KUBERC_MODE', '')
            )
            if len(args) < 2 or args[0] != '--kubeconfig':
                raise SystemExit(64)
            try:
                supplied = Path(args[1]).read_text(encoding='utf-8')
            except OSError:
                raise SystemExit(64)
            if supplied != os.environ['FAKE_ADMIN_CONF_CONTENT']:
                raise SystemExit(64)
            prefix = ['--kubeconfig', args[1]]
            safe_prefix = prefix + ['--cache-dir=/dev/null']
            if args[:3] == safe_prefix:
                command = args[3:]
            elif args[:2] == prefix:
                command = args[2:]
            else:
                raise SystemExit(64)
            if hostile_kuberc:
                with open(
                    os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8'
                ) as log:
                    log.write(
                        'kuberc-injected '
                        + os.environ['FAKE_HOSTILE_KUBERC_MODE'] + '\\n'
                    )
                if os.environ['FAKE_HOSTILE_KUBERC_MODE'] == 'query':
                    raise SystemExit(64)
                if 'apply' in command:
                    raise SystemExit(0)

            if command == [
                'config', 'view', '--raw', '--merge=false', '--output=json',
            ]:
                if os.environ.get('FAKE_ADMIN_VIEW_FAIL', '0') == '1':
                    raise SystemExit(1)
                if os.environ.get('FAKE_ADMIN_SOURCE_RACE', '0') == '1':
                    Path(os.environ['FAKE_ADMIN_CONF']).write_text(
                        'raced-admin-config\\n', encoding='utf-8'
                    )
                sys.stdout.write(os.environ['FAKE_ADMIN_VIEW_JSON'])
                raise SystemExit(0)

            if command == [
                'config', 'view', '--minify',
                '--output=jsonpath={.clusters[0].cluster.server}',
            ]:
                counter = Path(os.environ['FAKE_API_COUNTER'])
                count = (
                    int(counter.read_text(encoding='utf-8')) + 1
                    if counter.exists() else 1
                )
                counter.write_text(str(count), encoding='utf-8')
                if (
                    os.environ.get('FAKE_PRE_GATEWAY_INPUT_RACE', '')
                    and count == 3
                ):
                    Path(os.environ['FAKE_GATEWAY_MANIFEST']).write_text(
                        'malicious\\n', encoding='utf-8'
                    )
                sys.stdout.write(
                    os.environ.get(
                        'FAKE_API_ENDPOINT', 'https://192.0.2.10:6443'
                    )
                )
                raise SystemExit(0)

            kube_proxy = {
                ('--namespace', 'kube-system', 'get', 'daemonset', 'kube-proxy', '--ignore-not-found', '--output=name'):
                    os.environ.get('FAKE_KUBE_PROXY_DAEMONSET', ''),
                ('--namespace', 'kube-system', 'get', 'pods', '--selector', 'k8s-app=kube-proxy', '--output=name'):
                    os.environ.get('FAKE_KUBE_PROXY_PODS', ''),
                ('--namespace', 'kube-system', 'get', 'configmap', 'kube-proxy', '--ignore-not-found', '--output=name'):
                    os.environ.get('FAKE_KUBE_PROXY_CONFIGMAP', ''),
            }
            key = tuple(command)
            if key in kube_proxy:
                query_failure = os.environ.get('FAKE_KUBE_PROXY_QUERY_FAIL', '')
                if query_failure and query_failure in ' '.join(command):
                    raise SystemExit(1)
                if key[3:5] == ('configmap', 'kube-proxy'):
                    counter = Path(os.environ['FAKE_KUBE_PROXY_COUNTER'])
                    count = int(counter.read_text(encoding='utf-8')) + 1 if counter.exists() else 1
                    counter.write_text(str(count), encoding='utf-8')
                    if count == int(os.environ.get('FAKE_PRE_HELM_RACE_COUNT', '0')):
                        race = os.environ.get('FAKE_PRE_HELM_RACE', '')
                        if race == 'helm':
                            Path(os.environ['FAKE_HELM_BINARY']).write_text(
                                '#!/bin/sh\\nprintf "malicious-helm-executed\\n" >>"$FAKE_COMMAND_LOG"\\nexit 0\\n',
                                encoding='utf-8',
                            )
                            Path(os.environ['FAKE_HELM_BINARY']).chmod(0o755)
                        elif race == 'release':
                            Path(os.environ['FAKE_RELEASE_MARKER']).touch()
                            Path(os.environ['FAKE_CILIUM_MARKER']).touch()
                if Path(os.environ['FAKE_KUBE_PROXY_MARKER']).exists():
                    sys.stdout.write('daemonset.apps/kube-proxy\\n')
                else:
                    sys.stdout.write(kube_proxy[key])
                raise SystemExit(0)

            if command in (
                ['get', 'secrets', '--all-namespaces', '--selector', 'owner=helm', '--output=json'],
                ['get', 'secrets,configmaps', '--all-namespaces', '--selector', 'owner=helm', '--output=json'],
            ):
                state = os.environ.get('FAKE_HELM_SECRET_STATE', '')
                if state == 'failure':
                    raise SystemExit(1)
                if state == 'extra':
                    path = os.environ['FAKE_SECRET_EXTRA_JSON']
                elif Path(os.environ['FAKE_RELEASE_MARKER']).exists():
                    path = os.environ['FAKE_SECRET_EXACT_JSON']
                else:
                    print('{"apiVersion":"v1","kind":"List","items":[]}')
                    raise SystemExit(0)
                sys.stdout.write(Path(path).read_text(encoding='utf-8'))
                raise SystemExit(0)

            unscoped_bundle_get = [
                'get',
                'customresourcedefinitions.apiextensions.k8s.io,validatingadmissionpolicies.admissionregistration.k8s.io,validatingadmissionpolicybindings.admissionregistration.k8s.io',
                '--output=json',
            ]
            gateway_names = [
                'backendtlspolicies.gateway.networking.k8s.io',
                'gatewayclasses.gateway.networking.k8s.io',
                'gateways.gateway.networking.k8s.io',
                'grpcroutes.gateway.networking.k8s.io',
                'httproutes.gateway.networking.k8s.io',
                'listenersets.gateway.networking.k8s.io',
                'referencegrants.gateway.networking.k8s.io',
                'tcproutes.gateway.networking.k8s.io',
                'tlsroutes.gateway.networking.k8s.io',
                'udproutes.gateway.networking.k8s.io',
            ]
            scoped_bundle_get = ['get']
            scoped_bundle_get.extend(
                'customresourcedefinition.apiextensions.k8s.io/' + name
                for name in gateway_names
            )
            scoped_bundle_get.extend([
                'validatingadmissionpolicy.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io',
                'validatingadmissionpolicybinding.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io',
                '--ignore-not-found', '--output=json',
            ])
            if command in (unscoped_bundle_get, scoped_bundle_get):
                if (
                    command == unscoped_bundle_get
                    and os.environ.get('FAKE_REQUIRE_SCOPED_GATEWAY', '0') == '1'
                ):
                    raise SystemExit(64)
                state = os.environ.get('FAKE_GATEWAY_STATE', '')
                if state == 'failure':
                    raise SystemExit(1)
                if state == 'partial':
                    path = os.environ['FAKE_GATEWAY_PARTIAL_JSON']
                elif Path(os.environ['FAKE_GATEWAY_MARKER']).exists():
                    path = os.environ['FAKE_GATEWAY_EXACT_JSON']
                else:
                    # 真实 kubectl：按名字 get 且全部不存在时，--ignore-not-found 不打印任何字节。
                    raise SystemExit(0)
                sys.stdout.write(Path(path).read_text(encoding='utf-8'))
                raise SystemExit(0)

            diff_prefix = [
                'diff', '--server-side=true',
                '--field-manager=engineering-platform-bootstrap',
                '--filename',
            ]
            if len(command) == 5 and command[:4] == diff_prefix:
                state = os.environ.get('FAKE_GATEWAY_STATE', '')
                if state == 'failure':
                    raise SystemExit(2)
                raise SystemExit(0 if Path(os.environ['FAKE_GATEWAY_MARKER']).exists() else 1)

            apply_prefix = [
                'apply', '--server-side=true',
                '--field-manager=engineering-platform-bootstrap',
                '--filename',
            ]
            if len(command) == 5 and command[:4] == apply_prefix:
                if os.environ.get('FAKE_GATEWAY_APPLY_FAIL', '0') == '1':
                    raise SystemExit(1)
                if Path(command[4]).read_text(encoding='utf-8') == 'malicious\\n':
                    with open(
                        os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8'
                    ) as log:
                        log.write('malicious-gateway-consumed\\n')
                Path(os.environ['FAKE_GATEWAY_MARKER']).touch()
                race = os.environ.get('FAKE_RACE_AFTER_GATEWAY', '')
                if race == 'chart':
                    Path(os.environ['FAKE_CILIUM_CHART']).write_text('raced\\n', encoding='utf-8')
                elif race == 'values':
                    Path(os.environ['FAKE_VALUES_FILE']).write_text('raced\\n', encoding='utf-8')
                elif race == 'kube-proxy':
                    Path(os.environ['FAKE_KUBE_PROXY_MARKER']).touch()
                raise SystemExit(0)

            workloads = [
                '--namespace', 'kube-system', 'get',
                'daemonset/cilium', 'deployment/cilium-operator', '--output=json',
            ]
            safe_workloads = [
                '--namespace', 'kube-system', 'get',
                'daemonset/cilium', 'deployment/cilium-operator',
                '--ignore-not-found', '--output=json',
            ]
            if command in (workloads, safe_workloads):
                if (
                    command == workloads
                    and os.environ.get('FAKE_REQUIRE_IGNORE_NOT_FOUND', '0') == '1'
                    and not Path(os.environ['FAKE_CILIUM_MARKER']).exists()
                ):
                    raise SystemExit(1)
                state = os.environ.get('FAKE_CILIUM_STATE', '')
                if state == 'failure':
                    raise SystemExit(1)
                if state == 'partial':
                    path = os.environ['FAKE_CILIUM_PARTIAL_JSON']
                elif Path(os.environ['FAKE_CILIUM_MARKER']).exists():
                    # 真实 rollout：helm --atomic 返回后 DaemonSet/Deployment 仍可能未就绪，
                    # 前 N 次查询按 partial 回答，之后才 exact。
                    counter = Path(os.environ['FAKE_CILIUM_QUERY_COUNTER'])
                    seen = int(counter.read_text()) if counter.exists() else 0
                    counter.write_text(str(seen + 1))
                    if seen < int(os.environ.get('FAKE_CILIUM_READY_AFTER_QUERIES', '0')):
                        path = os.environ['FAKE_CILIUM_PARTIAL_JSON']
                    else:
                        path = os.environ['FAKE_CILIUM_EXACT_JSON']
                else:
                    # 真实 kubectl：按名字 get 且全部不存在时，--ignore-not-found 不打印任何字节。
                    raise SystemExit(0)
                sys.stdout.write(Path(path).read_text(encoding='utf-8'))
                raise SystemExit(0)

            managed_cilium_objects = {
                (
                    '--namespace', 'kube-system', 'get',
                    'daemonset/cilium-envoy', '--ignore-not-found',
                    '--output=json',
                ): 'FAKE_ENVOY_DAEMONSET_JSON',
                (
                    '--namespace', 'kube-system', 'get', 'pods',
                    '--selector', 'k8s-app=cilium-envoy', '--output=json',
                ): 'FAKE_ENVOY_PODS_JSON',
                (
                    '--namespace', 'kube-system', 'get',
                    'configmap/cilium-config', '--ignore-not-found',
                    '--output=json',
                ): 'FAKE_CILIUM_CONFIG_JSON',
            }
            if tuple(command) in managed_cilium_objects:
                if os.environ.get('FAKE_CILIUM_MANAGED_QUERY_FAIL', '') in command:
                    raise SystemExit(1)
                if not Path(os.environ['FAKE_CILIUM_MARKER']).exists():
                    if command[3] == 'pods':
                        print('{"apiVersion":"v1","kind":"List","items":[]}')
                    raise SystemExit(0)
                sys.stdout.write(os.environ[managed_cilium_objects[tuple(command)]])
                raise SystemExit(0)
            raise SystemExit(64)
            ''',
        )

        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'HOME': str(home),
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_HOSTS_DIR': str(hosts_root),
                'BOOTSTRAP_TEST_VALUES_FILE': str(values),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_CANARY': self.canary,
                'FAKE_HELM_VALUES_JSON': json.dumps(
                    self.desired_values_object
                ),
                'FAKE_ADMIN_CONF': str(admin_conf),
                'FAKE_ADMIN_CONF_CONTENT': self.canary + '\n',
                'FAKE_ADMIN_VIEW_JSON': json.dumps(self.admin_config_object()),
                'FAKE_GATEWAY_MANIFEST': str(gateway_manifest),
                'FAKE_CILIUM_CHART': str(chart),
                'FAKE_VALUES_FILE': str(values),
                'FAKE_GATEWAY_MARKER': str(gateway_marker),
                'FAKE_RELEASE_MARKER': str(release_marker),
                'FAKE_CILIUM_MARKER': str(cilium_marker),
                'FAKE_CILIUM_QUERY_COUNTER': str(directory / 'cilium-query-count'),
                'FAKE_KUBE_PROXY_MARKER': str(directory / 'kube-proxy-present'),
                'FAKE_KUBE_PROXY_COUNTER': str(directory / 'kube-proxy-count'),
                'FAKE_API_COUNTER': str(directory / 'api-count'),
                'FAKE_HELM_BINARY': str(host / 'usr/local/bin/helm'),
                'FAKE_HELM_OUTSIDE': str(directory / 'helm-outside'),
                'FAKE_GATEWAY_EXACT_JSON': str(gateway_exact),
                'FAKE_GATEWAY_PARTIAL_JSON': str(gateway_partial),
                'FAKE_CILIUM_EXACT_JSON': str(cilium_exact),
                'FAKE_CILIUM_PARTIAL_JSON': str(cilium_partial),
                'FAKE_ENVOY_DAEMONSET_JSON': self.envoy_daemonset_json(),
                'FAKE_ENVOY_PODS_JSON': self.envoy_pods_json(),
                'FAKE_CILIUM_CONFIG_JSON': self.cilium_config_json(),
                'FAKE_SECRET_EXACT_JSON': str(secret_exact),
                'FAKE_SECRET_EXTRA_JSON': str(secret_extra),
            }
        )
        for variable in (
            'APT_CONFIG', 'KUBECONFIG', 'GNUPGHOME', 'HELM_NAMESPACE',
            'HELM_DRIVER', 'HELM_KUBECONTEXT', 'HELM_CONFIG_HOME',
            'HELM_CACHE_HOME', 'HELM_DATA_HOME', 'DPKG_ADMINDIR',
            'DPKG_ROOT', 'DPKG_FORCE', 'DPKG_FRONTEND_LOCKED',
            'KUBECACHEDIR', 'TAR_OPTIONS', 'BASH_ENV', 'ENV',
            'OPENSSL_CONF', 'OPENSSL_MODULES', 'PYTHONPATH', 'PYTHONHOME',
            'PYTHONPYCACHEPREFIX', 'PYTHONDONTWRITEBYTECODE',
        ):
            environment.pop(variable, None)
        return environment, host, command_log, values

    def run_stage(
        self,
        environment: dict[str, str],
        mode: str = '--check',
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', '-p', str(INSTALL_CILIUM), mode],
            env=environment,
            timeout=timeout,
        )

    def test_fake_ln_extracts_last_argument_under_posix_shell(self) -> None:
        """捕获 /bin/sh fixture 在并发目标注入前因 ${!#} 退出的缺陷。"""
        environment, host, _, _ = self.make_environment()
        fake_ln = Path(environment['PATH'].split(':', 1)[0]) / 'ln'
        source = host / 'ln-source'
        target = host / 'ln-target'
        source.write_text('source\n', encoding='utf-8')
        environment['FAKE_LN_RACE_TARGET'] = str(target)
        posix_shell = next(
            (
                str(path)
                for path in (Path('/bin/dash'), Path('/usr/bin/dash'))
                if path.exists()
            ),
            '/bin/sh',
        )

        result = self.run_command(
            [posix_shell, str(fake_ln), str(source), str(target)],
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(encoding='utf-8'), 'raced\n')

    def install_helm_contract(self, host: Path) -> None:
        archive = host / (
            'root/dev-infra-artifacts/pcs-2026-08-10.1/'
            'helm-v3.21.0-linux-amd64.tar.gz'
        )
        with tarfile.open(archive, mode='r:gz') as source:
            member = source.extractfile('linux-amd64/helm')
            assert member is not None
            payload = member.read()
        self.write_executable(host / 'usr/local/bin/helm', payload)

    def install_full_cluster_contract(
        self, environment: dict[str, str], host: Path
    ) -> None:
        self.install_helm_contract(host)
        Path(environment['FAKE_GATEWAY_MARKER']).touch()
        Path(environment['FAKE_RELEASE_MARKER']).touch()
        Path(environment['FAKE_CILIUM_MARKER']).touch()

    # "零写入" = 运行结束后无残留；CHECK 期间允许 helm 的私有 kubeconfig 临时目录短暂存在。
    def test_check_is_zero_write_for_clean_apply_required_state(self) -> None:
        environment, host, command_log, _ = self.make_environment()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)
        self.assertIn('NEXT=stages/60-install-cilium/run.sh --apply', result.stdout)
        self.assertFalse((host / 'usr/local/bin/helm').exists())
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')),
            [],
        )
        if command_log.exists():
            commands = command_log.read_text(encoding='utf-8')
            self.assertNotIn(' apply ', commands)
            self.assertNotIn('helm --kubeconfig', commands)

    def test_check_accepts_declared_kubectl_doc_exclusions(self) -> None:
        """捕获 Stage 60 把官方 dpkg 文档排除输出误判为 kubectl provenance 漂移。"""
        environment, host, _, _ = self.make_environment()
        excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
        excludes.parent.mkdir(parents=True)
        excludes.write_text(
            'path-exclude=/usr/share/man/*\n'
            'path-exclude=/usr/share/doc/*\n'
            'path-include=/usr/share/doc/*/copyright\n'
            'path-include=/usr/share/doc/*/changelog.*\n',
            encoding='utf-8',
        )
        excludes.chmod(0o644)
        environment['FAKE_KUBECTL_VERIFY_DOC_EXCLUDES'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)

    def test_check_rejects_unsafe_kubectl_doc_exclusion_shapes(self) -> None:
        """缺失或不安全的 exclude 合同与任何额外 payload 缺失都必须 fail closed。"""
        for drift in (
            'missing-config',
            'symlink-config',
            'unsafe-mode',
            'single',
            'duplicate',
            'other-package',
            'extra-missing',
            'checksum',
            'nonzero',
        ):
            with self.subTest(drift=drift):
                environment, host, _, _ = self.make_environment()
                environment['FAKE_KUBECTL_VERIFY_DOC_EXCLUDES'] = '1'
                excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
                if drift != 'missing-config':
                    excludes.parent.mkdir(parents=True)
                    if drift == 'symlink-config':
                        outside = host.parent / 'unapproved-dpkg-excludes'
                        outside.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        outside.chmod(0o644)
                        excludes.symlink_to(outside)
                    else:
                        excludes.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        excludes.chmod(
                            0o666 if drift == 'unsafe-mode' else 0o644
                        )
                if drift not in {
                    'missing-config', 'symlink-config', 'unsafe-mode'
                }:
                    environment['FAKE_KUBECTL_VERIFY_DOC_SHAPE'] = drift

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertIn('REASON=kubectl-provenance-drift', result.stdout)

    def test_check_declares_dpkg_verification_dependencies(self) -> None:
        """共享 dpkg 校验预期的 awk/grep 必须在 Stage 60 前置声明。"""
        required_commands = next(
            line
            for line in INSTALL_CILIUM.read_text(encoding='utf-8').splitlines()
            if line.startswith('for required_command in ')
        )

        self.assertIn('awk', required_commands.split())
        self.assertIn('grep', required_commands.split())

    def test_rejects_staged_digest_or_values_contract_drift(self) -> None:
        for drift in ('helm', 'gateway', 'chart', 'values'):
            with self.subTest(drift=drift):
                environment, host, command_log, _ = self.make_environment()
                environment['FAKE_DIGEST_DRIFT'] = drift

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
                self.assertFalse((host / 'usr/local/bin/helm').exists())
                self.assertFalse(command_log.exists())

    def test_rejects_hostile_helm_archive_contract(self) -> None:
        for mutation in (
            'absent', 'duplicate', 'target-symlink', 'nonexec',
            'traversal', 'unrelated-link',
        ):
            with self.subTest(mutation=mutation):
                environment, host, command_log, _ = self.make_environment()
                archive = (
                    host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
                    / 'helm-v3.21.0-linux-amd64.tar.gz'
                )
                archive.write_bytes(self.hostile_helm_archive(mutation))

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn(
                    'RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout
                )
                self.assertFalse((host / 'usr/local/bin/helm').exists())
                if command_log.exists():
                    commands = command_log.read_text(encoding='utf-8')
                    self.assertNotIn(' apply ', commands)
                    self.assertNotIn(' install ', commands)

        for mutation in ('mode', 'symlink', 'kube-proxy-disabled'):
            with self.subTest(mutation=mutation):
                environment, host, command_log, values = self.make_environment()
                if mutation == 'mode':
                    values.chmod(0o666)
                elif mutation == 'symlink':
                    target = values.with_name('values-target.yaml')
                    target.write_bytes(values.read_bytes())
                    values.unlink()
                    values.symlink_to(target)
                else:
                    values.write_text(
                        values.read_text(encoding='utf-8').replace(
                            'kubeProxyReplacement: true',
                            'kubeProxyReplacement: false',
                        ),
                        encoding='utf-8',
                    )

                result = self.run_stage(environment, '--apply')

                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((host / 'usr/local/bin/helm').exists())
                self.assertFalse(command_log.exists())

    def test_rejects_kube_proxy_unknown_release_or_partial_state(self) -> None:
        cases = (
            'kube-proxy', 'unknown-release', 'gateway-partial',
            'gateway-annotation-extra', 'cilium-partial',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log, _ = self.make_environment()
                if case == 'kube-proxy':
                    environment['FAKE_KUBE_PROXY_DAEMONSET'] = (
                        'daemonset.apps/kube-proxy\n'
                    )
                elif case == 'unknown-release':
                    environment['FAKE_HELM_SECRET_STATE'] = 'extra'
                elif case == 'gateway-partial':
                    environment['FAKE_GATEWAY_STATE'] = 'partial'
                elif case == 'gateway-annotation-extra':
                    Path(environment['FAKE_GATEWAY_MARKER']).touch()
                    gateway = Path(environment['FAKE_GATEWAY_EXACT_JSON'])
                    payload = json.loads(gateway.read_text(encoding='utf-8'))
                    payload['items'][0]['metadata']['annotations'][
                        'unapproved.example.invalid/annotation'
                    ] = 'value'
                    gateway.write_text(json.dumps(payload), encoding='utf-8')
                else:
                    self.install_full_cluster_contract(environment, host)
                    environment['FAKE_CILIUM_STATE'] = 'partial'

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' install ', commands)
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_rejects_invalid_official_helm_storage_labels(self) -> None:
        for mutation in (
            'missing-modified-at', 'created-at-only',
            'invalid-modified-at', 'extra-label',
        ):
            with self.subTest(mutation=mutation):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                secret = Path(environment['FAKE_SECRET_EXACT_JSON'])
                payload = json.loads(secret.read_text(encoding='utf-8'))
                labels = payload['items'][0]['metadata']['labels']
                if mutation == 'missing-modified-at':
                    labels.pop('modifiedAt')
                elif mutation == 'created-at-only':
                    labels.pop('modifiedAt')
                    labels['createdAt'] = '1786320000'
                elif mutation == 'invalid-modified-at':
                    labels['modifiedAt'] = 'not-a-timestamp'
                else:
                    labels['unapproved'] = 'value'
                secret.write_text(json.dumps(payload), encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_apply_uses_only_fixed_staged_inputs_and_safe_argv(self) -> None:
        environment, host, command_log, values = self.make_environment()

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_INSTALLED', result.stdout)
        self.assertIn('NEXT=stages/90-verify/run.sh --check', result.stdout)
        commands = command_log.read_text(encoding='utf-8').splitlines()
        staging = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
        gateway_apply = next(line for line in commands if ' apply ' in line)
        helm_install = next(line for line in commands if ' install cilium ' in line)
        gateway_argv = gateway_apply.split()
        helm_argv = helm_install.split()
        self.assertEqual(
            gateway_argv[:2] + gateway_argv[3:8],
            [
                'kubectl', '--kubeconfig', '--cache-dir=/dev/null', 'apply',
                '--server-side=true',
                '--field-manager=engineering-platform-bootstrap', '--filename',
            ],
        )
        self.assertTrue(gateway_argv[2].startswith('/dev/fd/'))
        gateway_snapshot = Path(gateway_argv[8])
        self.assertEqual(gateway_snapshot.name, 'standard-install.yaml')
        snapshot_dir = gateway_snapshot.parent
        self.assertEqual(snapshot_dir.parent, host / 'root')
        self.assertTrue(snapshot_dir.name.startswith('.cilium-inputs.'))
        self.assertEqual(helm_argv[:2], ['helm', '--kubeconfig'])
        helm_kubeconfig = Path(helm_argv[2])
        self.assertEqual(helm_kubeconfig.name, 'config')
        self.assertEqual(helm_kubeconfig.parent.parent, host / 'root')
        self.assertTrue(helm_kubeconfig.parent.name.startswith('.helm-kubeconfig.'))
        self.assertFalse(helm_kubeconfig.exists(), 'helm 临时 kubeconfig 用完必须删除')
        self.assertEqual(list((host / 'root').glob('.helm-kubeconfig.*')), [])
        self.assertEqual(helm_argv[3:5], ['install', 'cilium'])
        self.assertEqual(Path(helm_argv[5]).parent, snapshot_dir)
        self.assertEqual(Path(helm_argv[5]).name, 'cilium-1.20.0.tgz')
        self.assertEqual(
            helm_argv[6:9], ['--namespace', 'kube-system', '--values']
        )
        self.assertEqual(Path(helm_argv[9]).parent, snapshot_dir)
        self.assertEqual(Path(helm_argv[9]).name, 'values.yaml')
        self.assertEqual(helm_argv[10:], ['--atomic', '--timeout', '10m0s'])
        self.assertLess(commands.index(gateway_apply), commands.index(helm_install))
        mutation_commands = [
            line for line in commands
            if ' apply ' in line or ' install ' in line
        ]
        self.assertEqual(mutation_commands, [gateway_apply, helm_install])
        self.assertNotIn(str(staging), '\n'.join(mutation_commands))
        self.assertNotIn(str(values), '\n'.join(mutation_commands))
        for forbidden in (
            '--set', ' repo ', ' upgrade ', ' dependency ',
            'https://', '--reuse-values', '--reset-values',
        ):
            self.assertNotIn(forbidden, '\n'.join(commands))
        evidence = list(
            (host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')
        )
        self.assertEqual(len(evidence), 1)
        all_output = result.stdout + result.stderr + evidence[0].read_text(
            encoding='utf-8'
        )
        self.assertNotIn(self.canary, all_output)
        self.assertNotIn('kubeconfig', all_output.lower())

    def test_apply_resumes_gateway_only_then_check_is_idempotent(self) -> None:
        environment, host, command_log, _ = self.make_environment()
        Path(environment['FAKE_GATEWAY_MARKER']).touch()

        apply_result = self.run_stage(environment, '--apply')

        self.assertEqual(apply_result.returncode, 0, apply_result.stderr)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn(' apply ', commands)
        self.assertIn('helm --kubeconfig', commands)
        command_log.unlink()

        check_result = self.run_stage(environment)

        self.assertEqual(check_result.returncode, 0, check_result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', check_result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertNotIn(' apply ', commands)
        self.assertNotIn(' install ', commands)
        self.assertTrue((host / 'usr/local/bin/helm').is_file())

    def test_helm_publication_rejects_unknown_shadow_and_race(self) -> None:
        for mutation in ('unknown', 'shadow', 'race'):
            with self.subTest(mutation=mutation):
                environment, host, command_log, _ = self.make_environment()
                helm = host / 'usr/local/bin/helm'
                if mutation == 'unknown':
                    self.write_executable(helm, '#!/bin/sh\nprintf unknown\\n\n')
                elif mutation == 'shadow':
                    self.write_executable(
                        host / 'usr/bin/helm', '#!/bin/sh\nprintf shadow\\n\n'
                    )
                else:
                    environment['FAKE_LN_RACE_TARGET'] = str(helm)

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                if mutation == 'unknown':
                    self.assertIn('unknown', helm.read_text(encoding='utf-8'))
                if command_log.exists():
                    self.assertNotIn(
                        ' apply ', command_log.read_text(encoding='utf-8')
                    )

    def test_helm_publication_rejects_post_sync_temporary_races(self) -> None:
        for mutation in ('symlink', 'mode', 'bytes'):
            with self.subTest(mutation=mutation):
                environment, host, command_log, _ = self.make_environment()
                outside = Path(environment['FAKE_HELM_OUTSIDE'])
                outside.write_text('outside-sentinel\n', encoding='utf-8')
                outside.chmod(0o600)
                before = outside.read_bytes()
                environment['FAKE_HELM_TEMP_RACE'] = mutation

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertFalse((host / 'usr/local/bin/helm').exists())
                self.assertEqual(outside.read_bytes(), before)
                self.assertEqual(
                    list((host / 'usr/local/bin').glob('.helm.tmp.*')),
                    [],
                )
                if command_log.exists():
                    commands = command_log.read_text(encoding='utf-8')
                    self.assertNotIn(' apply ', commands)
                    self.assertNotIn(' install ', commands)

    def test_helm_publication_stops_if_temporary_unlink_fails(self) -> None:
        environment, host, _, _ = self.make_environment()
        environment['FAKE_HELM_TEMP_RM_FAIL'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertNotIn('PASS_CILIUM_INSTALLED', result.stdout)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')),
            [],
        )

    def test_apply_waits_for_cilium_rollout_before_verifying(self) -> None:
        """helm --atomic 不保证 DaemonSet/Deployment 已就绪（maxUnavailable ≥ desired 时
        0 个就绪也算就绪）；装完后必须有界轮询直到 COMPLIANT，而不是一次性检查。"""
        environment, _, command_log, _ = self.make_environment()
        environment['FAKE_CILIUM_READY_AFTER_QUERIES'] = '2'
        # 预算按实测取，不靠拍脑袋。轮询本身是墙钟判定（deadline = SECONDS + 预算），
        # 而本用例要求的三轮 load_cluster_state 空载实测约 13 秒（把预算逐档压下去，
        # 12 秒判红、16 秒判绿）；同一条 stage 的总耗时随机器负载在 59～231 秒之间
        # 摆动，约 4 倍。原值 30 秒只有约 2 倍余量，一次双套件互抢的全量跑就把它吃穿，
        # 报 cilium-post-install-state-invalid，看上去像回归其实是负载。
        # 180 秒对实测值有约 14 倍余量，对最坏观测仍有约 3 倍。
        # 间隔从 0 改为 1：正常路径只多 2 秒，而实现若回归成永不就绪，轮询由热自旋
        # 变成每秒一次，超时前不会派生上千个子进程。
        environment['BOOTSTRAP_TEST_POST_INSTALL_INTERVAL'] = '1'
        environment['BOOTSTRAP_TEST_POST_INSTALL_TIMEOUT'] = '180'

        # 与姊妹用例同理：就绪判定若回归成永不 COMPLIANT，这里同样会无界自旋，
        # 从"判红"退化成"永久挂起"。上限远高于实测最坏 stage_wall（231 秒）。
        result = self.run_stage(environment, '--apply', timeout=600)

        self.assertEqual(
            result.returncode,
            0,
            '若 REASON=cilium-post-install-state-invalid，说明 180 秒预算被耗尽，'
            '两种可能：实现退化成不再轮询或永不就绪；或机器负载把预算吃穿'
            '（三轮轮询空载约 13 秒）。先数命令日志里 install 之后的 '
            'get daemonset/cilium 次数——少于 3 次是回归，够 3 次就是负载。\n'
            + result.stdout + result.stderr,
        )
        self.assertIn('RESULT=PASS_CILIUM_INSTALLED', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        install_index = commands.index(' install cilium ')
        after_install = commands[install_index:]
        self.assertGreaterEqual(
            after_install.count('get daemonset/cilium deployment/cilium-operator'), 3
        )

    def test_apply_stops_when_cilium_never_becomes_ready(self) -> None:
        environment, host, _, _ = self.make_environment()
        environment['FAKE_CILIUM_READY_AFTER_QUERIES'] = '1000'
        environment['BOOTSTRAP_TEST_POST_INSTALL_INTERVAL'] = '0'
        environment['BOOTSTRAP_TEST_POST_INSTALL_TIMEOUT'] = '1'

        # 墙钟上限：截止判定一旦失效（比较写反、或被整条删掉），轮询会无限自旋，
        # 这条用例就从"判红"退化成"永久挂起"——挂起的测试与恒绿的测试是同一类问题，
        # 本地挂到无穷、CI 挂到 job 的 45 分钟超时且不指向具体用例。实测过：把
        # `(( SECONDS < post_install_deadline ))` 改成恒真后，本用例 100 秒不返回。
        # 600 秒远高于实测最坏 stage_wall（231 秒），不会被机器负载误触发。
        result = self.run_stage(environment, '--apply', timeout=600)

        self.assertEqual(result.returncode, 50, result.stdout)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        self.assertIn('REASON=cilium-post-install-state-invalid', result.stdout)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')), []
        )

    def test_apply_regates_inputs_and_cluster_after_gateway_mutation(self) -> None:
        for race, expected_code in (
            ('chart', 20), ('values', 20), ('kube-proxy', 30)
        ):
            with self.subTest(race=race):
                environment, _, command_log, _ = self.make_environment()
                environment['FAKE_RACE_AFTER_GATEWAY'] = race

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, expected_code, result.stderr)
                commands = command_log.read_text(encoding='utf-8')
                self.assertIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_apply_consumes_only_private_snapshots_across_input_races(self) -> None:
        for race in ('gateway', 'chart', 'values'):
            with self.subTest(race=race):
                environment, host, command_log, values = self.make_environment()
                if race == 'gateway':
                    environment['FAKE_PRE_GATEWAY_INPUT_RACE'] = '1'
                else:
                    environment['FAKE_INPUT_RACE_AT_CONSUMER'] = race

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 20, result.stderr)
                self.assertIn('RESULT=STOP_SUPPLY_CHAIN_MISMATCH', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn('malicious-gateway-consumed', commands)
                self.assertNotIn('malicious-helm-input-consumed', commands)
                if race == 'gateway':
                    self.assertNotIn(' apply ', commands)
                else:
                    install = next(
                        line for line in commands.splitlines()
                        if ' install cilium ' in line
                    )
                    self.assertNotIn(
                        str(
                            host
                            / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
                            / 'cilium-1.20.0.tgz'
                        ),
                        install,
                    )
                    self.assertNotIn(str(values), install)
                self.assertEqual(
                    list((host / 'root').glob('.cilium-inputs.*')),
                    [],
                )

    def test_success_requires_safe_snapshot_cleanup_before_evidence(self) -> None:
        environment, host, _, _ = self.make_environment()
        environment['FAKE_SNAPSHOT_UNKNOWN_ENTRY'] = '1'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertNotIn('PASS_CILIUM_INSTALLED', result.stdout)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')),
            [],
        )
        snapshots = list((host / 'root').glob('.cilium-inputs.*'))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(
            (snapshots[0] / 'unapproved').read_text(encoding='utf-8'),
            'preserve-me\n',
        )

    def test_rejects_relevant_environment_overrides_before_lookup(self) -> None:
        for variable in (
            'KUBECONFIG', 'HELM_NAMESPACE', 'HELM_DRIVER',
            'DPKG_ADMINDIR', 'DPKG_ROOT', 'DPKG_FORCE',
            'DPKG_FRONTEND_LOCKED', 'KUBECACHEDIR',
            'KUBECTL_EXTERNAL_DIFF', 'KUBECTL_KUBERC',
            'KUBECTL_UNAPPROVED', 'TAR_OPTIONS', 'BASH_ENV', 'ENV',
            'OPENSSL_CONF', 'OPENSSL_MODULES', 'PYTHONPATH', 'PYTHONHOME',
            'PYTHONPYCACHEPREFIX', 'PYTHONDONTWRITEBYTECODE',
        ):
            for value in ('', '/tmp/unapproved'):
                with self.subTest(variable=variable, value=value):
                    environment, _, command_log, _ = self.make_environment()
                    environment[variable] = value

                    result = self.run_stage(environment)

                    self.assertEqual(result.returncode, 10, result.stderr)
                    self.assertIn(
                        'REASON=untrusted-environment-override', result.stderr
                    )
                    self.assertFalse(command_log.exists())

    def test_uses_isolated_python_from_hostile_working_directory(self) -> None:
        environment, _, _, _ = self.make_environment()
        hostile = self.temporary_directory() / 'hostile-cwd'
        hostile.mkdir()
        import_marker = hostile / 'python-imported'
        (hostile / 'json.py').write_text(
            'from pathlib import Path\n'
            f'Path({str(import_marker)!r}).write_text("executed\\n")\n'
            'raise RuntimeError("hostile json module")\n',
            encoding='utf-8',
        )

        result = subprocess.run(
            ['/bin/bash', '-p', str(INSTALL_CILIUM), '--check'],
            cwd=hostile,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(import_marker.exists())

    def test_uses_fixed_tar_outside_path(self) -> None:
        environment, _, _, _ = self.make_environment()
        tar_marker = self.temporary_directory() / 'tar-executed'
        fake_bin = Path(environment['PATH'].split(':', 1)[0])
        self.write_executable(
            fake_bin / 'tar',
            '#!/bin/sh\n'
            'case "$*" in\n'
            f'  *helm-v3.21.0*) printf executed >{tar_marker}; exit 99 ;;\n'
            '  *) exec /usr/bin/tar "$@" ;;\n'
            'esac\n',
        )

        result = subprocess.run(
            ['/bin/bash', '-p', str(INSTALL_CILIUM), '--apply'],
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tar_marker.exists())

    def test_rejects_unsafe_admin_config_or_source_race(self) -> None:
        for case in (
            'exec', 'auth-provider', 'proxy-url', 'insecure-tls',
            'extra-cluster', 'wrong-context', 'query-failure', 'source-race',
        ):
            with self.subTest(case=case):
                environment, _, command_log, _ = self.make_environment()
                payload = self.admin_config_object()
                cluster = payload['clusters'][0]['cluster']
                user = payload['users'][0]['user']
                if case == 'exec':
                    user['exec'] = {'command': self.canary}
                elif case == 'auth-provider':
                    user['auth-provider'] = {'name': self.canary}
                elif case == 'proxy-url':
                    cluster['proxy-url'] = 'https://127.0.0.1:1'
                elif case == 'insecure-tls':
                    cluster['insecure-skip-tls-verify'] = True
                elif case == 'extra-cluster':
                    payload['clusters'].append(payload['clusters'][0].copy())
                elif case == 'wrong-context':
                    payload['current-context'] = 'unapproved'
                elif case == 'query-failure':
                    environment['FAKE_ADMIN_VIEW_FAIL'] = '1'
                else:
                    environment['FAKE_ADMIN_SOURCE_RACE'] = '1'
                environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertNotIn(self.canary, result.stdout + result.stderr)
                if command_log.exists():
                    commands = command_log.read_text(encoding='utf-8')
                    self.assertNotIn(' apply ', commands)
                    self.assertNotIn(' install ', commands)

    def test_check_accepts_optional_empty_preferences(self) -> None:
        """kubectl 若序列化空 preferences，也必须被接受。"""
        environment, _, _, _ = self.make_environment()
        payload = self.admin_config_object()
        payload['preferences'] = {}
        environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)

    def test_check_rejects_cluster_or_context_naming_drift(self) -> None:
        """cluster/context 命名或非空 preferences 偏离固定合同必须 fail closed。"""
        for case in (
            'nonempty-preferences',
            'cluster-name',
            'context-name',
            'context-cluster',
        ):
            with self.subTest(case=case):
                environment, _, _, _ = self.make_environment()
                payload = self.admin_config_object()
                if case == 'nonempty-preferences':
                    payload['preferences'] = {'colors': True}
                elif case == 'cluster-name':
                    payload['clusters'][0]['name'] = 'kubernetes'
                elif case == 'context-name':
                    payload['contexts'][0]['name'] = 'kubernetes-admin@kubernetes'
                else:
                    payload['contexts'][0]['context']['cluster'] = 'kubernetes'
                environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertIn(
                    'REASON=admin-conf-content-or-structure-drift',
                    result.stdout,
                )

    def test_admin_conf_contract_is_derived_from_host_config(self) -> None:
        """admin.conf 合同来自 host.env，lib 与 stage 内不得再写死名字。"""
        library = (ROOT / 'scripts/bootstrap/lib/admin-conf.sh').read_text(encoding='utf-8')
        for literal in ('example-cluster', '192.0.2.10', 'ADMIN_CONF_CLUSTER_NAME='):
            self.assertNotIn(literal, library)

        environment, _, _, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        shutil.rmtree(hosts_root / 'example-node')
        self.write_fixture_host(hosts_root, cluster_name='fixture-cluster')

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stdout)
        self.assertIn('REASON=admin-conf-content-or-structure-drift', result.stdout)

    def test_values_semantics_and_endpoint_come_from_host_env(self) -> None:
        cases = ('pin', 'semantics', 'endpoint')
        for case in cases:
            with self.subTest(case=case):
                environment, _, _, _ = self.make_environment()
                hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
                retail_pins = (hosts_root / 'example-node/pins.sha256').read_text(encoding='utf-8')
                if case == 'pin':
                    pins = hosts_root / 'example-node/pins.sha256'
                    pins.write_text(retail_pins.replace('5f598e99', '00000000', 1), encoding='utf-8')
                    expected_code, expected_reason = 20, 'staged-input-contract-drift'
                elif case == 'semantics':
                    # host.env 说 IP 是 .99，但 values 文件与 pins 仍是 retail 的：
                    # digest 通过，形状比对必须按 .99 拒绝。
                    shutil.rmtree(hosts_root / 'example-node')
                    host_dir = self.write_fixture_host(hosts_root, node_ip='192.0.2.99')
                    (host_dir / 'pins.sha256').write_text(retail_pins, encoding='utf-8')
                    expected_code, expected_reason = 20, 'staged-input-contract-drift'
                else:
                    # values 与 pins 一致地换成 .99，staged inputs 通过；
                    # admin.conf fixture 仍是 .27 → 谓词按 .99 拒绝。
                    shutil.rmtree(hosts_root / 'example-node')
                    host_dir = self.write_fixture_host(hosts_root, node_ip='192.0.2.99')
                    environment['BOOTSTRAP_TEST_VALUES_FILE'] = str(host_dir / 'cilium-values.yaml')
                    expected_code, expected_reason = 30, 'admin-conf-content-or-structure-drift'

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, expected_code, result.stdout)
                self.assertIn(f'REASON={expected_reason}', result.stdout)

    def test_registered_second_host_flows_through_cilium_check(self) -> None:
        environment, _, _, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        host_dir = self.write_fixture_host(
            hosts_root, name='fixture-host-b', node_ip='10.200.0.2',
            cluster_name='fixture-b',
        )
        environment['FAKE_HOSTNAME'] = 'fixture-host-b'
        environment['BOOTSTRAP_TEST_VALUES_FILE'] = str(host_dir / 'cilium-values.yaml')
        environment['FAKE_API_ENDPOINT'] = 'https://10.200.0.2:6443'
        payload = self.admin_config_object()
        payload['clusters'][0]['name'] = 'fixture-b'
        payload['clusters'][0]['cluster']['server'] = 'https://10.200.0.2:6443'
        payload['contexts'][0]['name'] = 'kubernetes-admin@fixture-b'
        payload['contexts'][0]['context']['cluster'] = 'fixture-b'
        payload['current-context'] = 'kubernetes-admin@fixture-b'
        environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)

    def test_admin_conf_predicate_is_not_duplicated(self) -> None:
        """Stage 60/90 必须共用同一份 admin.conf 谓词，避免再次漂移。"""
        for script in (INSTALL_CILIUM, FINAL_VERIFY):
            with self.subTest(script=script.name):
                text = script.read_text(encoding='utf-8')
                self.assertIn('lib/admin-conf.sh', text)
                self.assertNotIn('admin_conf_json_is_exact() {', text)

    def test_cni_manifest_is_not_duplicated(self) -> None:
        """Stage 40/90 必须共用同一份 CNI payload 锁定清单，避免再次漂移。"""
        for script in (INSTALL_KUBERNETES, FINAL_VERIFY):
            with self.subTest(script=script.name):
                text = script.read_text(encoding='utf-8')
                self.assertIn('lib/cni-manifest.sh', text)
                self.assertNotIn('cni_manifest() {', text)

    def test_all_cluster_clients_use_validated_in_memory_admin_config(self) -> None:
        environment, host, command_log, _ = self.make_environment()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = command_log.read_text(encoding='utf-8').splitlines()
        self.assertTrue(any(
            'config view --raw --merge=false --output=json' in line
            for line in commands
        ))
        cluster_clients = [
            line for line in commands
            if line.startswith('kubectl ') or (
                line.startswith('helm ') and ' version --short' not in line
            )
        ]
        self.assertTrue(cluster_clients)
        temporary_root = str(host / 'root/.helm-kubeconfig.')
        for line in cluster_clients:
            if line.startswith('kubectl '):
                self.assertIn(' --kubeconfig /dev/fd/', line)
            else:
                # helm 不能读管道：只接受 /root 下私有临时文件里的已校验内容。
                self.assertIn(f' --kubeconfig {temporary_root}', line)
                self.assertIn('/config ', line)
            self.assertNotIn(str(host / 'etc/kubernetes/admin.conf'), line)
        self.assertEqual(list((host / 'root').glob('.helm-kubeconfig.*')), [])

    def write_helm_kubeconfig_residue(self, host: Path) -> Path:
        residue = host / 'root/.helm-kubeconfig.stale'
        residue.mkdir()
        config = residue / 'config'
        config.write_text('leftover kubeconfig\n', encoding='utf-8')
        config.chmod(0o600)
        residue.chmod(0o700)
        return residue

    def test_check_stops_on_helm_kubeconfig_residue(self) -> None:
        """上次运行被中断留下的 kubeconfig 残留必须 fail-closed，且不被自动删除。"""
        environment, host, command_log, _ = self.make_environment()
        residue = self.write_helm_kubeconfig_residue(host)
        before_host = self.tree_snapshot(host)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        self.assertIn('REASON=helm-kubeconfig-residue', result.stdout)
        self.assertTrue((residue / 'config').is_file())
        self.assertEqual(self.tree_snapshot(host), before_host)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('13-cilium-*.txt')), []
        )
        self.assertFalse(command_log.exists())

    def test_helm_kubeconfig_is_removed_when_stage_is_signalled(self) -> None:
        """helm 运行期间被 SIGTERM 杀死时，EXIT trap 必须清掉 kubeconfig 临时目录。"""
        environment, host, command_log, _ = self.make_environment()
        self.install_helm_contract(host)
        environment['FAKE_HELM_KILL_PARENT'] = '1'

        result = self.run_stage(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            ' --kubeconfig ', command_log.read_text(encoding='utf-8')
        )
        self.assertEqual(list((host / 'root').glob('.helm-kubeconfig.*')), [])

    def test_fresh_workload_query_uses_ignore_not_found(self) -> None:
        environment, _, command_log, _ = self.make_environment()
        environment['FAKE_REQUIRE_IGNORE_NOT_FOUND'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)
        self.assertIn(
            'get daemonset/cilium deployment/cilium-operator '
            '--ignore-not-found --output=json',
            command_log.read_text(encoding='utf-8'),
        )

    def test_gateway_query_is_scoped_to_exact_bundle_objects(self) -> None:
        environment, _, command_log, _ = self.make_environment()
        environment['FAKE_REQUIRE_SCOPED_GATEWAY'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_CHECK', result.stdout)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            'customresourcedefinition.apiextensions.k8s.io/'
            'backendtlspolicies.gateway.networking.k8s.io',
            commands,
        )
        self.assertIn(
            'validatingadmissionpolicybinding.admissionregistration.k8s.io/'
            'safe-upgrades.gateway.networking.k8s.io --ignore-not-found',
            commands,
        )
        self.assertNotIn(
            'customresourcedefinitions.apiextensions.k8s.io,',
            commands,
        )

    # 断言的是"无残留"（tree snapshot 前后相同），不是字面意义的"没有写过"：
    # helm 的私有 kubeconfig 临时目录会在 CHECK 期间建立并在返回前删除。
    def test_check_has_no_host_or_client_cache_writes(self) -> None:
        environment, host, _, _ = self.make_environment()
        self.install_full_cluster_contract(environment, host)
        environment['FAKE_SIMULATE_CLIENT_CACHE'] = '1'
        home = Path(environment['HOME'])
        (home / '.kube').mkdir(mode=0o700)
        (home / '.kube/kuberc').write_text(
            'defaults:\n- command: get\n  options:\n'
            '    selector: hidden=true\n',
            encoding='utf-8',
        )
        environment['FAKE_HOSTILE_KUBERC_MODE'] = 'query'
        before_host = self.tree_snapshot(host)
        before_home = self.tree_snapshot(home)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=ALREADY_COMPLIANT', result.stdout)
        self.assertEqual(self.tree_snapshot(host), before_host)
        self.assertEqual(self.tree_snapshot(home), before_home)

    def test_rejects_helm_kube_environment_and_api_endpoint_drift(self) -> None:
        for value in ('', 'https://127.0.0.1:6443'):
            with self.subTest(helm_env=value):
                environment, _, command_log, _ = self.make_environment()
                environment['HELM_KUBEAPISERVER'] = value

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertFalse(command_log.exists())

        environment, _, command_log, _ = self.make_environment()
        environment['FAKE_API_ENDPOINT'] = 'https://127.0.0.1:6443'

        result = self.run_stage(environment, '--apply')

        self.assertEqual(result.returncode, 30, result.stderr)
        self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
        if command_log.exists():
            commands = command_log.read_text(encoding='utf-8')
            self.assertNotIn(' apply ', commands)
            self.assertNotIn(' install ', commands)

    def test_apply_disables_hostile_home_kuberc_defaults(self) -> None:
        for mode in ('query', 'apply'):
            with self.subTest(mode=mode):
                environment, _, command_log, _ = self.make_environment()
                home = Path(environment['HOME'])
                (home / '.kube').mkdir(mode=0o700)
                (home / '.kube/kuberc').write_text(
                    'defaults:\n- command: apply\n  options:\n'
                    '    dry-run: server\n',
                    encoding='utf-8',
                )
                environment['FAKE_HOSTILE_KUBERC_MODE'] = mode

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(
                    'kuberc-injected',
                    command_log.read_text(encoding='utf-8'),
                )

    def test_apply_regates_helm_and_cluster_immediately_before_install(self) -> None:
        for race in ('helm', 'release'):
            with self.subTest(race=race):
                environment, _, command_log, _ = self.make_environment()
                Path(environment['FAKE_GATEWAY_MARKER']).touch()
                environment['FAKE_PRE_HELM_RACE'] = race
                environment['FAKE_PRE_HELM_RACE_COUNT'] = '3'

                result = self.run_stage(environment, '--apply')

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn('malicious-helm-executed', commands)
                self.assertNotIn(' install cilium ', commands)

    def test_rejects_invalid_helm_list_contract(self) -> None:
        base = {
            'name': 'cilium',
            'namespace': 'kube-system',
            'revision': '1',
            'updated': '2026-08-10 00:00:00.000000000 +0000 UTC',
            'status': 'deployed',
            'chart': 'cilium-1.20.0',
            'app_version': '1.20.0',
        }
        for mutation in ('revision-type', 'updated-empty', 'extra-field'):
            with self.subTest(mutation=mutation):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                release = dict(base)
                if mutation == 'revision-type':
                    release['revision'] = 1
                elif mutation == 'updated-empty':
                    release['updated'] = ''
                else:
                    release['unapproved'] = 'value'
                environment['FAKE_HELM_LIST_JSON'] = json.dumps([release])

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_rejects_official_cilium_workload_identity_drift(self) -> None:
        for component, key in (
            ('agent', 'app.kubernetes.io/name'),
            ('operator', 'io.cilium/app'),
        ):
            with self.subTest(component=component):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                workload = Path(environment['FAKE_CILIUM_EXACT_JSON'])
                payload = json.loads(workload.read_text(encoding='utf-8'))
                for item in payload['items']:
                    item['metadata']['labels'][
                        'app.kubernetes.io/version'
                    ] = '1.20.0'
                index = 0 if component == 'agent' else 1
                payload['items'][index]['metadata']['labels'][key] = 'drift'
                workload.write_text(json.dumps(payload), encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_accepts_digest_pinned_values(self) -> None:
        environment, _, _, values = self.make_environment()
        values.write_text(self.desired_values, encoding='utf-8')

        pinned_result = self.run_stage(environment, '--apply')

        self.assertEqual(pinned_result.returncode, 0, pinned_result.stderr)
        self.assertIn('RESULT=PASS_CILIUM_INSTALLED', pinned_result.stdout)

    def test_rejects_unpinned_cilium_workload_images(self) -> None:
        for component in ('agent', 'operator'):
            with self.subTest(component=component):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                workload = Path(environment['FAKE_CILIUM_EXACT_JSON'])
                payload = json.loads(workload.read_text(encoding='utf-8'))
                index = 0 if component == 'agent' else 1
                payload['items'][index]['spec']['template']['spec'][
                    'containers'
                ][0]['image'] = (
                    'quay.io/cilium/cilium:v1.20.0'
                    if component == 'agent'
                    else 'quay.io/cilium/operator-generic:v1.20.0'
                )
                workload.write_text(json.dumps(payload), encoding='utf-8')

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_requires_exact_envoy_dataplane_and_cilium_config(self) -> None:
        cases = (
            ('envoy-daemonset-label', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-daemonset-image', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-daemonset-not-ready', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-pod-label', 'FAKE_ENVOY_PODS_JSON'),
            ('envoy-pod-image', 'FAKE_ENVOY_PODS_JSON'),
            ('envoy-pod-not-ready', 'FAKE_ENVOY_PODS_JSON'),
            ('cilium-config-missing', 'FAKE_CILIUM_CONFIG_JSON'),
            ('cilium-config-drift', 'FAKE_CILIUM_CONFIG_JSON'),
            ('query-failure', ''),
        )
        for case, variable in cases:
            with self.subTest(case=case):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                if case == 'query-failure':
                    environment['FAKE_CILIUM_MANAGED_QUERY_FAIL'] = (
                        'daemonset/cilium-envoy'
                    )
                else:
                    payload = json.loads(environment[variable])
                    item = (
                        payload['items'][0]
                        if variable == 'FAKE_ENVOY_PODS_JSON'
                        else payload
                    )
                    if case.endswith('-label'):
                        item['metadata']['labels']['helm.sh/chart'] = 'drift'
                    elif case.endswith('-image'):
                        containers = (
                            item['spec']['containers']
                            if variable == 'FAKE_ENVOY_PODS_JSON'
                            else item['spec']['template']['spec']['containers']
                        )
                        containers[0]['image'] = 'quay.io/cilium/cilium-envoy:mutable'
                    elif case == 'envoy-daemonset-not-ready':
                        item['status']['numberReady'] = 0
                    elif case == 'envoy-pod-not-ready':
                        item['status']['conditions'][0]['status'] = 'False'
                    elif case == 'cilium-config-missing':
                        del payload['data']['enable-gateway-api']
                    elif case == 'cilium-config-drift':
                        payload['data']['cgroup-root'] = '/unapproved'
                    environment[variable] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)

    def test_queries_exact_deployed_helm_user_values(self) -> None:
        environment, host, command_log, _ = self.make_environment()
        self.install_full_cluster_contract(environment, host)

        exact_result = self.run_stage(environment)

        self.assertEqual(exact_result.returncode, 0, exact_result.stderr)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            ' get values cilium --namespace kube-system --revision 1 '
            '--output json\n',
            commands,
        )
        self.assertNotIn(' get values cilium --all', commands)

    def test_rejects_deployed_helm_user_values_drift(self) -> None:
        for case in (
            'missing', 'extra', 'wrong-type', 'wrong-value', 'duplicate-key',
            'nan', 'malformed', 'empty', 'query-failure',
        ):
            with self.subTest(case=case):
                environment, host, command_log, _ = self.make_environment()
                self.install_full_cluster_contract(environment, host)
                payload = json.loads(json.dumps(self.desired_values_object))
                if case == 'missing':
                    del payload['operator']['image']['genericDigest']
                elif case == 'extra':
                    payload['unapproved'] = self.canary
                elif case == 'wrong-type':
                    payload['k8sServicePort'] = '6443'
                elif case == 'wrong-value':
                    payload['k8sServiceHost'] = '192.0.2.11'
                raw = json.dumps(payload)
                if case == 'duplicate-key':
                    raw = raw.replace(
                        '"kubeProxyReplacement": true',
                        '"kubeProxyReplacement": true, '
                        '"kubeProxyReplacement": true',
                        1,
                    )
                elif case == 'nan':
                    raw = raw.replace('"k8sServicePort": 6443', '"k8sServicePort": NaN')
                elif case == 'malformed':
                    raw = '{'
                elif case == 'empty':
                    raw = ''
                elif case == 'query-failure':
                    environment['FAKE_HELM_VALUES_FAIL'] = '1'
                environment['FAKE_HELM_VALUES_JSON'] = raw

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 30, result.stderr)
                self.assertIn('RESULT=STOP_UNKNOWN_STATE', result.stdout)
                self.assertNotIn(self.canary, result.stdout + result.stderr)
                commands = command_log.read_text(encoding='utf-8')
                self.assertNotIn(' apply ', commands)
                self.assertNotIn(' install ', commands)


class FinalVerifyTest(BootstrapTestCase):
    canary = 'SECRET_CANARY_FINAL_VERIFY_DO_NOT_LOG'
    endpoint = 'unix:///run/containerd/containerd.sock'
    gateway_names = CiliumInstallTest.gateway_names
    cilium_image = CiliumInstallTest.cilium_image
    operator_image = CiliumInstallTest.operator_image
    envoy_image = CiliumInstallTest.envoy_image
    desired_values_object = CiliumInstallTest.desired_values_object
    # 已安装 Cilium 由 agent 写入的 CNI 插件（Stage 90 运行时默认已存在）。
    cilium_cni_record = ('cilium-cni', '755', '17270840', '6b7c1300294f522f5731629c9c53c756c2c55f6aace656fe08e95418769796ce')
    cni_records = (
        ('LICENSE', '644', '11357', 'b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1'),
        ('README.md', '644', '2343', '43c32d29316a4a9fe23af500917bd89e51d6a84fa0dcbfcc75b5fbd834c3145a'),
        ('bandwidth', '755', '5042926', '01c59cee777ade0608361d94bf3bfe01bda82bc8da276d8be917e225aa660639'),
        ('bridge', '755', '5698763', '3553f5e8f47ed62aec728ab6f7444f6bf1624f916769852c6deb52cd216e22ba'),
        ('dhcp', '755', '13725422', 'bf0552ff2ef54fbd8846b21ffe149f4de63dcd98d86d6b91de5e0bd94473870d'),
        ('dummy', '755', '5251069', '88f9c9d018681a2b806db2c33184a0a4a532773cb71a60e975a9bf2f017199f6'),
        ('firewall', '755', '5702145', 'ecbd112d77192a125e85ab1fa4ded6cfaf4e9732172e072ee248caa81eba7aed'),
        ('host-device', '755', '5159967', 'a891bd77c5e25b6c4dfa65c8b78cf7f0a00be5ba5d5bbeccd902c08d7f0ea7f3'),
        ('host-local', '755', '4350778', 'ac5ff19b1120bd1d58203b20d45165f244691fcf9776ba55d6dd1747f043c90f'),
        ('ipvlan', '755', '5274322', '40ceded59770a0f28e7a45a0ed5f8c49044e786bc728f34d6c9de7bc5d3fb660'),
        ('loopback', '755', '4302030', '02956bdd03b9b71693b3efd72afce88384e4472b644a1c6410fe817f618c1a83'),
        ('macvlan', '755', '5307111', '33d2730d229dea786c56465a1a96db84ca27b3d5ac552bbc9aa5cdc942622814'),
        ('portmap', '755', '5108385', '10cc11a28d9c16465889eb59968be76cf04fa884939edf70c27b722cec2c0156'),
        ('ptp', '755', '5475470', '1cbbce28e96accfef5fe6021762a55ad2b114705f410b8837361a201df6c0b03'),
        ('sbr', '755', '4525826', 'bb886c24182afbad535f158b585524b08a9f1cf0618679987d6b0e11ebf50bb5'),
        ('static', '755', '3776708', '7bf980bedb303f6d314239413fd4aca5479a9affcd38509057ae203b0da67058'),
        ('tap', '755', '5453308', 'ebff11573fa4ed5793cc08776b8811a3c0f44705b2b530fd5014e6bf69275c1a'),
        ('tuning', '755', '4389084', '4659e9129d8c669c21c932cd778dc1ac17a717d100768ea23242883401cbb536'),
        ('vlan', '755', '5267679', '5f6973d15ad2b0d44d1dc0e59982ed05e34e4709630ecd367f766202f9034ac8'),
        ('vrf', '755', '4685012', '3f3363182c4777bd0d3ead028147f9ecebd60bb32f2d47b7c181877a00ae049b'),
    )

    def write_executable(self, path: Path, source: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        path.chmod(0o755)

    def helm_member(self) -> bytes:
        return textwrap.dedent(
            '''
            #!/usr/bin/python3 -B
            import os
            from pathlib import Path
            import signal
            import sys
            import time

            args = sys.argv[1:]
            with open(os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8') as log:
                log.write('helm ' + ' '.join(args) + '\\n')
            sys.stderr.write(os.environ['FAKE_CANARY'] + '\\n')
            if (
                os.environ.get('FAKE_SIMULATE_CLIENT_CACHE', '0') == '1'
                and os.environ.get('KUBECACHEDIR') != '/dev/null'
            ):
                cache = Path(os.environ['HOME']) / '.kube/cache/helm-write'
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text('cache\\n', encoding='utf-8')
            if args == ['version', '--short']:
                print(os.environ.get('FAKE_HELM_VERSION', 'v3.21.0+gfixture'))
                raise SystemExit(0)
            if len(args) < 2 or args[0] != '--kubeconfig':
                raise SystemExit(64)
            try:
                supplied = Path(args[1]).read_text(encoding='utf-8')
                # 真实 helm/client-go 会多次加载 kubeconfig；管道第二次读到空。
                supplied_again = Path(args[1]).read_text(encoding='utf-8')
            except OSError:
                raise SystemExit(64)
            if supplied != os.environ['FAKE_ADMIN_CONF_CONTENT'] or supplied_again != supplied:
                raise SystemExit(64)
            if os.environ.get('FAKE_HELM_KILL_PARENT', '0') == '1':
                # 模拟运维中断：kubeconfig 临时目录还在时杀掉调用 stage 的 shell。
                os.kill(os.getppid(), signal.SIGTERM)
                time.sleep(0.5)
                raise SystemExit(0)
            expected = [
                '--kubeconfig', args[1],
                'list', '--all-namespaces', '--all', '--output', 'json',
            ]
            if args == expected:
                if os.environ.get('FAKE_HELM_LIST_FAIL', '0') == '1':
                    raise SystemExit(1)
                print(os.environ['FAKE_HELM_LIST_JSON'])
                raise SystemExit(0)
            values = [
                '--kubeconfig', args[1],
                'get', 'values', 'cilium', '--namespace', 'kube-system',
                '--revision', '1', '--output', 'json',
            ]
            if args == values:
                if os.environ.get('FAKE_HELM_VALUES_FAIL', '0') == '1':
                    raise SystemExit(1)
                sys.stdout.write(os.environ['FAKE_HELM_VALUES_JSON'])
                raise SystemExit(0)
            raise SystemExit(64)
            '''
        ).lstrip().encode()

    def helm_archive(self, member: bytes) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            entry = tarfile.TarInfo('linux-amd64/helm')
            entry.mode = 0o755
            entry.size = len(member)
            archive.addfile(entry, io.BytesIO(member))
        return stream.getvalue()

    def helm_list_json(self, **overrides: object) -> str:
        release: dict[str, object] = {
            'name': 'cilium',
            'namespace': 'kube-system',
            'revision': '1',
            'updated': '2026-08-10 00:00:00.000000000 +0000 UTC',
            'status': 'deployed',
            'chart': 'cilium-1.20.0',
            'app_version': '1.20.0',
        }
        release.update(overrides)
        return json.dumps([release])

    def gateway_bundle_json(self, *, partial: bool = False) -> str:
        annotations = {
            'gateway.networking.k8s.io/bundle-version': 'v1.6.1',
            'gateway.networking.k8s.io/channel': 'standard',
        }
        crd_annotations = {
            'api-approved.kubernetes.io': (
                'https://github.com/kubernetes-sigs/gateway-api/pull/4530'
            ),
            **annotations,
        }
        items: list[dict[str, object]] = [
            {
                'apiVersion': 'apiextensions.k8s.io/v1',
                'kind': 'CustomResourceDefinition',
                'metadata': {
                    'name': name,
                    'annotations': dict(crd_annotations),
                },
            }
            for name in self.gateway_names
        ]
        items.extend(
            [
                {
                    'apiVersion': 'admissionregistration.k8s.io/v1',
                    'kind': 'ValidatingAdmissionPolicy',
                    'metadata': {
                        'name': 'safe-upgrades.gateway.networking.k8s.io',
                        'annotations': dict(annotations),
                    },
                    'status': {'typeChecking': {'expressionWarnings': []}},
                },
                {
                    'apiVersion': 'admissionregistration.k8s.io/v1',
                    'kind': 'ValidatingAdmissionPolicyBinding',
                    'metadata': {
                        'name': 'safe-upgrades.gateway.networking.k8s.io',
                        'annotations': dict(annotations),
                    },
                    'spec': {'validationActions': ['Deny']},
                },
            ]
        )
        if partial:
            items.pop(0)
        return json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items})

    def release_json(self) -> str:
        return json.dumps(
            {
                'apiVersion': 'v1',
                'kind': 'List',
                'items': [
                    {
                        'apiVersion': 'v1',
                        'kind': 'Secret',
                        'metadata': {
                            'name': 'sh.helm.release.v1.cilium.v1',
                            'namespace': 'kube-system',
                            'labels': {
                                'owner': 'helm',
                                'name': 'cilium',
                                'status': 'deployed',
                                'version': '1',
                                'modifiedAt': '1786320001',
                            },
                        },
                        'type': 'helm.sh/release.v1',
                        'data': {'release': 'SECRET_HELM_RELEASE_PAYLOAD'},
                    }
                ],
            }
        )

    def cilium_daemonset_json(self, *, ready: bool = True) -> str:
        return json.dumps(
            {
                'apiVersion': 'apps/v1',
                'kind': 'DaemonSet',
                'metadata': {
                    'name': 'cilium',
                    'namespace': 'kube-system',
                    'labels': {
                        'k8s-app': 'cilium',
                        'app.kubernetes.io/name': 'cilium-agent',
                        'app.kubernetes.io/part-of': 'cilium',
                        'helm.sh/chart': 'cilium-1.20.0',
                    },
                },
                'spec': {
                    'template': {
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-agent',
                                    'image': self.cilium_image,
                                }
                            ]
                        }
                    }
                },
                'status': {
                    'desiredNumberScheduled': 1,
                    'numberReady': 1 if ready else 0,
                    'numberAvailable': 1 if ready else 0,
                    'numberUnavailable': 0 if ready else 1,
                },
            }
        )

    def pod_list_json(self, name: str, *, ready: bool = True) -> str:
        labels = (
            {
                'k8s-app': 'cilium',
                'app.kubernetes.io/name': 'cilium-agent',
                'app.kubernetes.io/part-of': 'cilium',
                'helm.sh/chart': 'cilium-1.20.0',
                'controller-revision-hash': 'fixture-hash',
            }
            if name == 'cilium-fixture'
            else {
                'io.cilium/app': 'operator',
                'name': 'cilium-operator',
                'app.kubernetes.io/name': 'cilium-operator',
                'app.kubernetes.io/part-of': 'cilium',
                'helm.sh/chart': 'cilium-1.20.0',
                'pod-template-hash': 'fixture-hash',
            }
        )
        return json.dumps(
            {
                'apiVersion': 'v1',
                'kind': 'List',
                'items': [
                    {
                        'apiVersion': 'v1',
                        'kind': 'Pod',
                        'metadata': {
                            'name': name,
                            'namespace': 'kube-system',
                            'labels': labels,
                        },
                        'spec': {
                            'containers': [
                                {
                                    'name': (
                                        'cilium-agent'
                                        if name == 'cilium-fixture'
                                        else 'cilium-operator'
                                    ),
                                    'image': (
                                        self.cilium_image
                                        if name == 'cilium-fixture'
                                        else self.operator_image
                                    ),
                                }
                            ]
                        },
                        'status': {
                            'phase': 'Running' if ready else 'Pending',
                            'conditions': [
                                {
                                    'type': 'Ready',
                                    'status': 'True' if ready else 'False',
                                }
                            ],
                            'containerStatuses': [{'ready': ready}],
                        },
                    }
                ],
            }
        )

    def operator_json(self, *, ready: bool = True) -> str:
        return json.dumps(
            {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'metadata': {
                    'name': 'cilium-operator',
                    'namespace': 'kube-system',
                    'labels': {
                        'io.cilium/app': 'operator',
                        'name': 'cilium-operator',
                        'app.kubernetes.io/name': 'cilium-operator',
                        'app.kubernetes.io/part-of': 'cilium',
                        'helm.sh/chart': 'cilium-1.20.0',
                    },
                },
                'spec': {
                    'replicas': 1,
                    'template': {
                        'spec': {
                            'containers': [
                                {
                                    'name': 'cilium-operator',
                                    'image': self.operator_image,
                                }
                            ]
                        }
                    },
                },
                'status': {
                    'replicas': 1,
                    'updatedReplicas': 1,
                    'readyReplicas': 1 if ready else 0,
                    'availableReplicas': 1 if ready else 0,
                    'unavailableReplicas': 0 if ready else 1,
                },
            }
        )

    def envoy_daemonset_json(self, *, ready: bool = True) -> str:
        return CiliumInstallTest.envoy_daemonset_json(self, ready=ready)

    def envoy_pods_json(self, *, ready: bool = True) -> str:
        return CiliumInstallTest.envoy_pods_json(self, ready=ready)

    @staticmethod
    def cilium_config_json() -> str:
        return CiliumInstallTest.cilium_config_json()

    def node_json(
        self,
        *,
        ready: bool = True,
        name: str = 'example-node',
        ip: str = '192.0.2.10',
    ) -> str:
        return json.dumps(
            {
                'apiVersion': 'v1',
                'kind': 'List',
                'items': [
                    {
                        'apiVersion': 'v1',
                        'kind': 'Node',
                        'metadata': {'name': name},
                        'status': {
                            'conditions': [
                                {
                                    'type': 'Ready',
                                    'status': 'True' if ready else 'False',
                                }
                            ],
                            'addresses': [
                                {'type': 'InternalIP', 'address': ip},
                                {'type': 'Hostname', 'address': name},
                            ],
                        },
                    }
                ],
            }
        )

    def cri_json(
        self, *, ready: object = True, network_ready: object = True
    ) -> str:
        return json.dumps(
            {
                'status': {
                    'conditions': [
                        {'type': 'RuntimeReady', 'status': ready},
                        {'type': 'NetworkReady', 'status': network_ready},
                    ]
                },
                'config': {
                    'containerd': {
                        'defaultRuntimeName': 'runc',
                        'runtimes': {
                            'runc': {
                                'runtimeType': 'io.containerd.runc.v2',
                                'options': {'SystemdCgroup': True},
                            }
                        },
                    }
                },
            }
        )

    def csr_json(self, **overrides: object) -> str:
        spec: dict[str, object] = {
            'signerName': 'kubernetes.io/kubelet-serving',
            'username': 'system:node:example-node',
            # 服务器实测：ECDSA serving 证书不请求 key encipherment。
            'usages': ['server auth', 'digital signature'],
            'request': 'ZmFrZS1jc3ItcmVxdWVzdA==',
        }
        spec.update(overrides)
        return json.dumps(
            {
                'apiVersion': 'certificates.k8s.io/v1',
                'kind': 'CertificateSigningRequestList',
                'items': [
                    {
                        'apiVersion': 'certificates.k8s.io/v1',
                        'kind': 'CertificateSigningRequest',
                        'metadata': {
                            'name': 'csr-serving-fixture',
                            'creationTimestamp': '2026-08-10T00:00:00Z',
                        },
                        'spec': spec,
                        'status': {
                            'certificate': 'SECRET_CERTIFICATE_CANARY',
                            'conditions': [{'reason': 'SECRET_CONDITION_CANARY'}],
                        },
                    }
                ],
            }
        )

    def make_environment(self) -> tuple[dict[str, str], Path, Path]:
        directory = self.temporary_directory()
        host = directory / 'host'
        home = directory / 'home'
        fake_bin = directory / 'bin'
        command_log = directory / 'commands.log'
        staging = host / 'root/dev-infra-artifacts/pcs-2026-08-10.1'
        for path in (
            host / 'root/dev-infra-evidence', host / 'etc/kubernetes',
            host / 'usr/bin', host / 'usr/sbin', host / 'usr/local/bin',
            host / 'usr/local/sbin', host / 'usr/local/lib/systemd/system',
            host / 'etc/containerd', host / 'var/lib/containerd',
            host / 'run/containerd', host / 'opt/cni/bin', staging, fake_bin,
            home,
        ):
            path.mkdir(parents=True, exist_ok=True)
        for path, mode in (
            (host / 'root', 0o700),
            (host / 'root/dev-infra-artifacts', 0o700),
            (staging, 0o700),
            (host / 'usr', 0o755),
            (host / 'usr/local', 0o755),
            (host / 'usr/local/bin', 0o755),
            (host / 'opt', 0o755),
            (host / 'opt/cni', 0o755),
            (host / 'opt/cni/bin', 0o755),
            (host / 'var/lib/containerd', 0o700),
            (host / 'run/containerd', 0o711),
        ):
            path.chmod(mode)

        helm_member = self.helm_member()
        helm_archive = staging / 'helm-v3.21.0-linux-amd64.tar.gz'
        helm_archive.write_bytes(self.helm_archive(helm_member))
        helm_archive.chmod(0o600)
        helm_binary = host / 'usr/local/bin/helm'
        helm_binary.write_bytes(helm_member)
        helm_binary.chmod(0o755)
        gateway_manifest = staging / 'standard-install.yaml'
        gateway_manifest.write_text('gateway v1.6.1 fixture\n', encoding='utf-8')
        gateway_manifest.chmod(0o600)
        admin_conf = host / 'etc/kubernetes/admin.conf'
        admin_conf.write_text(self.canary + '\n', encoding='utf-8')
        admin_conf.chmod(0o600)
        swap_file = host / 'swap.img'
        swap_file.write_text('swap fixture\n', encoding='utf-8')
        swap_file.chmod(0o600)

        cni_manifest = directory / 'cni-manifest.tsv'
        cni_manifest.write_text(
            ''.join('\t'.join(record) + '\n' for record in (*self.cni_records, self.cilium_cni_record)),
            encoding='utf-8',
        )
        for name, mode, _, _ in (*self.cni_records, self.cilium_cni_record):
            target = host / 'opt/cni/bin' / name
            target.write_text(name + '\n', encoding='utf-8')
            target.chmod(int(mode, 8))

        runtime_targets = (
            (
                host / 'usr/local/bin/containerd',
                ContainerdInstallTest.containerd_version,
                0o755,
            ),
            (
                host / 'usr/local/bin/ctr',
                ContainerdInstallTest.ctr_binary,
                0o755,
            ),
            (
                host / 'usr/local/bin/containerd-shim-runc-v2',
                ContainerdInstallTest.shim_binary,
                0o755,
            ),
            (
                host / 'usr/local/sbin/runc',
                ContainerdInstallTest.runc_binary,
                0o755,
            ),
            (
                host / 'etc/containerd/config.toml',
                (ROOT / 'bootstrap/containerd/config.toml').read_bytes(),
                0o644,
            ),
            (
                host / 'usr/local/lib/systemd/system/containerd.service',
                (ROOT / 'bootstrap/containerd/containerd.service').read_bytes(),
                0o644,
            ),
        )
        for target, content, mode in runtime_targets:
            target.write_bytes(content)
            target.chmod(mode)
        cri_socket = host / 'run/containerd/containerd.sock'
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(cri_socket))
        listener.close()
        cri_socket.chmod(0o660)

        self.write_executable(fake_bin / 'id', '#!/bin/sh\nprintf "0\\n"\n')
        self.write_executable(
            fake_bin / 'hostname',
            '#!/bin/sh\nprintf "%s\\n" "${FAKE_HOSTNAME:-example-node}"\n',
        )
        hosts_root = directory / 'hosts'
        hosts_root.mkdir()
        self.write_fixture_host(hosts_root)
        self.write_executable(
            fake_bin / 'systemctl',
            '''
            #!/bin/sh
            printf 'systemctl %s\n' "$*" >>"$FAKE_COMMAND_LOG"
            case "$1" in
              show)
                [ "$*" = "show --all --property=LoadState --property=FragmentPath --property=DropInPaths containerd.service" ] || exit 64
                if [ "${FAKE_CONTAINERD_UNIT_STATE:-loaded}" = missing ]; then
                  printf 'LoadState=not-found\nFragmentPath=\nDropInPaths=\n'
                else
                  printf 'LoadState=loaded\nFragmentPath=%s\nDropInPaths=\n' "$FAKE_CONTAINERD_UNIT"
                fi
                ;;
              is-enabled)
                [ "${FAKE_CONTAINERD_SERVICE_ENABLED:-1}" = 1 ]
                ;;
              is-active)
                [ "${FAKE_CONTAINERD_SERVICE_ACTIVE:-1}" = 1 ] && printf 'active\n'
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg-query',
            '''
            #!/bin/sh
            if [ -n "${FAKE_RESTORE_CRICTL_SOURCE:-}" ]; then
              /bin/cp "$FAKE_RESTORE_CRICTL_SOURCE" "$FAKE_RESTORE_CRICTL_TARGET"
              chmod 0755 "$FAKE_RESTORE_CRICTL_TARGET"
              unset FAKE_RESTORE_CRICTL_SOURCE
            fi
            if [ "$1" = -W ]; then
              for package in kubeadm kubectl kubelet kubernetes-cni; do
                version=1.36.3-1.1
                [ "$package" != kubernetes-cni ] || version=1.9.1-1.1
                [ "${FAKE_PACKAGE_DRIFT:-}" != "$package" ] || version=0.0.0-0
                printf '%s\\tamd64\\thold\\tinstalled\\t%s\\n' "$package" "$version"
              done
              [ "${FAKE_EXTRA_HOLD:-0}" != 1 ] || printf 'unapproved\\tamd64\\thold\\tinstalled\\t1\\n'
              exit 0
            fi
            [ "$1" = -S ] || exit 64
            logical=$2
            case "$logical" in
              /usr/bin/kubeadm) package=kubeadm ;;
              /usr/bin/kubectl) package=kubectl ;;
              /usr/bin/kubelet) package=kubelet ;;
              /opt/cni/bin/cilium-cni)
                [ "${FAKE_CILIUM_CNI_OWNED:-0}" = 1 ] || exit 1
                package=kubernetes-cni
                ;;
              /opt/cni/bin/*) package=kubernetes-cni ;;
              *) exit 1 ;;
            esac
            [ "${FAKE_OWNER_DRIFT:-}" != "$logical" ] || package=unapproved
            printf '%s: %s\\n' "$package" "$logical"
            ''',
        )
        self.write_executable(
            fake_bin / 'dpkg',
            '''
            #!/bin/sh
            [ "$1" = --verify ] || exit 64
            case "$2" in kubeadm|kubectl|kubelet|kubernetes-cni) ;; *) exit 64 ;; esac
            if [ "${FAKE_VERIFY_DOC_EXCLUDES:-0}" = 1 ]; then
              case "${FAKE_VERIFY_DOC_SHAPE:-exact}" in
                exact)
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\\n' "$2"
                  ;;
                single)
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  ;;
                duplicate)
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\\n' "$2"
                  ;;
                other-package)
                  printf 'missing     /usr/share/doc/unapproved/LICENSE\\n'
                  printf 'missing     /usr/share/doc/%s/README.md\\n' "$2"
                  ;;
                extra-missing)
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\\n' "$2"
                  printf 'missing     /usr/bin/%s\\n' "$2"
                  ;;
                checksum)
                  printf '??5??????   /usr/bin/%s\\n' "$2"
                  ;;
                nonzero)
                  printf 'missing     /usr/share/doc/%s/LICENSE\\n' "$2"
                  printf 'missing     /usr/share/doc/%s/README.md\\n' "$2"
                  exit 1
                  ;;
                *) exit 64 ;;
              esac
              exit 0
            fi
            [ "${FAKE_VERIFY_DRIFT:-}" != "$2" ] || printf '??5?????? /unapproved\\n'
            ''',
        )
        self.write_executable(
            fake_bin / 'sha256sum',
            '''
            #!/bin/sh
            if [ "$#" -eq 0 ]; then
              exec /usr/bin/shasum -a 256
            fi
            path=$1
            if [ "${path##*/}" = helm-v3.21.0-linux-amd64.tar.gz ]; then
              digest=0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36
              [ "${FAKE_HELM_ARCHIVE_DIGEST_DRIFT:-0}" != 1 ] || digest=0000000000000000000000000000000000000000000000000000000000000000
            elif [ "${path##*/}" = standard-install.yaml ]; then
              digest=24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73
            else
              digest=$(awk -F '\\t' -v name="${path##*/}" '$1 == name {print $4}' "$FAKE_CNI_MANIFEST")
            fi
            [ -n "$digest" ] || exec /usr/bin/shasum -a 256 "$path"
            [ "${FAKE_CNI_DIGEST_DRIFT:-}" != "${path##*/}" ] || digest=0000000000000000000000000000000000000000000000000000000000000000
            printf '%s  %s\\n' "$digest" "$path"
            ''',
        )
        self.write_executable(
            fake_bin / 'stat',
            '''
            #!/bin/sh
            if [ "$1" = -c ] && [ "$2" = %s ] && [ "${3#${FAKE_CNI_ROOT}/}" != "$3" ]; then
              size=$(awk -F '\\t' -v name="${3##*/}" '$1 == name {print $3}' "$FAKE_CNI_MANIFEST")
              [ -n "$size" ] || exit 1
              printf '%s\\n' "$size"
              exit 0
            fi
            exec /usr/bin/stat "$@"
            ''',
        )
        self.write_executable(
            fake_bin / 'swapon',
            '''
            #!/bin/sh
            [ "${FAKE_SWAP_FAIL:-0}" != 1 ] || exit 1
            if [ "$#" = 4 ] &&
               [ "$1" = '--show=NAME,SIZE' ] &&
               [ "$2" = --noheadings ] &&
               [ "$3" = --raw ] &&
               [ "$4" = --bytes ]; then
              :
            elif [ "$#" = 5 ] &&
                 [ "$1" = --show ] &&
                 [ "$2" = --noheadings ] &&
                 [ "$3" = --bytes ] &&
                 [ "$4" = --output ] &&
                 [ "$5" = NAME,SIZE ]; then
              if [ "${FAKE_SWAPON_UTIL_LINUX_239:-0}" = 1 ]; then
                printf '/swap.img file 4106219520    0   -2 fixture-uuid \n'
                exit 0
              fi
            else
              exit 64
            fi
            if [ "${FAKE_SWAP_OUTPUT+x}" = x ]; then
              printf '%s\\n' "$FAKE_SWAP_OUTPUT"
            else
              printf '/swap.img 4200000000\\n'
            fi
            ''',
        )
        self.write_executable(
            fake_bin / 'openssl',
            '''
            #!/bin/sh
            printf 'openssl %s\\n' "$*" >>"$FAKE_COMMAND_LOG"
            /bin/cat >/dev/null
            [ "${FAKE_OPENSSL_FAIL:-0}" != 1 ] || exit 1
            printf 'Certificate Request:\\n'
            printf '    X509v3 Subject Alternative Name:\\n'
            printf '        %s\\n' "${FAKE_CSR_SAN:-DNS:example-node, IP Address:192.0.2.10}"
            ''',
        )
        self.write_executable(
            host / 'usr/bin/openssl',
            (fake_bin / 'openssl').read_text(encoding='utf-8'),
        )
        self.write_executable(
            host / 'usr/bin/kubeadm',
            '''
            #!/bin/sh
            printf 'kubeadm %s\\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "$*" = "version -o short" ] || exit 64
            printf '%s\\n' "${FAKE_KUBEADM_VERSION:-v1.36.3}"
            ''',
        )
        self.write_executable(
            host / 'usr/bin/kubelet',
            '''
            #!/bin/sh
            printf 'kubelet %s\\n' "$*" >>"$FAKE_COMMAND_LOG"
            [ "$*" = --version ] || exit 64
            printf '%s\\n' "${FAKE_KUBELET_VERSION:-Kubernetes v1.36.3}"
            ''',
        )
        self.write_executable(
            host / 'usr/local/bin/crictl',
            '''
            #!/bin/sh
            printf 'crictl %s\\n' "$*" >>"$FAKE_COMMAND_LOG"
            printf '%s\\n' "$FAKE_CANARY" >&2
            case "$*" in
              --version) printf '%s\\n' "${FAKE_CRICTL_VERSION:-crictl version v1.36.0}" ;;
              "--runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info --output json")
                [ "${FAKE_CRICTL_FAIL:-0}" != 1 ] || exit 1
                printf '%s\\n' "$FAKE_CRI_JSON"
                ;;
              *) exit 64 ;;
            esac
            ''',
        )
        self.write_executable(
            host / 'usr/bin/kubectl',
            '''
            #!/usr/bin/python3 -B
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with open(os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8') as log:
                log.write('kubectl ' + ' '.join(args) + '\\n')
            sys.stderr.write(os.environ['FAKE_CANARY'] + '\\n')
            if (
                os.environ.get('FAKE_SIMULATE_CLIENT_CACHE', '0') == '1'
                and '--cache-dir=/dev/null' not in args
            ):
                cache = Path(os.environ['HOME']) / '.kube/cache/kubectl-write'
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text('cache\\n', encoding='utf-8')
            hostile_kuberc = (
                (Path(os.environ['HOME']) / '.kube/kuberc').exists()
                and os.environ.get('KUBECTL_KUBERC') != 'false'
                and os.environ.get('FAKE_HOSTILE_KUBERC_MODE', '')
            )
            if len(args) < 2 or args[0] != '--kubeconfig':
                raise SystemExit(64)
            try:
                supplied = Path(args[1]).read_text(encoding='utf-8')
            except OSError:
                raise SystemExit(64)
            if supplied != os.environ['FAKE_ADMIN_CONF_CONTENT']:
                raise SystemExit(64)
            prefix = ['--kubeconfig', args[1]]
            safe_prefix = prefix + ['--cache-dir=/dev/null']
            if args[:3] == safe_prefix:
                command = args[3:]
            elif args[:2] == prefix:
                command = args[2:]
            else:
                raise SystemExit(64)
            if hostile_kuberc:
                with open(
                    os.environ['FAKE_COMMAND_LOG'], 'a', encoding='utf-8'
                ) as log:
                    log.write('kuberc-injected query\\n')
                raise SystemExit(64)

            if command == [
                'config', 'view', '--raw', '--merge=false', '--output=json',
            ]:
                if os.environ.get('FAKE_ADMIN_VIEW_FAIL', '0') == '1':
                    raise SystemExit(1)
                if os.environ.get('FAKE_ADMIN_SOURCE_RACE', '0') == '1':
                    Path(os.environ['FAKE_ADMIN_CONF']).write_text(
                        'raced-admin-config\\n', encoding='utf-8'
                    )
                sys.stdout.write(os.environ['FAKE_ADMIN_VIEW_JSON'])
                raise SystemExit(0)

            gateway_names = [
                'backendtlspolicies.gateway.networking.k8s.io',
                'gatewayclasses.gateway.networking.k8s.io',
                'gateways.gateway.networking.k8s.io',
                'grpcroutes.gateway.networking.k8s.io',
                'httproutes.gateway.networking.k8s.io',
                'listenersets.gateway.networking.k8s.io',
                'referencegrants.gateway.networking.k8s.io',
                'tcproutes.gateway.networking.k8s.io',
                'tlsroutes.gateway.networking.k8s.io',
                'udproutes.gateway.networking.k8s.io',
            ]
            scoped_gateway = ['get']
            scoped_gateway.extend(
                'customresourcedefinition.apiextensions.k8s.io/' + name
                for name in gateway_names
            )
            scoped_gateway.extend([
                'validatingadmissionpolicy.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io',
                'validatingadmissionpolicybinding.admissionregistration.k8s.io/safe-upgrades.gateway.networking.k8s.io',
                '--ignore-not-found', '--output=json',
            ])
            unscoped_gateway = (
                'get',
                'customresourcedefinitions.apiextensions.k8s.io,validatingadmissionpolicies.admissionregistration.k8s.io,validatingadmissionpolicybindings.admissionregistration.k8s.io',
                '--output=json',
            )

            routes = {
                ('version', '--client=true', '--output=json'): ('version', 'FAKE_KUBECTL_VERSION_JSON'),
                ('config', 'view', '--minify', '--output=jsonpath={.clusters[0].cluster.server}'): ('endpoint', 'FAKE_API_ENDPOINT'),
                ('get', '--raw=/readyz'): ('readyz', 'FAKE_API_READYZ'),
                ('get', 'secrets', '--all-namespaces', '--selector', 'owner=helm', '--output=json'): ('legacy-releases', 'FAKE_LEGACY_RELEASE_JSON'),
                ('get', 'secrets,configmaps', '--all-namespaces', '--selector', 'owner=helm', '--output=json'): ('releases', 'FAKE_RELEASE_JSON'),
                ('get', 'customresourcedefinitions.apiextensions.k8s.io,validatingadmissionpolicies.admissionregistration.k8s.io,validatingadmissionpolicybindings.admissionregistration.k8s.io', '--output=json'): ('gateway', 'FAKE_GATEWAY_JSON'),
                ('--namespace', 'kube-system', 'get', 'daemonset/cilium', '--output=json'): ('cilium-daemonset', 'FAKE_CILIUM_DAEMONSET_JSON'),
                ('--namespace', 'kube-system', 'get', 'pods', '--selector', 'k8s-app=cilium', '--output=json'): ('cilium-pods', 'FAKE_CILIUM_PODS_JSON'),
                ('--namespace', 'kube-system', 'get', 'deployment/cilium-operator', '--output=json'): ('operator', 'FAKE_OPERATOR_JSON'),
                ('--namespace', 'kube-system', 'get', 'pods', '--selector', 'name=cilium-operator', '--output=json'): ('operator-pods', 'FAKE_OPERATOR_PODS_JSON'),
                ('--namespace', 'kube-system', 'get', 'daemonset/cilium-envoy', '--output=json'): ('envoy-daemonset', 'FAKE_ENVOY_DAEMONSET_JSON'),
                ('--namespace', 'kube-system', 'get', 'pods', '--selector', 'k8s-app=cilium-envoy', '--output=json'): ('envoy-pods', 'FAKE_ENVOY_PODS_JSON'),
                ('--namespace', 'kube-system', 'get', 'configmap/cilium-config', '--output=json'): ('cilium-config', 'FAKE_CILIUM_CONFIG_JSON'),
                ('get', 'nodes', '--output=json'): ('nodes', 'FAKE_NODE_JSON'),
                ('get', '--raw=/api/v1/nodes/' + os.environ.get('FAKE_NODE_NAME', 'example-node') + '/proxy/configz'): ('configz', 'FAKE_CONFIGZ_JSON'),
                ('get', 'certificatesigningrequests.certificates.k8s.io', '--output=json'): ('csr', 'FAKE_CSR_JSON'),
            }
            kube_proxy = {
                ('--namespace', 'kube-system', 'get', 'daemonset', 'kube-proxy', '--ignore-not-found', '--output=name'): ('kube-proxy-daemonset', 'FAKE_KUBE_PROXY_DAEMONSET'),
                ('--namespace', 'kube-system', 'get', 'pods', '--selector', 'k8s-app=kube-proxy', '--output=name'): ('kube-proxy-pods', 'FAKE_KUBE_PROXY_PODS'),
                ('--namespace', 'kube-system', 'get', 'configmap', 'kube-proxy', '--ignore-not-found', '--output=name'): ('kube-proxy-configmap', 'FAKE_KUBE_PROXY_CONFIGMAP'),
            }
            key = tuple(command)
            if (
                key == unscoped_gateway
                and os.environ.get('FAKE_REQUIRE_SCOPED_GATEWAY', '0') == '1'
            ):
                raise SystemExit(64)
            if key == tuple(scoped_gateway):
                if os.environ.get('FAKE_KUBECTL_FAIL', '') == 'gateway':
                    raise SystemExit(1)
                sys.stdout.write(os.environ['FAKE_GATEWAY_JSON'])
                raise SystemExit(0)
            if key in kube_proxy:
                route, variable = kube_proxy[key]
                if os.environ.get('FAKE_KUBECTL_FAIL', '') == route:
                    raise SystemExit(1)
                sys.stdout.write(os.environ.get(variable, ''))
                raise SystemExit(0)
            diff = (
                'diff', '--server-side=true',
                '--field-manager=engineering-platform-bootstrap',
                '--filename', os.environ['FAKE_GATEWAY_MANIFEST'],
            )
            if key == diff:
                if os.environ.get('FAKE_KUBECTL_FAIL', '') == 'gateway-diff':
                    raise SystemExit(2)
                raise SystemExit(int(os.environ.get('FAKE_GATEWAY_DIFF_EXIT', '0')))
            if key not in routes:
                raise SystemExit(64)
            route, variable = routes[key]
            if os.environ.get('FAKE_KUBECTL_FAIL', '') == route:
                raise SystemExit(1)
            sys.stdout.write(os.environ[variable])
            raise SystemExit(0)
            ''',
        )
        containerd_archive = ContainerdInstallTest.archive_bytes(
            self,
            [
                (
                    'bin/containerd',
                    (host / 'usr/local/bin/containerd').read_bytes(),
                ),
                ('bin/ctr', (host / 'usr/local/bin/ctr').read_bytes()),
                (
                    'bin/containerd-shim-runc-v2',
                    (host / 'usr/local/bin/containerd-shim-runc-v2').read_bytes(),
                ),
            ],
        )
        crictl_archive = ContainerdInstallTest.archive_bytes(
            self,
            [('crictl', (host / 'usr/local/bin/crictl').read_bytes())],
        )
        cilium_chart = b'cilium chart v1.20.0 fixture\n'
        artifact_specs = (
            (
                'containerd', '2.3.1',
                'https://github.com/containerd/containerd/releases/download/v2.3.1/containerd-2.3.1-linux-amd64.tar.gz',
                containerd_archive, '/usr/local/bin', None,
            ),
            (
                'runc', '1.3.6',
                'https://github.com/opencontainers/runc/releases/download/v1.3.6/runc.amd64',
                (host / 'usr/local/sbin/runc').read_bytes(),
                '/usr/local/sbin/runc', None,
            ),
            (
                'crictl', '1.36.0',
                'https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz',
                crictl_archive, '/usr/local/bin/crictl', None,
            ),
            (
                'helm', '3.21.0',
                'https://get.helm.sh/helm-v3.21.0-linux-amd64.tar.gz',
                helm_archive.read_bytes(), '/usr/local/bin/helm',
                '0093eb572e3d2380f094df162ddb525e219249de88957afe24cfbb19632acd36',
            ),
            (
                'gateway-api', '1.6.1',
                'https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml',
                gateway_manifest.read_bytes(),
                'kubernetes://gateway-api/standard',
                '24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73',
            ),
            (
                'cilium-chart', '1.20.0',
                'https://helm.cilium.io/cilium-1.20.0.tgz',
                cilium_chart, 'kubernetes://kube-system/cilium', None,
            ),
        )
        lock_lines = []
        for name, version, url, content, target, digest_override in artifact_specs:
            artifact = staging / Path(url).name
            artifact.write_bytes(content)
            artifact.chmod(0o600)
            digest = digest_override or hashlib.sha256(content).hexdigest()
            lock_lines.append('\t'.join((name, version, url, digest, target)))
        lock = directory / 'artifacts.lock.tsv'
        approved_lock = directory / 'approved-artifacts.lock.tsv'
        lock_content = '\n'.join(lock_lines) + '\n'
        lock.write_text(lock_content, encoding='utf-8')
        approved_lock.write_text(lock_content, encoding='utf-8')
        crictl_backup = directory / 'crictl.backup'
        crictl_backup.write_bytes((host / 'usr/local/bin/crictl').read_bytes())
        crictl_backup.chmod(0o600)
        environment = self.sanitized_environment()
        environment.update(
            {
                'PATH': f'{fake_bin}:/usr/bin:/bin',
                'HOME': str(home),
                'BOOTSTRAP_TEST_MODE': '1',
                'BOOTSTRAP_TEST_ROOT': str(host),
                'BOOTSTRAP_TEST_HOSTS_DIR': str(hosts_root),
                'BOOTSTRAP_TEST_LOCK_FILE': str(lock),
                'BOOTSTRAP_TEST_APPROVED_LOCK_FILE': str(approved_lock),
                'FAKE_COMMAND_LOG': str(command_log),
                'FAKE_CANARY': self.canary,
                'FAKE_CONTAINERD_UNIT': str(
                    host / 'usr/local/lib/systemd/system/containerd.service'
                ),
                'FAKE_CRICTL_BACKUP': str(crictl_backup),
                'FAKE_RESTORE_CRICTL_TARGET': str(
                    host / 'usr/local/bin/crictl'
                ),
                'FAKE_ADMIN_CONF': str(admin_conf),
                'FAKE_ADMIN_CONF_CONTENT': self.canary + '\n',
                'FAKE_ADMIN_VIEW_JSON': json.dumps(self.admin_config_object()),
                'FAKE_HELM_LIST_JSON': self.helm_list_json(),
                'FAKE_HELM_VALUES_JSON': json.dumps(
                    self.desired_values_object
                ),
                'FAKE_GATEWAY_MANIFEST': str(gateway_manifest),
                'FAKE_CNI_MANIFEST': str(cni_manifest),
                'FAKE_CNI_ROOT': str(host / 'opt/cni/bin'),
                'FAKE_CRI_JSON': self.cri_json(),
                'FAKE_KUBECTL_VERSION_JSON': json.dumps(
                    {
                        'clientVersion': {
                            'major': '1',
                            'minor': '36',
                            'gitVersion': 'v1.36.3',
                            'gitCommit': 'fixture-commit',
                            'gitTreeState': 'clean',
                            'buildDate': '2026-08-10T00:00:00Z',
                            'goVersion': 'go1.25.0',
                            'compiler': 'gc',
                            'platform': 'linux/amd64',
                        },
                        'kustomizeVersion': 'v5.7.1',
                    }
                ),
                'FAKE_API_ENDPOINT': 'https://192.0.2.10:6443',
                'FAKE_API_READYZ': 'ok\n',
                'FAKE_LEGACY_RELEASE_JSON': json.dumps(
                    {
                        'apiVersion': 'v1',
                        'kind': 'List',
                        'items': [
                            {
                                'apiVersion': 'v1',
                                'kind': 'Secret',
                                'metadata': {
                                    'name': 'sh.helm.release.v1.cilium.v1',
                                    'namespace': 'kube-system',
                                    'labels': {
                                        'owner': 'helm',
                                        'name': 'cilium',
                                        'status': 'deployed',
                                        'version': '1',
                                    },
                                },
                                'type': 'helm.sh/release.v1',
                            }
                        ],
                    }
                ),
                'FAKE_RELEASE_JSON': self.release_json(),
                'FAKE_GATEWAY_JSON': self.gateway_bundle_json(),
                'FAKE_CILIUM_DAEMONSET_JSON': self.cilium_daemonset_json(),
                'FAKE_CILIUM_PODS_JSON': self.pod_list_json('cilium-fixture'),
                'FAKE_OPERATOR_JSON': self.operator_json(),
                'FAKE_OPERATOR_PODS_JSON': self.pod_list_json('cilium-operator-fixture'),
                'FAKE_ENVOY_DAEMONSET_JSON': self.envoy_daemonset_json(),
                'FAKE_ENVOY_PODS_JSON': self.envoy_pods_json(),
                'FAKE_CILIUM_CONFIG_JSON': self.cilium_config_json(),
                'FAKE_NODE_JSON': self.node_json(),
                'FAKE_CONFIGZ_JSON': json.dumps(
                    {
                        'kubeletconfig': {
                            'failSwapOn': False,
                            'memorySwap': {'swapBehavior': 'NoSwap'},
                        }
                    }
                ),
                'FAKE_CSR_JSON': self.csr_json(),
            }
        )
        for variable in (
            'APT_CONFIG', 'KUBECONFIG', 'GNUPGHOME', 'HELM_NAMESPACE',
            'HELM_DRIVER', 'HELM_KUBECONTEXT', 'HELM_CONFIG_HOME',
            'HELM_CACHE_HOME', 'HELM_DATA_HOME', 'DPKG_ADMINDIR',
            'DPKG_ROOT', 'DPKG_FORCE', 'DPKG_FRONTEND_LOCKED',
            'CONTAINER_RUNTIME_ENDPOINT', 'IMAGE_SERVICE_ENDPOINT',
            'KUBECACHEDIR', 'KUBECTL_EXTERNAL_DIFF', 'KUBECTL_KUBERC',
            'KUBECTL_UNAPPROVED', 'TAR_OPTIONS', 'BASH_ENV', 'ENV',
            'OPENSSL_CONF', 'OPENSSL_MODULES', 'PYTHONPATH', 'PYTHONHOME',
            'PYTHONPYCACHEPREFIX', 'PYTHONDONTWRITEBYTECODE',
        ):
            environment.pop(variable, None)
        return environment, host, command_log

    def run_stage(
        self, environment: dict[str, str], mode: str = '--check'
    ) -> subprocess.CompletedProcess[str]:
        return self.run_command(
            ['/bin/bash', '-p', str(FINAL_VERIFY), mode], env=environment
        )

    def assert_stops_without_evidence(
        self, result: subprocess.CompletedProcess[str], host: Path
    ) -> None:
        self.assertEqual(result.returncode, 50, result.stderr)
        self.assertIn('RESULT=STOP_VERIFY_FAILED', result.stdout)
        self.assertNotIn('PASS_BOOTSTRAP_VERIFIED', result.stdout)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('14-verify-*.txt')),
            [],
        )
        self.assertNotIn(self.canary, result.stdout + result.stderr)

    # 断言的是"无残留"（tree snapshot 前后仅多出 evidence 文件），不是字面意义的
    # "没有写过"：helm 的私有 kubeconfig 临时目录会在 CHECK 期间建立并在返回前删除。
    def test_check_succeeds_read_only_with_allowlisted_evidence(self) -> None:
        environment, host, command_log = self.make_environment()
        environment['FAKE_SIMULATE_CLIENT_CACHE'] = '1'
        home = Path(environment['HOME'])
        (home / '.kube').mkdir(mode=0o700)
        (home / '.kube/kuberc').write_text(
            'defaults:\n- command: get\n  options:\n'
            '    server: https://127.0.0.1:2\n'
            '    selector: hidden=true\n',
            encoding='utf-8',
        )
        environment['FAKE_HOSTILE_KUBERC_MODE'] = 'query'
        evidence_dir = host / 'root/dev-infra-evidence'
        before_host = self.tree_snapshot(host)
        before_home = self.tree_snapshot(home)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_VERIFIED', result.stdout)
        self.assertIn('NEXT=NONE', result.stdout)
        self.assertIn('CSR_COUNT=1', result.stdout)
        self.assertIn('CSR_NAME=csr-serving-fixture', result.stdout)
        self.assertIn(
            'CSR_USAGES=digital signature,server auth', result.stdout
        )
        self.assertIn(
            'CSR_SAN=DNS:example-node,IP:192.0.2.10', result.stdout
        )
        evidence = list((host / 'root/dev-infra-evidence').glob('14-verify-*.txt'))
        self.assertEqual(len(evidence), 1)
        evidence_stat = evidence[0].lstat()
        self.assertTrue(evidence[0].is_file())
        self.assertFalse(evidence[0].is_symlink())
        self.assertEqual(evidence_stat.st_mode & 0o7777, 0o600)
        self.assertEqual(evidence_stat.st_uid, os.geteuid())
        self.assertEqual(evidence_stat.st_gid, os.getegid())
        all_output = result.stdout + result.stderr + evidence[0].read_text(
            encoding='utf-8'
        )
        for forbidden in (
            self.canary, 'SECRET_CERTIFICATE_CANARY',
            'SECRET_CONDITION_CANARY', 'ZmFrZS1jc3ItcmVxdWVzdA==',
            'client-certificate-data', 'kubeconfig', 'private key',
        ):
            self.assertNotIn(forbidden, all_output)
        commands = command_log.read_text(encoding='utf-8')
        command_lines = commands.splitlines()
        self.assertIn(
            f'crictl --runtime-endpoint {self.endpoint} '
            f'--image-endpoint {self.endpoint} info --output json', commands
        )
        self.assertIn(
            'systemctl show --all --property=LoadState '
            '--property=FragmentPath --property=DropInPaths '
            'containerd.service',
            commands,
        )
        self.assertIn('ctr plugins ls', commands)
        self.assertTrue(any(
            line.startswith('kubectl --kubeconfig /dev/fd/') and
            ' --cache-dir=/dev/null diff --server-side=true '
            '--field-manager=engineering-platform-bootstrap ' in line
            for line in command_lines
        ))
        self.assertTrue(any(
            line.startswith(f"helm --kubeconfig {host / 'root/.helm-kubeconfig.'}") and
            line.endswith(' list --all-namespaces --all --output json')
            for line in command_lines
        ))
        for forbidden in (' apply ', ' install ', ' patch ', ' delete '):
            self.assertNotIn(forbidden, commands)
        after_host = self.tree_snapshot(host)
        expected_host = dict(before_host)
        evidence_relative = str(evidence[0].relative_to(host))
        expected_host[evidence_relative] = after_host[evidence_relative]
        self.assertEqual(after_host, expected_host)
        self.assertEqual(self.tree_snapshot(home), before_home)

    def test_requires_exact_post_init_containerd_gate_transcript(self) -> None:
        for case in ('service-inactive', 'binary-drift', 'pass-check'):
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                if case == 'service-inactive':
                    environment['FAKE_CONTAINERD_SERVICE_ACTIVE'] = '0'
                elif case == 'binary-drift':
                    target = host / 'usr/local/bin/containerd'
                    target.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
                    target.chmod(0o755)
                elif case == 'pass-check':
                    for logical in (
                        'usr/local/bin/containerd',
                        'usr/local/bin/ctr',
                        'usr/local/bin/containerd-shim-runc-v2',
                        'usr/local/sbin/runc',
                        'usr/local/bin/crictl',
                        'etc/containerd/config.toml',
                        'usr/local/lib/systemd/system/containerd.service',
                        'run/containerd/containerd.sock',
                    ):
                        (host / logical).unlink()
                    environment.update(
                        {
                            'FAKE_CONTAINERD_UNIT_STATE': 'missing',
                            'FAKE_CONTAINERD_SERVICE_ENABLED': '0',
                            'FAKE_CONTAINERD_SERVICE_ACTIVE': '0',
                            'FAKE_RESTORE_CRICTL_SOURCE': environment[
                                'FAKE_CRICTL_BACKUP'
                            ],
                        }
                    )

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)
                if command_log.exists():
                    commands = command_log.read_text(encoding='utf-8')
                    self.assertNotIn('kubectl ', commands)
                    if case != 'binary-drift':
                        self.assertIn('systemctl ', commands)

    def test_queries_exact_deployed_helm_user_values(self) -> None:
        environment, host, command_log = self.make_environment()

        exact_result = self.run_stage(environment)

        self.assertEqual(exact_result.returncode, 0, exact_result.stderr)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            ' get values cilium --namespace kube-system --revision 1 '
            '--output json\n',
            commands,
        )
        self.assertNotIn(' get values cilium --all', commands)

    def test_rejects_deployed_helm_user_values_drift(self) -> None:
        for case in (
            'missing', 'extra', 'wrong-type', 'wrong-value', 'duplicate-key',
            'nan', 'malformed', 'empty', 'query-failure',
        ):
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                payload = json.loads(json.dumps(self.desired_values_object))
                if case == 'missing':
                    del payload['operator']['image']['genericDigest']
                elif case == 'extra':
                    payload['unapproved'] = self.canary
                elif case == 'wrong-type':
                    payload['k8sServicePort'] = '6443'
                elif case == 'wrong-value':
                    payload['k8sServiceHost'] = '192.0.2.11'
                raw = json.dumps(payload)
                if case == 'duplicate-key':
                    raw = raw.replace(
                        '"kubeProxyReplacement": true',
                        '"kubeProxyReplacement": true, '
                        '"kubeProxyReplacement": true',
                        1,
                    )
                elif case == 'nan':
                    raw = raw.replace('"k8sServicePort": 6443', '"k8sServicePort": NaN')
                elif case == 'malformed':
                    raw = '{'
                elif case == 'empty':
                    raw = ''
                elif case == 'query-failure':
                    environment['FAKE_HELM_VALUES_FAIL'] = '1'
                environment['FAKE_HELM_VALUES_JSON'] = raw

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)
                self.assertNotIn(self.canary, result.stdout + result.stderr)

    def test_rejects_unpinned_cilium_controller_and_pod_images(self) -> None:
        cases = (
            ('FAKE_CILIUM_DAEMONSET_JSON', None),
            ('FAKE_CILIUM_PODS_JSON', 0),
            ('FAKE_OPERATOR_JSON', None),
            ('FAKE_OPERATOR_PODS_JSON', 0),
        )
        for variable, list_index in cases:
            with self.subTest(variable=variable):
                environment, host, _ = self.make_environment()
                payload = json.loads(environment[variable])
                item = (
                    payload['items'][list_index]
                    if list_index is not None
                    else payload
                )
                containers = (
                    item['spec']['containers']
                    if list_index is not None
                    else item['spec']['template']['spec']['containers']
                )
                containers[0]['image'] = (
                    'quay.io/cilium/cilium:v1.20.0'
                    if 'CILIUM' in variable
                    else 'quay.io/cilium/operator-generic:v1.20.0'
                )
                environment[variable] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)

    def test_requires_exact_envoy_dataplane_and_cilium_config(self) -> None:
        cases = (
            ('envoy-daemonset-label', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-daemonset-image', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-daemonset-not-ready', 'FAKE_ENVOY_DAEMONSET_JSON'),
            ('envoy-pod-label', 'FAKE_ENVOY_PODS_JSON'),
            ('envoy-pod-image', 'FAKE_ENVOY_PODS_JSON'),
            ('envoy-pod-not-ready', 'FAKE_ENVOY_PODS_JSON'),
            ('cilium-config-missing', 'FAKE_CILIUM_CONFIG_JSON'),
            ('cilium-config-drift', 'FAKE_CILIUM_CONFIG_JSON'),
            ('query-failure', ''),
        )
        for case, variable in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'query-failure':
                    environment['FAKE_KUBECTL_FAIL'] = 'envoy-daemonset'
                else:
                    payload = json.loads(environment[variable])
                    item = (
                        payload['items'][0]
                        if variable == 'FAKE_ENVOY_PODS_JSON'
                        else payload
                    )
                    if case.endswith('-label'):
                        item['metadata']['labels']['helm.sh/chart'] = 'drift'
                    elif case.endswith('-image'):
                        containers = (
                            item['spec']['containers']
                            if variable == 'FAKE_ENVOY_PODS_JSON'
                            else item['spec']['template']['spec']['containers']
                        )
                        containers[0]['image'] = 'quay.io/cilium/cilium-envoy:mutable'
                    elif case == 'envoy-daemonset-not-ready':
                        item['status']['numberReady'] = 0
                    elif case == 'envoy-pod-not-ready':
                        item['status']['conditions'][0]['status'] = 'False'
                    elif case == 'cilium-config-missing':
                        del payload['data']['enable-gateway-api']
                    elif case == 'cilium-config-drift':
                        payload['data']['cgroup-root'] = '/unapproved'
                    environment[variable] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)

    def test_rejects_apply_invalid_mode_and_environment_before_lookup(self) -> None:
        for mode in ('--apply', '--force'):
            with self.subTest(mode=mode):
                environment, host, command_log = self.make_environment()
                result = self.run_stage(environment, mode)
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertFalse(command_log.exists())
                self.assertEqual(
                    list((host / 'root/dev-infra-evidence').glob('14-verify-*.txt')),
                    [],
                )
        for variable in (
            'KUBECONFIG', 'APT_CONFIG', 'HELM_NAMESPACE', 'DPKG_ADMINDIR',
            'CONTAINER_RUNTIME_ENDPOINT', 'KUBECACHEDIR',
            'KUBECTL_EXTERNAL_DIFF', 'KUBECTL_KUBERC',
            'KUBECTL_UNAPPROVED', 'HELM_KUBEAPISERVER', 'TAR_OPTIONS',
            'BASH_ENV', 'ENV', 'OPENSSL_CONF', 'OPENSSL_MODULES',
            'PYTHONPATH', 'PYTHONHOME', 'PYTHONPYCACHEPREFIX',
            'PYTHONDONTWRITEBYTECODE',
        ):
            for value in ('', '/tmp/unapproved'):
                with self.subTest(variable=variable, value=value):
                    environment, host, command_log = self.make_environment()
                    environment[variable] = value
                    result = self.run_stage(environment)
                    self.assertEqual(result.returncode, 10, result.stderr)
                    self.assertFalse(command_log.exists())
                    self.assertEqual(
                        list(
                            (host / 'root/dev-infra-evidence').glob(
                                '14-verify-*.txt'
                            )
                        ),
                        [],
                    )

    def test_uses_isolated_python_from_hostile_working_directory(self) -> None:
        environment, _, _ = self.make_environment()
        hostile = self.temporary_directory() / 'hostile-cwd'
        hostile.mkdir()
        import_marker = hostile / 'python-imported'
        (hostile / 'json.py').write_text(
            'from pathlib import Path\n'
            f'Path({str(import_marker)!r}).write_text("executed\\n")\n'
            'raise RuntimeError("hostile json module")\n',
            encoding='utf-8',
        )

        result = subprocess.run(
            ['/bin/bash', '-p', str(FINAL_VERIFY), '--check'],
            cwd=hostile,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(import_marker.exists())

    def test_uses_fixed_tar_outside_path(self) -> None:
        environment, _, _ = self.make_environment()
        tar_marker = self.temporary_directory() / 'tar-executed'
        fake_bin = Path(environment['PATH'].split(':', 1)[0])
        self.write_executable(
            fake_bin / 'tar',
            '#!/bin/sh\n'
            'case "$*" in\n'
            f'  *helm-v3.21.0*) printf executed >{tar_marker}; exit 99 ;;\n'
            '  *) exec /usr/bin/tar "$@" ;;\n'
            'esac\n',
        )

        result = subprocess.run(
            ['/bin/bash', '-p', str(FINAL_VERIFY), '--check'],
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(tar_marker.exists())

    def test_uses_fixed_openssl_outside_path(self) -> None:
        environment, host, _ = self.make_environment()
        fake_bin = Path(environment['PATH'].split(':', 1)[0])
        approved_openssl = host / 'usr/bin/openssl'
        approved_openssl.write_bytes((fake_bin / 'openssl').read_bytes())
        approved_openssl.chmod(0o755)
        marker = self.temporary_directory() / 'path-openssl-executed'
        self.write_executable(
            fake_bin / 'openssl',
            f'#!/bin/sh\nprintf executed >{marker}\nexit 99\n',
        )

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_rejects_unsafe_admin_config_or_source_race(self) -> None:
        for case in (
            'exec', 'auth-provider', 'proxy-url', 'insecure-tls',
            'extra-cluster', 'wrong-context', 'query-failure', 'source-race',
        ):
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                payload = self.admin_config_object()
                cluster = payload['clusters'][0]['cluster']
                user = payload['users'][0]['user']
                if case == 'exec':
                    user['exec'] = {'command': self.canary}
                elif case == 'auth-provider':
                    user['auth-provider'] = {'name': self.canary}
                elif case == 'proxy-url':
                    cluster['proxy-url'] = 'https://127.0.0.1:1'
                elif case == 'insecure-tls':
                    cluster['insecure-skip-tls-verify'] = True
                elif case == 'extra-cluster':
                    payload['clusters'].append(payload['clusters'][0].copy())
                elif case == 'wrong-context':
                    payload['current-context'] = 'unapproved'
                elif case == 'query-failure':
                    environment['FAKE_ADMIN_VIEW_FAIL'] = '1'
                else:
                    environment['FAKE_ADMIN_SOURCE_RACE'] = '1'
                environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)

    def test_all_cluster_clients_use_validated_in_memory_admin_config(self) -> None:
        environment, host, command_log = self.make_environment()

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = command_log.read_text(encoding='utf-8').splitlines()
        self.assertTrue(any(
            'config view --raw --merge=false --output=json' in line
            for line in commands
        ))
        cluster_clients = [
            line for line in commands
            if line.startswith('kubectl ') or (
                line.startswith('helm ') and ' version --short' not in line
            )
        ]
        self.assertTrue(cluster_clients)
        temporary_root = str(host / 'root/.helm-kubeconfig.')
        for line in cluster_clients:
            if line.startswith('kubectl '):
                self.assertIn(' --kubeconfig /dev/fd/', line)
            else:
                # helm 不能读管道：只接受 /root 下私有临时文件里的已校验内容。
                self.assertIn(f' --kubeconfig {temporary_root}', line)
                self.assertIn('/config ', line)
            self.assertNotIn(str(host / 'etc/kubernetes/admin.conf'), line)
        self.assertEqual(list((host / 'root').glob('.helm-kubeconfig.*')), [])

    def test_check_stops_on_helm_kubeconfig_residue(self) -> None:
        """上次运行被中断留下的 kubeconfig 残留必须 fail-closed，且不被自动删除。"""
        environment, host, _ = self.make_environment()
        residue = host / 'root/.helm-kubeconfig.stale'
        residue.mkdir()
        config = residue / 'config'
        config.write_text('leftover kubeconfig\n', encoding='utf-8')
        config.chmod(0o600)
        residue.chmod(0o700)
        before_host = self.tree_snapshot(host)

        result = self.run_stage(environment)

        self.assert_stops_without_evidence(result, host)
        self.assertIn('REASON=helm-kubeconfig-residue', result.stdout)
        self.assertTrue((residue / 'config').is_file())
        self.assertEqual(self.tree_snapshot(host), before_host)

    def test_helm_kubeconfig_is_removed_when_stage_is_signalled(self) -> None:
        """helm 运行期间被 SIGTERM 杀死时，EXIT trap 必须清掉 kubeconfig 临时目录。"""
        environment, host, command_log = self.make_environment()
        environment['FAKE_HELM_KILL_PARENT'] = '1'

        result = self.run_stage(environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(' --kubeconfig ', command_log.read_text(encoding='utf-8'))
        self.assertEqual(list((host / 'root').glob('.helm-kubeconfig.*')), [])

    def test_containerd_gate_uses_privileged_child_bash(self) -> None:
        script = FINAL_VERIFY.read_text(encoding='utf-8')

        # 路径由 STAGE_SCRIPTS 派生：stage 迁进 stages/<NN-name>/run.sh 后，写死的
        # 平铺路径会让这条断言在迁移当次判红，而它要钉的其实是「以特权子 bash、
        # 清空 BASH_ENV/ENV 的方式调用 containerd stage」这三件事，与布局无关。
        # 锚点变量随布局变化（平铺用 script_dir，迁移后用 bootstrap_dir），这里只钉
        # 「以特权子 bash、清空 BASH_ENV/ENV、指向 containerd stage」这三件事。
        containerd = re.escape(self.stage_paths['30'])
        self.assertRegex(
            script,
            r"BASH_ENV='' ENV='' PYTHONDONTWRITEBYTECODE=1 \\\n"
            r'      /bin/bash -p "\$\{(?:script_dir|bootstrap_dir)\}/'
            + containerd + '"',
        )

    def test_verify_stops_on_unregistered_host(self) -> None:
        environment, host, _ = self.make_environment()
        environment['FAKE_HOSTNAME'] = 'wrong-host'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 10, result.stdout)
        self.assertIn('RESULT=STOP_PRECONDITION', result.stdout)
        self.assertIn('REASON=host-not-registered', result.stdout)
        self.assertEqual(
            list((host / 'root/dev-infra-evidence').glob('14-verify-*.txt')), []
        )

    def test_node_csr_and_swap_contracts_come_from_host_env(self) -> None:
        """把 host.env 的值改掉后，对应 gate 必须按新值拒绝原 fixture。"""
        cases = (
            ('node-name', {'name': 'fixture-host-b'}, 'node-readiness-or-address-drift'),
            ('node-ip', {'node_ip': '192.0.2.99'}, 'admin-conf-content-or-structure-drift'),
            ('swap-range', {'swap_min': 1000, 'swap_max': 2000}, 'swap-contract-drift'),
        )
        for case, overrides, expected in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
                shutil.rmtree(hosts_root / 'example-node')
                name = overrides.get('name', 'example-node')
                self.write_fixture_host(hosts_root, **overrides)
                environment['FAKE_HOSTNAME'] = name

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)
                self.assertIn(f'REASON={expected}', result.stdout)

    def test_registered_second_host_flows_through_verify(self) -> None:
        environment, host, _ = self.make_environment()
        hosts_root = Path(environment['BOOTSTRAP_TEST_HOSTS_DIR'])
        self.write_fixture_host(
            hosts_root, name='fixture-host-b', node_ip='10.200.0.2',
            cluster_name='fixture-b', swap_file='/swap-b.img',
            swap_min=3000000000, swap_max=3400000000,
        )
        swap_file = host / 'swap-b.img'
        swap_file.write_text('swap fixture\n', encoding='utf-8')
        swap_file.chmod(0o600)
        environment['FAKE_SWAP_OUTPUT'] = '/swap-b.img 3221225472'
        environment['FAKE_HOSTNAME'] = 'fixture-host-b'
        environment['FAKE_API_ENDPOINT'] = 'https://10.200.0.2:6443'
        environment['FAKE_NODE_NAME'] = 'fixture-host-b'
        environment['FAKE_NODE_IP'] = '10.200.0.2'
        environment['FAKE_NODE_JSON'] = self.node_json(
            name=environment['FAKE_NODE_NAME'], ip=environment['FAKE_NODE_IP']
        )
        values = json.loads(json.dumps(self.desired_values_object))
        values['k8sServiceHost'] = environment['FAKE_NODE_IP']
        environment['FAKE_HELM_VALUES_JSON'] = json.dumps(values)
        environment['FAKE_CSR_SAN'] = 'DNS:fixture-host-b, IP Address:10.200.0.2'
        environment['FAKE_CSR_JSON'] = self.csr_json(username='system:node:fixture-host-b')
        payload = self.admin_config_object()
        payload['clusters'][0]['name'] = 'fixture-b'
        payload['clusters'][0]['cluster']['server'] = 'https://10.200.0.2:6443'
        payload['contexts'][0]['name'] = 'kubernetes-admin@fixture-b'
        payload['contexts'][0]['context']['cluster'] = 'fixture-b'
        payload['current-context'] = 'kubernetes-admin@fixture-b'
        environment['FAKE_ADMIN_VIEW_JSON'] = json.dumps(payload)

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('RESULT=PASS_BOOTSTRAP_VERIFIED', result.stdout)
        self.assertIn('NODE_NAME=fixture-host-b', result.stdout)
        self.assertIn('CSR_SAN=DNS:fixture-host-b,IP:10.200.0.2', result.stdout)
        self.assertIn('SWAP_DEVICE=/swap-b.img', result.stdout)

    def test_rejects_package_hold_binary_or_cni_drift(self) -> None:
        for package in ('kubeadm', 'kubectl', 'kubelet', 'kubernetes-cni'):
            with self.subTest(package=package):
                environment, host, _ = self.make_environment()
                environment['FAKE_PACKAGE_DRIFT'] = package
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)
        cases = ('extra-hold', 'verify', 'binary-mode', 'binary-owner', 'cni-extra', 'cni-digest')
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'extra-hold':
                    environment['FAKE_EXTRA_HOLD'] = '1'
                elif case == 'verify':
                    environment['FAKE_VERIFY_DRIFT'] = 'kubectl'
                elif case == 'binary-mode':
                    (host / 'usr/bin/kubeadm').chmod(0o775)
                elif case == 'binary-owner':
                    environment['FAKE_OWNER_DRIFT'] = '/usr/bin/kubelet'
                elif case == 'cni-extra':
                    (host / 'opt/cni/bin/unapproved').write_text(
                        'unapproved\n', encoding='utf-8'
                    )
                else:
                    environment['FAKE_CNI_DIGEST_DRIFT'] = 'bridge'
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_verify_accepts_declared_client_doc_exclusions(self) -> None:
        """捕获 Stage 90 把官方 dpkg 文档排除输出误判为 package payload 漂移。"""
        environment, host, _ = self.make_environment()
        excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
        excludes.parent.mkdir(parents=True, exist_ok=True)
        excludes.write_text(
            'path-exclude=/usr/share/man/*\n'
            'path-exclude=/usr/share/doc/*\n'
            'path-include=/usr/share/doc/*/copyright\n'
            'path-include=/usr/share/doc/*/changelog.*\n',
            encoding='utf-8',
        )
        excludes.chmod(0o644)
        environment['FAKE_VERIFY_DOC_EXCLUDES'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_BOOTSTRAP_VERIFIED', result.stdout)

    def test_verify_rejects_unsafe_client_doc_exclusion_shapes(self) -> None:
        """缺失或不安全的 exclude 合同与任何额外 payload 缺失都必须 fail closed。"""
        for drift in (
            'missing-config',
            'symlink-config',
            'unsafe-mode',
            'single',
            'duplicate',
            'other-package',
            'extra-missing',
            'checksum',
            'nonzero',
        ):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                environment['FAKE_VERIFY_DOC_EXCLUDES'] = '1'
                excludes = host / 'etc/dpkg/dpkg.cfg.d/excludes'
                if drift != 'missing-config':
                    excludes.parent.mkdir(parents=True, exist_ok=True)
                    if drift == 'symlink-config':
                        outside = host.parent / 'unapproved-dpkg-excludes'
                        outside.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        outside.chmod(0o644)
                        excludes.symlink_to(outside)
                    else:
                        excludes.write_text(
                            'path-exclude=/usr/share/doc/*\n', encoding='utf-8'
                        )
                        excludes.chmod(
                            0o666 if drift == 'unsafe-mode' else 0o644
                        )
                if drift not in {
                    'missing-config', 'symlink-config', 'unsafe-mode'
                }:
                    environment['FAKE_VERIFY_DOC_SHAPE'] = drift

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)

    def test_verify_declares_dpkg_verification_dependencies(self) -> None:
        """共享 dpkg 校验预期的 grep 必须在 Stage 90 前置声明。"""
        required_commands = next(
            line
            for line in FINAL_VERIFY.read_text(encoding='utf-8').splitlines()
            if line.startswith('for required_command in ')
        )

        self.assertIn('awk', required_commands.split())
        self.assertIn('grep', required_commands.split())

    def test_accepts_cni_payload_with_or_without_cilium_plugin(self) -> None:
        for present in (True, False):
            with self.subTest(cilium_cni_present=present):
                environment, host, _ = self.make_environment()
                if not present:
                    (host / 'opt/cni/bin/cilium-cni').unlink()

                result = self.run_stage(environment)

                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('RESULT=PASS_BOOTSTRAP_VERIFIED', result.stdout)

    def test_rejects_cilium_cni_plugin_drift(self) -> None:
        for drift in ('mode', 'digest', 'package-owned'):
            with self.subTest(drift=drift):
                environment, host, _ = self.make_environment()
                if drift == 'mode':
                    (host / 'opt/cni/bin/cilium-cni').chmod(0o775)
                elif drift == 'digest':
                    environment['FAKE_CNI_DIGEST_DRIFT'] = 'cilium-cni'
                else:
                    environment['FAKE_CILIUM_CNI_OWNED'] = '1'

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)
                self.assertIn('REASON=cni-payload-drift', result.stdout)

    def test_rejects_cri_version_or_api_endpoint_health_drift(self) -> None:
        cases = (
            'cri', 'network', 'kubeadm-version', 'kubectl-version',
            'kubelet-version', 'endpoint', 'readyz',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'cri':
                    environment['FAKE_CRI_JSON'] = self.cri_json(ready=False)
                elif case == 'network':
                    environment['FAKE_CRI_JSON'] = self.cri_json(
                        network_ready=False
                    )
                elif case == 'kubeadm-version':
                    environment['FAKE_KUBEADM_VERSION'] = 'v1.35.0'
                elif case == 'kubectl-version':
                    environment['FAKE_KUBECTL_VERSION_JSON'] = json.dumps(
                        {'clientVersion': {'gitVersion': 'v1.35.0'}}
                    )
                elif case == 'kubelet-version':
                    environment['FAKE_KUBELET_VERSION'] = 'Kubernetes v1.35.0'
                elif case == 'endpoint':
                    environment['FAKE_API_ENDPOINT'] = 'https://127.0.0.1:6443'
                else:
                    environment['FAKE_API_READYZ'] = 'not-ready\n'
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_rejects_helm_provenance_list_or_storage_drift(self) -> None:
        cases = (
            'binary', 'shadow', 'archive-digest', 'version', 'list-failure',
            'chart', 'app-version', 'revision-type', 'updated-empty',
            'extra-release', 'storage-missing-modified-at',
            'storage-created-at-only', 'storage-modified-at',
            'storage-release-data',
        )
        for case in cases:
            with self.subTest(case=case):
                environment, host, command_log = self.make_environment()
                if case == 'binary':
                    (host / 'usr/local/bin/helm').write_text(
                        '#!/bin/sh\nexit 0\n', encoding='utf-8'
                    )
                elif case == 'shadow':
                    self.write_executable(
                        host / 'usr/bin/helm', '#!/bin/sh\nexit 0\n'
                    )
                elif case == 'archive-digest':
                    environment['FAKE_HELM_ARCHIVE_DIGEST_DRIFT'] = '1'
                elif case == 'version':
                    environment['FAKE_HELM_VERSION'] = 'v3.20.0+gfixture'
                elif case == 'list-failure':
                    environment['FAKE_HELM_LIST_FAIL'] = '1'
                elif case == 'chart':
                    environment['FAKE_HELM_LIST_JSON'] = self.helm_list_json(
                        chart='cilium-1.19.0'
                    )
                elif case == 'app-version':
                    environment['FAKE_HELM_LIST_JSON'] = self.helm_list_json(
                        app_version='1.19.0'
                    )
                elif case == 'revision-type':
                    environment['FAKE_HELM_LIST_JSON'] = self.helm_list_json(
                        revision=1
                    )
                elif case == 'updated-empty':
                    environment['FAKE_HELM_LIST_JSON'] = self.helm_list_json(
                        updated=''
                    )
                elif case == 'extra-release':
                    payload = json.loads(self.helm_list_json())
                    payload.append(dict(payload[0], name='unknown'))
                    environment['FAKE_HELM_LIST_JSON'] = json.dumps(payload)
                else:
                    payload = json.loads(environment['FAKE_RELEASE_JSON'])
                    item = payload['items'][0]
                    if case == 'storage-missing-modified-at':
                        item['metadata']['labels'].pop('modifiedAt')
                    elif case == 'storage-created-at-only':
                        item['metadata']['labels'].pop('modifiedAt')
                        item['metadata']['labels']['createdAt'] = '1786320000'
                    elif case == 'storage-modified-at':
                        item['metadata']['labels']['modifiedAt'] = 'invalid'
                    else:
                        item['data']['release'] = ''
                    environment['FAKE_RELEASE_JSON'] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)
                if command_log.exists():
                    self.assertNotIn(
                        self.canary,
                        command_log.read_text(encoding='utf-8'),
                    )

    def test_rejects_every_kube_proxy_object_or_query_failure(self) -> None:
        cases = (
            ('FAKE_KUBE_PROXY_DAEMONSET', 'daemonset.apps/kube-proxy\n'),
            ('FAKE_KUBE_PROXY_PODS', 'pod/kube-proxy-fixture\n'),
            ('FAKE_KUBE_PROXY_CONFIGMAP', 'configmap/kube-proxy\n'),
        )
        for variable, value in cases:
            with self.subTest(variable=variable):
                environment, host, _ = self.make_environment()
                environment[variable] = value
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)
        for route in (
            'kube-proxy-daemonset', 'kube-proxy-pods',
            'kube-proxy-configmap',
        ):
            with self.subTest(route=route):
                environment, host, _ = self.make_environment()
                environment['FAKE_KUBECTL_FAIL'] = route
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_rejects_unhealthy_cilium_operator_or_unknown_release(self) -> None:
        cases = ('daemonset', 'cilium-pods', 'operator', 'operator-pods', 'release')
        for case in cases:
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'daemonset':
                    environment['FAKE_CILIUM_DAEMONSET_JSON'] = (
                        self.cilium_daemonset_json(ready=False)
                    )
                elif case == 'cilium-pods':
                    environment['FAKE_CILIUM_PODS_JSON'] = self.pod_list_json(
                        'cilium-fixture', ready=False
                    )
                elif case == 'operator':
                    environment['FAKE_OPERATOR_JSON'] = self.operator_json(
                        ready=False
                    )
                elif case == 'operator-pods':
                    environment['FAKE_OPERATOR_PODS_JSON'] = self.pod_list_json(
                        'cilium-operator-fixture', ready=False
                    )
                else:
                    payload = json.loads(environment['FAKE_RELEASE_JSON'])
                    payload['items'][0]['metadata']['labels']['name'] = 'unknown'
                    environment['FAKE_RELEASE_JSON'] = json.dumps(payload)
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_rejects_official_cilium_object_and_pod_identity_drift(self) -> None:
        cases = (
            ('FAKE_CILIUM_DAEMONSET_JSON', None, 'app.kubernetes.io/name'),
            ('FAKE_CILIUM_PODS_JSON', 0, 'app.kubernetes.io/name'),
            ('FAKE_OPERATOR_JSON', None, 'io.cilium/app'),
            ('FAKE_OPERATOR_PODS_JSON', 0, 'app.kubernetes.io/part-of'),
        )
        for variable, list_index, key in cases:
            with self.subTest(variable=variable, key=key):
                environment, host, _ = self.make_environment()
                for payload_variable in (
                    'FAKE_CILIUM_DAEMONSET_JSON', 'FAKE_CILIUM_PODS_JSON',
                    'FAKE_OPERATOR_JSON', 'FAKE_OPERATOR_PODS_JSON',
                ):
                    payload = json.loads(environment[payload_variable])
                    items = payload.get('items')
                    item = items[0] if isinstance(items, list) else payload
                    item['metadata']['labels'][
                        'app.kubernetes.io/version'
                    ] = '1.20.0'
                    environment[payload_variable] = json.dumps(payload)
                payload = json.loads(environment[variable])
                item = (
                    payload['items'][list_index]
                    if list_index is not None
                    else payload
                )
                item['metadata']['labels'][key] = 'drift'
                environment[variable] = json.dumps(payload)

                result = self.run_stage(environment)

                self.assert_stops_without_evidence(result, host)

    def test_rejects_gateway_bundle_or_server_side_diff_drift(self) -> None:
        for case in ('partial', 'annotation', 'annotation-extra', 'diff', 'query'):
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'partial':
                    environment['FAKE_GATEWAY_JSON'] = self.gateway_bundle_json(
                        partial=True
                    )
                elif case == 'annotation':
                    payload = json.loads(environment['FAKE_GATEWAY_JSON'])
                    payload['items'][0]['metadata']['annotations'][
                        'gateway.networking.k8s.io/bundle-version'
                    ] = 'v1.5.0'
                    environment['FAKE_GATEWAY_JSON'] = json.dumps(payload)
                elif case == 'annotation-extra':
                    payload = json.loads(environment['FAKE_GATEWAY_JSON'])
                    payload['items'][0]['metadata']['annotations'][
                        'unapproved.example.invalid/annotation'
                    ] = 'value'
                    environment['FAKE_GATEWAY_JSON'] = json.dumps(payload)
                elif case == 'diff':
                    environment['FAKE_GATEWAY_DIFF_EXIT'] = '1'
                else:
                    environment['FAKE_KUBECTL_FAIL'] = 'gateway-diff'
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_gateway_query_is_scoped_to_pinned_objects(self) -> None:
        environment, _, command_log = self.make_environment()
        environment['FAKE_REQUIRE_SCOPED_GATEWAY'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        commands = command_log.read_text(encoding='utf-8')
        self.assertIn(
            'customresourcedefinition.apiextensions.k8s.io/'
            'backendtlspolicies.gateway.networking.k8s.io',
            commands,
        )
        self.assertNotIn(
            'customresourcedefinitions.apiextensions.k8s.io,',
            commands,
        )

    def test_rejects_node_swap_or_kubelet_configz_drift(self) -> None:
        for case in (
            'node-not-ready', 'node-ip', 'swap-off', 'swap-extra',
            'swap-size', 'fail-swap-on', 'limited-swap',
        ):
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'node-not-ready':
                    environment['FAKE_NODE_JSON'] = self.node_json(ready=False)
                elif case == 'node-ip':
                    environment['FAKE_NODE_JSON'] = self.node_json(ip='192.0.2.99')
                elif case == 'swap-off':
                    environment['FAKE_SWAP_OUTPUT'] = ''
                elif case == 'swap-extra':
                    environment['FAKE_SWAP_OUTPUT'] = (
                        '/swap.img 4200000000\n/dev/other 1000000'
                    )
                elif case == 'swap-size':
                    environment['FAKE_SWAP_OUTPUT'] = '/swap.img 3999999999'
                elif case == 'fail-swap-on':
                    environment['FAKE_CONFIGZ_JSON'] = json.dumps(
                        {
                            'kubeletconfig': {
                                'failSwapOn': True,
                                'memorySwap': {'swapBehavior': 'NoSwap'},
                            }
                        }
                    )
                else:
                    environment['FAKE_CONFIGZ_JSON'] = json.dumps(
                        {
                            'kubeletconfig': {
                                'failSwapOn': False,
                                'memorySwap': {'swapBehavior': 'LimitedSwap'},
                            }
                        }
                    )
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)

    def test_check_uses_raw_swap_columns_on_util_linux_239(self) -> None:
        """捕获最终验证在 util-linux 2.39.3 上把 TYPE 当成 SIZE。"""
        environment, _, _ = self.make_environment()
        environment['FAKE_SWAPON_UTIL_LINUX_239'] = '1'

        result = self.run_stage(environment)

        self.assertEqual(
            result.returncode,
            0,
            f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('RESULT=PASS_BOOTSTRAP_VERIFIED', result.stdout)

    def test_csr_summary_is_strict_and_never_leaks_request_or_certificate(self) -> None:
        for case in (
            'requester', 'usages', 'stale-usages', 'extra-usage',
            'san', 'malformed',
        ):
            with self.subTest(case=case):
                environment, host, _ = self.make_environment()
                if case == 'requester':
                    environment['FAKE_CSR_JSON'] = self.csr_json(
                        username='system:node:other'
                    )
                elif case == 'usages':
                    environment['FAKE_CSR_JSON'] = self.csr_json(
                        usages=['server auth']
                    )
                elif case == 'stale-usages':
                    environment['FAKE_CSR_JSON'] = self.csr_json(
                        usages=[
                            'server auth', 'digital signature',
                            'key encipherment',
                        ]
                    )
                elif case == 'extra-usage':
                    environment['FAKE_CSR_JSON'] = self.csr_json(
                        usages=[
                            'server auth', 'digital signature', 'client auth',
                        ]
                    )
                elif case == 'san':
                    environment['FAKE_CSR_SAN'] = (
                        'DNS:example-node, IP Address:192.0.2.99'
                    )
                else:
                    environment['FAKE_CSR_JSON'] = '{not-json'
                result = self.run_stage(environment)
                self.assert_stops_without_evidence(result, host)
                self.assertNotIn(
                    'ZmFrZS1jc3ItcmVxdWVzdA==', result.stdout + result.stderr
                )
                self.assertNotIn(
                    'SECRET_CERTIFICATE_CANARY', result.stdout + result.stderr
                )

        environment, _, _ = self.make_environment()
        environment['FAKE_CSR_JSON'] = json.dumps(
            {
                'apiVersion': 'certificates.k8s.io/v1',
                'kind': 'CertificateSigningRequestList',
                'items': [],
            }
        )
        result = self.run_stage(environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CSR_COUNT=0', result.stdout)

    def test_script_has_no_mutation_or_prior_package_stage_escape_hatches(self) -> None:
        self.assertTrue(FINAL_VERIFY.exists(), '90-verify run.sh entry is missing')
        script = FINAL_VERIFY.read_text(encoding='utf-8')
        for forbidden in (
            self.stage_paths['40'], 'kubectl apply', 'kubectl patch',
            'kubectl delete', 'helm install', 'kubeadm reset', 'set -x',
            '--raw=true',
        ):
            self.assertNotIn(forbidden, script)


if __name__ == '__main__':
    unittest.main()
