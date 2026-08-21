from __future__ import annotations

import collections
import importlib
import inspect
import unittest


SHARD_ORDER = (
    'contracts', 'artifacts', 'kernel', 'containerd',
    'kubernetes', 'kubeadm', 'cilium', 'final-verify',
)

SHARDS = {
    'contracts': (
        'test_validate.ProfileValidationTest',
        'test_validate.RepositoryProfileContractTest',
        'test_validate.ActiveRootIsolationTest',
        'test_validate.BootstrapContractTest',
        'test_validate.ValidateEntrypointTest',
        'test_validate.ValidationCatalogTest',
        'test_bootstrap.HostConfigTest',
        'test_bootstrap.CommonLibraryTest',
        'test_bootstrap.ShellSourceStatementTest',
        'test_bootstrap.PathFactsTest',
        'test_bootstrap.ArchiveLibraryTest',
        'test_bootstrap.ExecSafetyTest',
        'test_bootstrap.CidrCheckTest',
        'test_bootstrap.PreflightTest',
        'test_bootstrap.BootstrapEntrySecurityTest',
        'test_bootstrap.BootstrapOrchestratorTest',
        'test_bootstrap.RunApprovedTest',
    ),
    'artifacts': ('test_bootstrap.ArtifactStageTest',),
    'kernel': ('test_bootstrap.KernelStageTest',),
    'containerd': ('test_bootstrap.ContainerdInstallTest',),
    'kubernetes': ('test_bootstrap.KubernetesInstallTest',),
    'kubeadm': ('test_bootstrap.KubeadmInitTest',),
    'cilium': ('test_bootstrap.CiliumInstallTest',),
    'final-verify': ('test_bootstrap.FinalVerifyTest',),
}

FAST_SELECTORS = (
    'test_validate.ProfileValidationTest',
    'test_validate.RepositoryProfileContractTest',
    'test_validate.ActiveRootIsolationTest',
    'test_validate.BootstrapContractTest',
    'test_validate.ValidateEntrypointTest',
    'test_validate.ValidationCatalogTest',
    'test_bootstrap.HostConfigTest',
    'test_bootstrap.CommonLibraryTest',
    'test_bootstrap.ShellSourceStatementTest',
    'test_bootstrap.PathFactsTest',
    'test_bootstrap.ArchiveLibraryTest',
    'test_bootstrap.ExecSafetyTest',
    'test_bootstrap.CidrCheckTest',
    'test_bootstrap.PreflightTest.test_accepts_canonical_ubuntu_os_release_symlink',
    'test_bootstrap.PreflightTest.test_fake_cleanup_digest_precedes_system_sha256sum',
    'test_bootstrap.PreflightTest.test_stage30_owned_runtime_footprint_does_not_fail_preflight',
    'test_bootstrap.PreflightTest.test_legacy_runtime_conflicts_still_fail_preflight',
    'test_bootstrap.PreflightTest.test_stops_on_cleanup_evidence_digest_drift',
    'test_bootstrap.PreflightTest.test_stops_on_local_cidr_overlap',
    'test_bootstrap.BootstrapEntrySecurityTest',
    'test_bootstrap.BootstrapOrchestratorTest.test_direct_entry_ignores_path_bash_and_bash_env',
    'test_bootstrap.BootstrapOrchestratorTest.test_check_resumes_from_every_legal_checkpoint',
    'test_bootstrap.BootstrapOrchestratorTest.test_nonzero_stage_exit_is_preserved',
    'test_bootstrap.BootstrapOrchestratorTest.test_structured_output_and_postcheck_fail_closed',
    'test_bootstrap.BootstrapOrchestratorTest.test_apply_requires_main_clean_repo_and_exclusive_lock',
    'test_bootstrap.BootstrapOrchestratorTest.test_gnu_stat_fallback_discards_failed_probe_stdout',
    'test_bootstrap.RunApprovedTest',
)


def selector_class_name(selector: str) -> str | None:
    parts = selector.split('.')
    if len(parts) not in (2, 3):
        return None
    return '.'.join(parts[:2])


def selector_exists(selector: str) -> bool:
    parts = selector.split('.')
    if len(parts) not in (2, 3):
        return False
    try:
        module = importlib.import_module(parts[0])
        test_class = getattr(module, parts[1])
    except (AttributeError, ImportError):
        return False
    if not inspect.isclass(test_class) or not issubclass(test_class, unittest.TestCase):
        return False
    methods = unittest.defaultTestLoader.getTestCaseNames(test_class)
    return bool(methods) if len(parts) == 2 else parts[2] in methods


def discover_concrete_test_cases() -> tuple[str, ...]:
    loader = unittest.defaultTestLoader
    discovered: list[str] = []
    for module_name in ('test_validate', 'test_bootstrap'):
        module = importlib.import_module(module_name)
        for class_name, candidate in inspect.getmembers(module, inspect.isclass):
            if candidate.__module__ != module_name:
                continue
            if not issubclass(candidate, unittest.TestCase):
                continue
            if not loader.getTestCaseNames(candidate):
                continue
            discovered.append(f'{module_name}.{class_name}')
    return tuple(sorted(discovered))


def validate_catalog() -> None:
    assigned = [
        selector for name in SHARD_ORDER for selector in SHARDS.get(name, ())
    ]
    counts = collections.Counter(assigned)
    duplicate = sorted(name for name, count in counts.items() if count != 1)
    discovered = set(discover_concrete_test_cases())
    unknown = sorted(set(assigned) - discovered)
    missing = sorted(discovered - set(assigned))
    empty = sorted(name for name in SHARD_ORDER if not SHARDS.get(name))
    fast_duplicate = sorted(
        selector for selector, count in collections.Counter(FAST_SELECTORS).items()
        if count != 1
    )
    fast_unknown = sorted(
        selector for selector in FAST_SELECTORS if not selector_exists(selector)
    )
    contract_classes = set(SHARDS.get('contracts', ()))
    fast_outside_contracts = sorted(
        selector for selector in FAST_SELECTORS
        if selector_class_name(selector) not in contract_classes
    )
    if (duplicate or unknown or missing or empty or
        set(SHARDS) != set(SHARD_ORDER) or fast_duplicate or fast_unknown or
        fast_outside_contracts):
        raise ValueError(
            f'catalog invalid: duplicate={duplicate}; unknown={unknown}; '
            f'missing={missing}; empty={empty}; '
            f'fast_duplicate={fast_duplicate}; fast_unknown={fast_unknown}; '
            f'fast_outside_contracts={fast_outside_contracts}'
        )


def selectors_for_profile(name: str) -> tuple[str, ...]:
    if name == 'full':
        shards = SHARD_ORDER
    elif name == 'fast':
        return FAST_SELECTORS
    else:
        raise ValueError(f'unknown validation profile: {name}')
    return tuple(selector for shard in shards for selector in SHARDS[shard])


def selectors_for_shard(name: str) -> tuple[str, ...]:
    try:
        return SHARDS[name]
    except KeyError:
        raise ValueError(f'unknown validation shard: {name}') from None


def matrix_document() -> dict[str, list[dict[str, str]]]:
    return {'include': [{'shard': name} for name in SHARD_ORDER]}
