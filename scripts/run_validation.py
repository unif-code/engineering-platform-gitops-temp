#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import unittest

from validation_catalog import (
    matrix_document,
    selectors_for_profile,
    selectors_for_shard,
    validate_catalog,
)


def run_selectors(selectors: tuple[str, ...]) -> int:
    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromNames(list(selectors))
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 2
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--profile', choices=('fast', 'full'))
    operation.add_argument('--shard')
    operation.add_argument('--matrix', action='store_true')
    operation.add_argument('--validate-catalog', action='store_true')
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    validate_catalog()
    if arguments.profile:
        return run_selectors(selectors_for_profile(arguments.profile))
    if arguments.shard:
        return run_selectors(selectors_for_shard(arguments.shard))
    if arguments.matrix:
        print(json.dumps(matrix_document(), separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
