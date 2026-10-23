# Validation

Version 0.2.0 validated on 22 October 2026 in a temporary Linux environment.

| Check | Result |
| --- | --- |
| Complete offline test suite | 305 passed in 21.21 seconds |
| AWS example collection without `--run-aws` | 15 skipped; no AWS access |
| Ruff lint | Passed |
| Ruff format check | Passed |
| Source distribution and wheel build | Passed with setuptools |
| Installed wheel import and organization/endpoint/region smoke check | Passed outside the source directory |
| Wheel/source comparison | Every package source file and `py.typed` matched |
| Source distribution contents | Includes documentation, profile example, tests and aggregator IAM policy |

Environment: Python 3.12.14, boto3/botocore 1.43.117, pytest 9.1.1,
Ruff 0.17.1, build 1.6.1, setuptools 84.2.1. The package declares Python 3.10+
support; only the runtime above was executed in this validation.

The tests cover real botocore request/response models using `Stubber`, plus
route-selection and builder behavior using synthetic data. They include
pagination, Config's recorded/live separation, custom endpoints, per-region
clients, malformed responses, blackholes, full CIDR coverage, prefix lists,
peering, TGW propagation, analysis failure and timeout, unsupported analysis
codes, and cleanup failures. Organization coverage includes independent account
and Region scopes, a separate Config reader, centrally executed cross-account
analysis and cleanup, lazy per-account profiles and sessions, STS account
mismatch rejection, account-qualified endpoint ARNs, shared-VPC ENI ownership,
and TGW ownership distinct from the attached VPC's owner.

No live AWS account or third-party emulator was contacted. These results verify
the library and its SDK contracts. Actual account permissions, Config recording,
regional service support and topology still need to be exercised using the
included opt-in examples in the intended environment.
