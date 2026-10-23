"""Inspect or explicitly clean up a recorded temporary Lambda probe run."""

from ._recovery import main, recover_probes

__all__ = ["recover_probes"]


if __name__ == "__main__":
    raise SystemExit(main())
