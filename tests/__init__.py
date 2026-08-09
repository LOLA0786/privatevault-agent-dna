"""Test package root.

Kept as a regular package so cross-module helpers
(``from tests....``) resolve to this repository even when an ambient
``PYTHONPATH`` entry exposes another project named ``tests``.
"""
