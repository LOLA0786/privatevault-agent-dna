"""
Pipeline orchestration.
"""

from __future__ import annotations

from agent_dna.security_validation.framework.report_builder import ReportBuilder


class Pipeline:
    """Simple execution pipeline."""

    def __init__(self):
        self.report_builder = ReportBuilder()

    def process(self, attack_result):
        return self.report_builder.build(attack_result)
