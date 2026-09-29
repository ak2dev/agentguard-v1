"""Analyzer registry. Order matters: unit builders and evidence producers run
before rules that consume their output; correlators run last."""

from __future__ import annotations

import importlib.util

from ..correlate.cred_egress import CredEgressCorrelator
from ..correlate.flows import FlowAnalyzer
from ..policy.analyzer import PolicyAnalyzer
from .capabilities import CapabilityAnalyzer
from .code import CodeAnalyzer
from .hidden import HiddenContentAnalyzer
from .mcp import McpConfigAnalyzer, McpMetaAnalyzer, McpUnitsBuilder
from .network_rules import AuthAnalyzer, OsvAnalyzer, PackageAgeAnalyzer, ProvenanceAnalyzer
from .regex_rules import RegexRuleAnalyzer
from .supply_chain import DriftAnalyzer, IntelAnalyzer, RegistryOfflineAnalyzer
from .skill import (
    BundleAnalyzer,
    SkillExecAnalyzer,
    SkillPrivilegeAnalyzer,
    SkillSpecAnalyzer,
    TyposquatAnalyzer,
)
from .system import LimitsAnalyzer

ANALYZERS: list[type] = [
    LimitsAnalyzer,
    McpUnitsBuilder,
    SkillSpecAnalyzer,
    SkillExecAnalyzer,
    McpConfigAnalyzer,
    HiddenContentAnalyzer,
    RegexRuleAnalyzer,
    McpMetaAnalyzer,
    CodeAnalyzer,
    SkillPrivilegeAnalyzer,
    CapabilityAnalyzer,
    TyposquatAnalyzer,
    BundleAnalyzer,
    IntelAnalyzer,
    RegistryOfflineAnalyzer,
    AuthAnalyzer,
    ProvenanceAnalyzer,
    OsvAnalyzer,
    PackageAgeAnalyzer,
]

CORRELATORS: list[type] = [
    CredEgressCorrelator,
    FlowAnalyzer,
    DriftAnalyzer,
    PolicyAnalyzer,
]


def native_available(analyzer_cls: type) -> bool:
    modules = getattr(analyzer_cls, "native_modules", ())
    return all(importlib.util.find_spec(m) is not None for m in modules)


def all_stages() -> list[type]:
    return [*ANALYZERS, *CORRELATORS]
