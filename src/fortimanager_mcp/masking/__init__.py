"""Reversible data masking for FortiManager MCP (issue #34, FAZ RFC #40).

Off unless ``MASKING_ENABLED`` is set. When on, tool outputs have their
IOC-bearing values replaced by reversible tokens, and any token supplied
back as a tool argument is refused. See ``tokens`` for the marker
vocabulary, ``fpe_engine`` for the ciphers, ``fields`` for the carrier
table, and ``wrapper`` for the tool boundary.
"""
