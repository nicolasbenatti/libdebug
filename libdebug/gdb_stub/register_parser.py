#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RegisterInfo:
    index: int
    """Index of the register. It's used to correctly parse data coming from the stub."""

    name: str
    """Shorthand for the register. (e.g. RAX)"""

    size: int
    """Register size in bits."""

    def __init__(self, idx: int, name: str, size: int):
        self.index = idx
        self.name = name
        self.size = size

class RegisterInfoParser(ABC):
    """An abstract class which extracts register information from a Target Description file.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Descriptions.html#Target-Descriptions for info"""

    @staticmethod
    @abstractmethod
    def parse(data: str) -> list[RegisterInfo]:
        """Returns a list containing useful information as register name and size."""
        pass

