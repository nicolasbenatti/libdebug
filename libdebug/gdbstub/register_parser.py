#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RegisterInfo:
    """Represents register metadata coming from the Target Description file.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html for info.
    """

    offset: int
    """Byte-offset of the register in the register blob (i.e., reply to 'g' packet).
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html#read-registers-packet for info.
    """

    index: int
    """Logical order of the register as stated in the Target Description file."""

    name: str
    """Shorthand for the register (e.g. RAX)."""

    size: int
    """Register size in Bytes."""

    def __init__(self, off: int, idx: int, name: str, size: int):
        self.offset = off
        self.index = idx
        self.name = name
        self.size = size

class RegisterInfoParser(ABC):
    """An abstract class which extracts register information from a Target Description file.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Descriptions.html#Target-Descriptions for info.
    """

    @staticmethod
    @abstractmethod
    def parse(data: str) -> list[RegisterInfo]:
        """Returns a list containing useful information as register name and size."""
        pass

