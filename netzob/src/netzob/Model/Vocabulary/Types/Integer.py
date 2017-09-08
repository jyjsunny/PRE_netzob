# -*- coding: utf-8 -*-

# +---------------------------------------------------------------------------+
# |          01001110 01100101 01110100 01111010 01101111 01100010            |
# |                                                                           |
# |               Netzob : Inferring communication protocols                  |
# +---------------------------------------------------------------------------+
# | Copyright (C) 2011-2017 Georges Bossert and Frédéric Guihéry              |
# | This program is free software: you can redistribute it and/or modify      |
# | it under the terms of the GNU General Public License as published by      |
# | the Free Software Foundation, either version 3 of the License, or         |
# | (at your option) any later version.                                       |
# |                                                                           |
# | This program is distributed in the hope that it will be useful,           |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of            |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the              |
# | GNU General Public License for more details.                              |
# |                                                                           |
# | You should have received a copy of the GNU General Public License         |
# | along with this program. If not, see <http://www.gnu.org/licenses/>.      |
# +---------------------------------------------------------------------------+
# | @url      : http://www.netzob.org                                         |
# | @contact  : contact@netzob.org                                            |
# | @sponsors : Amossys, http://www.amossys.fr                                |
# |             Supélec, http://www.rennes.supelec.fr/ren/rd/cidre/           |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | File contributors :                                                       |
# |       - Georges Bossert <georges.bossert (a) supelec.fr>                  |
# |       - Frédéric Guihéry <frederic.guihery (a) amossys.fr>                |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Standard library imports                                                  |
# +---------------------------------------------------------------------------+
import struct
import math
import random
import unittest
from bitarray import bitarray
from typing import Iterable

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Local application imports                                                 |
# +---------------------------------------------------------------------------+
from netzob.Model.Vocabulary import partialclass
from netzob.Model.Vocabulary.Types.AbstractType import AbstractType, Endianness, Sign, UnitSize


class Integer(AbstractType):
    r"""The Integer class enables to represent an integer, with the
    capability to express constraints regarding the sign, the
    endianness and the unit size.

    The Integer constructor expects some parameters:

    :param value: The current value of the type instance.
    :param interval: The interval of permitted values for the Integer. This information is used to compute the size of the Integer.
    :param unitSize: The unitsize of the current value. Values must be one of UnitSize.SIZE_* (see below for supported unit sizes). The default value is UnitSize.SIZE_8.

      The following unit sizes are available:

      * UnitSize.SIZE_1
      * UnitSize.SIZE_4
      * UnitSize.SIZE_8 (default unit size)
      * UnitSize.SIZE_16
      * UnitSize.SIZE_24
      * UnitSize.SIZE_32
      * UnitSize.SIZE_64

    :param endianness: The endianness of the current value. Values must be Endianness.BIG or Endianness.LITTLE. The default value is Endianness.BIG.

      The following endianness are available:

      * Endianness.BIG (default endianness)
      * Endianness.LITTLE

    :param sign: The sign of the current value. Values must be Sign.SIGNED or Sign.UNSIGNED. The default value is Sign.SIGNED.

      The following signs are available:

      * Sign.SIGNED (default sign)
      * Sign.UNSIGNED

    :type value: :class:`bitarray` or :class:`int`, optional
    :type interval: an :class:`int` or a tuple with the min and the max values specified as :class:`int`, optional
    :type unitSize: :class:`UnitSize <netzob.Model.Vocabulary.Types.AbstractType.UnitSize>`, optional
    :type endianness: :class:`Endianness <netzob.Model.Vocabulary.Types.AbstractType.Endianness>`, optional
    :type sign: :class:`Sign <netzob.Model.Vocabulary.Types.AbstractType.Sign>`, optional


    The Integer class provides the following public variables:

    :var typeName: The name of the implemented data type.
    :var value: The current value of the instance. This value is represented
                under the bitarray format.
    :var size: The size of the expected data type defined by a tuple (min integer, max integer).
               Instead of a tuple, an integer can be used to represent both min and max value.
    :var unitSize: The unitSize of the current value.
    :var endianness: The endianness of the current value.
    :var sign: The sign of the current value.
    :vartype typeName: :class:`str`
    :vartype value: :class:`bitarray`
    :vartype size: a tuple (:class:`int`, :class:`int`) or :class:`int`
    :vartype unitSize: :class:`str`
    :vartype endianness: :class:`str`
    :vartype sign: :class:`str`


    **Examples of Integer object instantiations**

    The following example shows how to define an integer encoded in
    sequences of 8 bits and with a default value of 12 (thus producing
    ``\x0c``):

    >>> from netzob.all import *
    >>> i = Integer(value=12, unitSize=UnitSize.SIZE_8)
    >>> i.generate().tobytes()
    b'\x0c'

    The following example shows how to define an integer encoded in
    sequences of 32 bits and with a default value of 12 (thus
    producing ``\x00\x00\x00\x0c``):

    >>> from netzob.all import *
    >>> i = Integer(value=12, unitSize=UnitSize.SIZE_32)
    >>> i.generate().tobytes()
    b'\x00\x00\x00\x0c'

    The following example shows how to define an integer encoded in
    sequences of 32 bits in little endian with a default value of 12
    (thus producing ``\x0c\x00\x00\x00``):

    >>> from netzob.all import *
    >>> i = Integer(value=12, unitSize=UnitSize.SIZE_32, endianness=Endianness.LITTLE)
    >>> i.generate().tobytes()
    b'\x0c\x00\x00\x00'

    The following example shows how to define a signed integer
    encoded in sequences of 16 bits with a default value of -12 (thus
    producing ``\xff\xf4``):

    >>> from netzob.all import *
    >>> i = Integer(value=-12, sign=Sign.SIGNED, unitSize=UnitSize.SIZE_16)
    >>> i.generate().tobytes()
    b'\xff\xf4'


    **Examples of pre-defined Integer types**

    For convenience, common specific integer types are also available, with
    pre-defined values of :attr:`unitSize`, :attr:`sign` and :attr:`endianness`
    attributes. They are used to shorten calls of singular definitions.

    For example, a *16-bit little-endian unsigned* Integer is classically defined
    like this:

    >>> from netzob.all import *
    >>> i = Integer(42,
    ...             unitSize=UnitSize.SIZE_16,
    ...             sign=Sign.UNSIGNED,
    ...             endianness=Endianness.LITTLE)

    Could also be called in an equivalent form:

    >>> from netzob.all import *
    >>> i = uint16le(42)

    There is an equivalence between these two integers, for every
    internal value of the type:

    >>> from netzob.all import *
    >>> i1 = Integer(42,
    ...              unitSize=UnitSize.SIZE_16,
    ...              sign=Sign.UNSIGNED,
    ...              endianness=Endianness.LITTLE)
    >>> i2 = uint16le(42)
    >>> i1, i2
    (42, 42)
    >>> i1 == i2
    True

    But a comparison between two specific integers of different kind will
    always fail, even if their values look equivalent:

    >>> from netzob.all import *
    >>> i1 = uint16le(42)
    >>> i2 = uint32le(42)
    >>> i1 == i2
    False

    And even when the concrete value seems identical, the integer
    objects are not:

    >>> from netzob.all import *
    >>> i1 = uint16le(42)
    >>> i2 = int16le(42)
    >>> i1, i2
    (42, 42)
    >>> print(i1, i2)
    Integer=42 ((None, None)) Integer=42 ((None, None))
    >>> i1 == i2
    False


    **Integer raw representations**

    The following examples show how to create integers with different
    raw representation, depending on data type attributes. In these
    examples, we create a 16 bits little endian, a 16 bits big endian,
    a 32 bits little endian and a 32 bits big endian:

    >>> from netzob.all import *
    >>> int16le(1234).value.tobytes()
    b'\xd2\x04'
    >>> int16be(1234).value.tobytes()
    b'\x04\xd2'
    >>> int32le(1234).value.tobytes()
    b'\xd2\x04\x00\x00'
    >>> int32be(1234).value.tobytes()
    b'\x00\x00\x04\xd2'


    **Representation of Integer type objects**

    The following examples show the representation of Integer objects
    with and without default value.

    >>> from netzob.all import *
    >>> i = int16le(value=12)
    >>> str(i)
    'Integer=12 ((None, None))'

    >>> from netzob.all import *
    >>> i = int16le()
    >>> str(i)
    'Integer=None ((-32768, 32767))'


    **Encoding of Integer type objects**

    The following examples show the encoding of Integer objects with
    and without default value.

    >>> from netzob.all import *
    >>> i = int32le(value=12)
    >>> repr(i)
    '12'

    >>> from netzob.all import *
    >>> i = int32le()
    >>> repr(i)
    'None'

    """

    def __init__(self,
                 value=None,
                 interval=None,
                 unitSize=AbstractType.defaultUnitSize(),
                 endianness=AbstractType.defaultEndianness(),
                 sign=AbstractType.defaultSign()):

        # Convert value to bitarray
        if value is not None and not isinstance(value, bitarray):
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray

            # Check if value is correct
            if not isinstance(value, int):
                raise ValueError("Input value shoud be a integer. Value received: '{}'".format(value))

            value = TypeConverter.convert(
                value,
                Integer,
                BitArray,
                src_unitSize=unitSize,
                src_endianness=endianness,
                src_sign=sign,
                dst_unitSize=unitSize,
                dst_endianness=endianness,
                dst_sign=sign)

        if value is None:
            interval = self._normalizeInterval(interval, unitSize, sign)
        else:
            interval = (None, None)

        super().__init__(
            self.__class__.__name__,
            value,
            interval,
            unitSize=unitSize,
            endianness=endianness,
            sign=sign)

    def _normalizeInterval(self, interval, unitSize, sign):

        if interval is None:
            interval = (None, None)

        if not (isinstance(interval, tuple) and len(interval) == 2):
            raise ValueError("Input interval shoud be a tuple of two integers. Value received: '{}'".format(interval))

        # Compute min and max value
        min_interval = getMinStorageValue(unitSize=unitSize, sign=sign)
        max_interval = getMaxStorageValue(unitSize=unitSize, sign=sign)

        if ((interval[0] is not None and interval[0] < min_interval) or
            (interval[1] is not None and interval[1] > max_interval)):
            raise ValueError("Specified interval '{}' does not fit in specified unitSize '{}'".format(interval, unitSize))

        # Reset min and max value if a valid interval is provided
        if interval[0] is not None:
            min_interval = interval[0]
        if interval[1] is not None:
            max_interval = interval[1]

        return min_interval, max_interval

    def getMinValue(self):
        if self.value is None:
            return self.size[0]
        else:
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray
            return TypeConverter.convert(self.value, BitArray, Integer, dst_unitSize=self.unitSize, dst_endianness=self.endianness, dst_sign=self.sign)

    def getMaxValue(self):
        if self.value is None:
            return self.size[1]
        else:
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray
            return TypeConverter.convert(self.value, BitArray, Integer, dst_unitSize=self.unitSize, dst_endianness=self.endianness, dst_sign=self.sign)

    def getMinStorageValue(self):
        return getMinStorageValue(self.unitSize, self.sign)

    def getMaxStorageValue(self):
        return getMaxStorageValue(self.unitSize, self.sign)

    def canParse(self,
                 data,
                 unitSize=AbstractType.defaultUnitSize(),
                 endianness=AbstractType.defaultEndianness(),
                 sign=AbstractType.defaultSign()):
        """This method returns True if data is a Integer.
        For the moment its always true because we consider
        the integer type to be very similar to the raw type.

        :param data: the data to check
        :type data: python raw
        :return: True if data is can be parsed as a Integer
        :rtype: bool
        :raise: TypeError if the data is None


        >>> from netzob.all import *
        >>> from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
        >>> Integer().canParse(10)
        True

        >>> Integer().canParse(TypeConverter.convert(10, Integer, BitArray))
        True

        >>> Integer(10).canParse(11)
        False

        By default, an Integer() with no parameter has a storage size
        of 8 bits:

        >>> Integer().canParse(-128)
        True

        >>> Integer().canParse(-129)
        Traceback (most recent call last):
        ...
        struct.error: byte format requires -128 <= number <= 127

        To specify a bigger storage, the unitSize should be used:

        >>> Integer(unitSize=UnitSize.SIZE_16).canParse(-129)
        True

        """

        if data is None:
            raise TypeError("data cannot be None")

        if not isinstance(data, int) and len(data) == 0:  # data cannot be an empty string
            return False

        # Convert data to bitarray
        if data is not None and not isinstance(data, bitarray):
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray

            # Check if data is correct
            if not isinstance(data, int):
                raise ValueError("Input data shoud be a integer. Data received: '{}'".format(data))

            data = TypeConverter.convert(
                data,
                Integer,
                BitArray,
                src_unitSize=self.unitSize,
                src_endianness=self.endianness,
                src_sign=self.sign,
                dst_unitSize=self.unitSize,
                dst_endianness=self.endianness,
                dst_sign=self.sign)

        # Compare with self.value if it is defined
        if self.value is not None:
            return self.value == data

        # Else, compare with expected size
        if self.size is not None and isinstance(self.size, Iterable) and len(self.size) == 2:
            minSize = min(self.size)
            maxSize = max(self.size)

            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray
            int_data = TypeConverter.convert(data, BitArray, Integer,
                                             dst_unitSize=self.unitSize,
                                             dst_endianness=self.endianness,
                                             dst_sign=self.sign)

            return minSize <= int_data <= maxSize

        raise Exception("Cannot parse this data '{}' because no domain is "
                        "expected.".format(data))

    @staticmethod
    def decode(data,
               unitSize=AbstractType.defaultUnitSize(),
               endianness=AbstractType.defaultEndianness(),
               sign=AbstractType.defaultSign()):
        r"""This method convert the specified data in python raw format.

        >>> from netzob.all import *
        >>> Integer.decode(23)
        b'\x17'

        >>> Integer.decode(-1, sign=Sign.UNSIGNED)
        Traceback (most recent call last):
        ...
        struct.error: ubyte format requires 0 <= number <= 255

        >>> Integer.decode(-1, sign=Sign.SIGNED)
        b'\xff'

        >>> Integer.decode(2000000000000000)
        Traceback (most recent call last):
        ...
        struct.error: byte format requires -128 <= number <= 127

        >>> Integer.decode(2000000000000000, unitSize=UnitSize.SIZE_64)
        b'\x00\x07\x1a\xfdI\x8d\x00\x00'

        >>> Integer.decode(25, unitSize=UnitSize.SIZE_16, endianness=Endianness.LITTLE)
        b'\x19\x00'
        >>> Integer.decode(25, unitSize=UnitSize.SIZE_16, endianness=Endianness.BIG)
        b'\x00\x19'

        >>> val = 167749568
        >>> a = Integer.decode(val, unitSize=UnitSize.SIZE_32)
        >>> b = Integer.encode(a, unitSize=UnitSize.SIZE_32)
        >>> b == val
        True


        :param data: the data encoded in Integer which will be decoded in raw
        :type data: the current type
        :keyword unitSize: the unitsize to consider while encoding. Values must be one of UnitSize.SIZE_*
        :type unitSize: str
        :keyword endianness: the endianness to consider while encoding. Values must be Endianness.BIG or Endianness.LITTLE
        :type endianness: str
        :keyword sign: the sign to consider while encoding Values must be Sign.SIGNED or Sign.UNSIGNED
        :type sign: :class:`Enum`

        :return: data encoded in python raw
        :rtype: python raw
        :raise: TypeError if parameters are not valid.
        """
        if data is None:
            raise TypeError("data cannot be None")

        f = Integer.computeFormat(unitSize, endianness, sign)

        return struct.pack(f, int(data))

    @staticmethod
    def encode(data,
               unitSize=AbstractType.defaultUnitSize(),
               endianness=AbstractType.defaultEndianness(),
               sign=AbstractType.defaultSign()):
        r"""This method converts a python raw data to an Integer.

        >>> from netzob.all import *

        >>> raw = Integer.decode(23)
        >>> Integer.encode(raw)
        23

        >>> raw = Integer.decode(1200, unitSize=UnitSize.SIZE_16)
        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_16)
        1200

        >>> raw = Integer.decode(25, unitSize=UnitSize.SIZE_16, endianness=Endianness.LITTLE)
        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_16, endianness=Endianness.BIG)
        6400
        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_16, endianness=Endianness.LITTLE)
        25

        >>> Integer.encode(b'\xcc\xac\x9c\x0c\x1c\xacL\x1c,\xac', unitSize=UnitSize.SIZE_8)
        -395865088909314208584756

        >>> raw = b'\xcc\xac\x9c'
        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_16, endianness=Endianness.BIG)
        10210476

        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_32, endianness=Endianness.BIG)
        13413532

        >>> Integer.encode(raw, unitSize=UnitSize.SIZE_32, endianness=Endianness.LITTLE)
        10267852

        :param data: the data encoded in python raw which will be encoded in current type
        :type data: python raw
        :keyword unitSize: the unitsize to consider while encoding. Values must be one of UnitSize.SIZE_*
        :type unitSize: :class:`Enum`
        :keyword endianness: the endianness to consider while encoding. Values must be Endianness.BIG or Endianness.LITTLE
        :type endianness: :class:`Enum`
        :keyword sign: the sign to consider while encoding Values must be Sign.SIGNED or Sign.UNSIGNED
        :type sign: :class:`Enum`

        :return: data encoded in python raw
        :rtype: python raw
        :raise: TypeError if parameters are not valid.
        """
        if data is None:
            raise TypeError("data cannot be None")

        perWordFormat = Integer.computeFormat(unitSize, endianness, sign)

        nbWords = int(len(data) * 8 / int(unitSize.value))

        # Check whether the input data matches unitSize. If not take 
        # precautions to able to pad it with null bytes later.
        padding_nullbytes = 0
        rest = (len(data) * 8) % int(unitSize.value)
        if rest != 0:
            nbWords += 1
            padding_nullbytes = (int(unitSize.value) - rest) / 8

        finalValue = 0

        iWord = 0
        start = 0
        end = nbWords
        inc = 1
        if endianness == Endianness.BIG:
            end = 0
            start = nbWords
            inc = -1

        for i in range(start, end, inc):
            # Extract the portion that represents the current word
            startPos = int(iWord * int(unitSize.value) / 8)
            endPos = int(iWord * int(unitSize.value) / 8 + int(unitSize.value) / 8)

            wordData = data[startPos:endPos]

            # Pad with null bytes to statisfy the unitSize.
            if padding_nullbytes > 0 and i == (end - inc):
                if endianness == Endianness.BIG:
                    wordData = b'\x00' * int(padding_nullbytes) + wordData
                elif endianness == Endianness.LITTLE:
                    wordData += b'\x00' * int(padding_nullbytes)
                else:
                    raise ValueError(
                        "Invalid endianness value: {0}".format(endianness))

            unpackedWord = struct.unpack(perWordFormat, wordData)[0]
            unpackedWord = unpackedWord << int(unitSize.value) * iWord

            finalValue = finalValue + unpackedWord

            iWord += 1

        return finalValue

    @staticmethod
    def computeFormat(unitSize, endianness, sign):
        # endian
        if endianness == Endianness.BIG:
            endianFormat = '>'
        elif endianness == Endianness.LITTLE:
            endianFormat = '<'
        else:
            raise ValueError(
                "Invalid endianness value: {0}".format(endianness))

        # unitSize
        if unitSize == UnitSize.SIZE_8:
            unitFormat = 'b'
        elif unitSize == UnitSize.SIZE_16:
            unitFormat = 'h'
        elif unitSize == UnitSize.SIZE_32:
            unitFormat = 'i'
        elif unitSize == UnitSize.SIZE_64:
            unitFormat = 'q'
        else:
            raise ValueError(
                "Only 8, 16, 32 and 64 bits unitsize are available for integers"
            )
        # sign
        if sign == Sign.UNSIGNED:
            unitFormat = unitFormat.upper()

        return endianFormat + unitFormat

    def generate(self):
        """Generates a random integer inside the given interval.

        >>> from netzob.all import *
        >>> v1 = Integer(interval=(-10, -1)).generate()
        >>> assert v1[0] is True  # sign bit (MSB) is set

        >>> v2 = Integer(42, sign=Sign.UNSIGNED)
        >>> v2.generate()
        bitarray('00101010')

        >>> v3 = uint16be(0xff00)
        >>> v3.generate()
        bitarray('1111111100000000')
        """
        if self.value is not None:
            return self.value
        elif self.size is not None and isinstance(self.size, Iterable) and len(self.size) == 2:
            from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
            from netzob.Model.Vocabulary.Types.BitArray import BitArray

            # Size is interpreted here as an interval
            val = random.randint(min(self.size), max(self.size))
            return TypeConverter.convert(val, Integer, BitArray,
                                         src_sign=self.sign,
                                         src_unitSize=self.unitSize,
                                         src_endianness=self.endianness,
                                         dst_sign=self.sign,
                                         dst_unitSize=self.unitSize,
                                         dst_endianness=self.endianness)
        else:
            raise Exception("Cannot generate integer value, as nor constant value or interval is defined")


    def _test(self):
        r"""
        Examples of Integer internal attribute access

        >>> from netzob.all import *
        >>> cDec = Integer(20)
        >>> print(repr(cDec))
        20
        >>> cDec.typeName
        'Integer'
        >>> cDec.value
        bitarray('00010100')

        The required size in bits is automatically computed following the specifications:

        >>> dec = Integer(10)
        >>> dec.size
        (None, None)

        >>> dec = Integer(interval=(-120, 10))
        >>> dec.size
        (-120, 10)

        Symbol abstraction:

        >>> from netzob.all import Field, Symbol
        >>> domains = [
        ...     uint16(1), int8le(), int32be(0x007F0041), uint16le(2)
        ... ]
        >>> symbol = Symbol(fields=[Field(d, str(i)) for i, d in enumerate(domains)])
        >>> data = b''.join(f.specialize() for f in symbol.fields)
        >>> Symbol.abstract(data, [symbol])  #doctest: +ELLIPSIS
        (Symbol, OrderedDict([('0', b'\x00\x01'), ('1', b'...'), ('2', b'\x00\x7f\x00A'), ('3', b'\x02\x00')]))

        """


def getMinStorageValue(unitSize, sign):
    if sign == Sign.UNSIGNED:
        return 0
    else:
        return -int((2**int(unitSize.value)) / 2)


def getMaxStorageValue(unitSize, sign):
    if sign == Sign.UNSIGNED:
        return 2**unitSize.value - 1
    else:
        return int((2**unitSize.value) / 2) - 1


int8be   = partialclass(Integer,
                        unitSize=UnitSize.SIZE_8,
                        sign=Sign.SIGNED,
                        endianness=Endianness.BIG)
int8le   = partialclass(Integer,
                        unitSize=UnitSize.SIZE_8,
                        sign=Sign.SIGNED,
                        endianness=Endianness.LITTLE)
uint8be  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_8,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.BIG)
uint8le  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_8,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.LITTLE)
int16be  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_16,
                        sign=Sign.SIGNED,
                        endianness=Endianness.BIG)
int16le  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_16,
                        sign=Sign.SIGNED,
                        endianness=Endianness.LITTLE)
uint16be = partialclass(Integer,
                        unitSize=UnitSize.SIZE_16,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.BIG)
uint16le = partialclass(Integer,
                        unitSize=UnitSize.SIZE_16,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.LITTLE)
int32be  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_32,
                        sign=Sign.SIGNED,
                        endianness=Endianness.BIG)
int32le  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_32,
                        sign=Sign.SIGNED,
                        endianness=Endianness.LITTLE)
uint32be = partialclass(Integer,
                        unitSize=UnitSize.SIZE_32,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.BIG)
uint32le = partialclass(Integer,
                        unitSize=UnitSize.SIZE_32,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.LITTLE)
int64be  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_64,
                        sign=Sign.SIGNED,
                        endianness=Endianness.BIG)
int64le  = partialclass(Integer,
                        unitSize=UnitSize.SIZE_64,
                        sign=Sign.SIGNED,
                        endianness=Endianness.LITTLE)
uint64be = partialclass(Integer,
                        unitSize=UnitSize.SIZE_64,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.BIG)
uint64le = partialclass(Integer,
                        unitSize=UnitSize.SIZE_64,
                        sign=Sign.UNSIGNED,
                        endianness=Endianness.LITTLE)
int8, int16, int32, int64 = int8be, int16be, int32be, int64be
uint8, uint16, uint32, uint64 = uint8be, uint16be, uint32be, uint64be
