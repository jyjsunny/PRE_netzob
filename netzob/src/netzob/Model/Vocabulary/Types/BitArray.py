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
import random
import unittest
from collections import OrderedDict

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+
from bitarray import bitarray

# +---------------------------------------------------------------------------+
# | Local application imports                                                 |
# +---------------------------------------------------------------------------+
from netzob.Common.Utils.Decorators import typeCheck, NetzobLogger
from netzob.Model.Vocabulary.Types.AbstractType import AbstractType, Endianness, Sign, UnitSize


@NetzobLogger
class BitArray(AbstractType):
    r"""This class defines a BitArray type.

    The BitArray type describes an object that contains a
    sequence of bits of arbitrary sizes.

    The BitArray constructor expects some parameters:

    :param value: The current value of the type instance.
    :param nbBits: The size in bits that this value can take.
    :type value: :class:`bitarray`, optional
    :type nbBits: an :class:`int` or a tuple with the min and the max size specified as :class:`int`, optional


    The BitArray class provides the following public variables:

    :var typeName: The name of the implemented data type.
    :var value: The current value of the instance. This value is represented
                under the bitarray format.
    :var size: The size in bits of the expected data type defined by a tuple (min, max).
               Instead of a tuple, an integer can be used to represent both min and max value.
    :var constants: A list of named constant used to access the bitarray internal elements.
    :vartype typeName: :class:`str`
    :vartype value: :class:`bitarray`
    :vartype size: a tuple (:class:`int`, :class:`int`) or :class:`int`
    :vartype constants: a :class:`list` of :class:`str`

    The following example show how to define a BitArray
    containing a fixed constant.

    >>> from netzob.all import *  
    >>> b = BitArray('00001111')
    >>> b.generate().tobytes()
    b'\x0f'


    **Bitarray of fixed and dynamic sizes**

    The following example shows how to define a bitarray of 1 bit, 47
    bits, 64 bits and then a bitarray whith a variable size between 13
    and 128 bits:

    >>> from netzob.all import *
    >>> b = BitArray(nbBits=1)
    >>> len(b.generate())
    1

    >>> from netzob.all import *
    >>> b = BitArray(nbBits=47)
    >>> len(b.generate())
    47

    >>> from netzob.all import *
    >>> b = BitArray(nbBits=64)
    >>> len(b.generate())
    64

    >>> from netzob.all import *
    >>> b = BitArray(nbBits=(13, 128))
    >>> 13 <= len(b.generate()) <= 128
    True


    **Accessing bitarray elements by named constant**
    
    In the following example, we define a bitarray with two
    elements. As this bitarray has a fixed length, element are
    automatically accessible by predefined named constants ('item_0'
    and 'item_1'):

    >>> from netzob.all import *
    >>> b = BitArray('00')
    >>> b.constants
    ['item_0', 'item_1']

    Bitarray element names can be changed:

    >>> from netzob.all import *
    >>> b.constants[0] = 'Urgent flag'
    >>> b.constants[1] = 'Data flag'
    >>> b.constants
    ['Urgent flag', 'Data flag']

    Bitarray element can be accessed in read or write mode:

    >>> from netzob.all import *
    >>> b['Urgent flag']
    False
    >>> b['Urgent flag'] = True
    >>> b['Urgent flag']
    True

    Bitarray element can be used with binary operators:

    >>> from netzob.all import *
    >>> b['Urgent flag'] |= b['Data flag']
    >>> b['Urgent flag']
    True

    """

    def __init__(self, value=None, nbBits=(None, None)):

        # Handle input value
        if value is not None and not isinstance(value, bitarray):

            # Check if value is correct, and normalize it in str object, and then in bitarray
            if isinstance(value, str):
                try:
                    value = bitarray(value)
                except Exception as e:
                    raise ValueError("Input value for the following BitArray is incorrect: '{}'. Error: '{}'".format(value, e))
            else:
                raise ValueError("Unsupported input format for value: '{}', type: '{}'".format(value, type(value)))

        super(BitArray, self).__init__(self.__class__.__name__, value, nbBits)
        self.constants = None  # A list of named constant used to access the bitarray elements

        # When value is not None, we can access each element of the bitarray with named constants
        if value is not None:
            self.constants = []
            for i in range(len(value)):
                self.constants.append("item_{}".format(i))

    def __getitem__(self, key):
        if isinstance(key, int):
            if self.value is not None:
                return self.value[key]
            else:
                raise ValueError("Cannot access internal bitarray value, as it does not exist.")
        else:
            if self.constants is not None:
                return self.value[self.constants.index(key)]
            else:
                raise ValueError("Named constant access to bitarray elements is not possible, as bitarray is not of fixed length.")

    def __setitem__(self, key, value):
        if isinstance(key, int):
            if self.value is not None:
                self.value[key] = value
            else:
                raise ValueError("Cannot access internal bitarray value, as it does not exist.")
        else:
            if self.constants is not None:
                self.value[self.constants.index(key)] = value
            else:
                raise ValueError("Named constant access to bitarray elements is not possible, as bitarray is not of fixed length.")

    def canParse(self,
                 data,
                 unitSize=AbstractType.defaultUnitSize(),
                 endianness=AbstractType.defaultEndianness(),
                 sign=AbstractType.defaultSign()):
        """For the moment its always true because we consider
        the decimal type to be very similar to the raw type.

        :param data: the data to check
        :type data: python raw
        :return: True if data can be parsed as a BitArray
        :rtype: bool
        :raise: TypeError if the data is None


        >>> from netzob.all import *
        >>> BitArray().canParse(String("hello john").value)
        True

        >>> BitArray(nbBits=8).canParse(bitarray('01010101'))
        True

        >>> BitArray(nbBits=8).canParse(bitarray('010101011'))
        False

        >>> BitArray('11110101').canParse(bitarray('11110101'))
        True

        """

        if data is None:
            raise TypeError("data cannot be None")

        if not isinstance(data, bitarray):
            raise TypeError("Data should be a python raw ({0}:{1})".format(
                data, type(data)))

        if len(data) == 0:
            return False

        # Firtly, check if self.value matches the data
        if self.value is not None:
            if self.value == data:
                return True

        # Else, check if the data is comprised between the expected sizes
        (nbMinBits, nbMaxBits) = self.size

        nbBitsData = len(data)

        if nbMinBits is not None and nbMinBits > nbBitsData:
            return False
        if nbMaxBits is not None and nbMaxBits < nbBitsData:
            return False

        return True

    def generate(self, generationStrategy=None):
        """Generates a random bitarray that respects the constraints.
        """

        if self.value is not None:
            return self.value

        minSize, maxSize = self.size
        if maxSize is None:
            maxSize = AbstractType.MAXIMUM_GENERATED_DATA_SIZE

        generatedSize = random.randint(minSize, maxSize)
        randomContent = [random.randint(0, 1) for i in range(0, generatedSize)]
        return bitarray(randomContent, endian=self.endianness.value)

    @staticmethod
    @typeCheck(bitarray)
    def decode(data,
               unitSize=AbstractType.defaultUnitSize(),
               endianness=AbstractType.defaultEndianness(),
               sign=AbstractType.defaultSign()):
        """This method convert the specified data in python raw format.

        >>> from netzob.all import *
        >>> from netzob.Model.Vocabulary.Types.BitArray import BitArray
        >>> d = String.decode("hello john")
        >>> r = BitArray.encode(d)
        >>> r.to01()
        '01101000011001010110110001101100011011110010000001101010011011110110100001101110'
        >>> t = BitArray.decode(r)
        >>> t
        b'hello john'


        :param data: the data encoded in BitArray which will be decoded in raw
        :type data: bitarray
        :keyword unitSize: the unit size of the specified data
        :type unitSize: :class:`UnitSize <netzob.Model.Vocabulary.Types.UnitSize.UnitSize>`
        :keyword endianness: the endianness of the specified data
        :type endianness: :class:`Endianness <netzob.Model.Vocabulary.Types.Endianness.Endianness>`
        :keyword sign: the sign of the specified data
        :type sign: :class:`Sign <netzob.Model.Vocabulary.Types.Sign.Sign>`

        :return: data encoded in python raw
        :rtype: python raw
        :raise: TypeError if parameters are not valid.
        """
        if data is None:
            raise TypeError("data cannot be None")
        return data.tobytes()

    @staticmethod
    def encode(data,
               unitSize=AbstractType.defaultUnitSize(),
               endianness=AbstractType.defaultEndianness(),
               sign=AbstractType.defaultSign()):
        """This method convert the python raw data to the BitArray.

        >>> from netzob.all import *
        >>> from netzob.Model.Vocabulary.Types.BitArray import BitArray
        >>> BitArray.encode(Integer.decode(20))
        bitarray('00010100')
        >>> BitArray.encode(Integer.decode(20), endianness=Endianness.LITTLE)
        bitarray('00101000')

        :param data: the data encoded in python raw which will be encoded in current type
        :type data: python raw
        :keyword unitSize: the unitsize to consider while encoding. Values must be one of UnitSize.SIZE_*
        :type unitSize: :class:`Enum`
        :keyword endianness: the endianness to consider while encoding. Values must be Endianness.BIG or Endianness.LITTLE
        :type endianness: :class:`Enum`
        :keyword sign: the sign to consider while encoding Values must be Sign.SIGNED or Sign.UNSIGNED
        :type sign: :class:`Enum`

        :return: data encoded in BitArray
        :rtype: :class:`BitArray <netzob.Model.Vocabulary.Types.BitArray.BitArray>`
        :raise: TypeError if parameters are not valid.
        """
        if data is None:
            raise TypeError("data cannot be None")

        if isinstance(data, bytes):
            norm_data = data
        elif isinstance(data, str):
            norm_data = bytes(data, "utf-8")
        else:
            raise TypeError("Invalid type for: '{}'. Expected bytes or str, and got '{}'".format(data, type(data)))

        b = bitarray(endian=endianness.value)
        b.frombytes(norm_data)
        return b


class __TestBitArray(unittest.TestCase):
    """
    Test class with test-only scenario that should not be documented.
    """

    def test_abstraction_arbitrary_values(self):
        from netzob.all import Field, Symbol
        domains = [
            BitArray(nbBits=8), # BitArray(bitarray("00001111" "1")), BitArray(nbBits=7),
        ]
        symbol = Symbol(fields=[Field(d, str(i)) for i, d in enumerate(domains)])
        data = b''.join(f.specialize() for f in symbol.fields)
        assert Symbol.abstract(data, [symbol])[1]
