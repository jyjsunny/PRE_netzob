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
# |             ANSSI,   https://www.ssi.gouv.fr                              |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | File contributors :                                                       |
# |       - Frédéric Guihéry <frederic.guihery (a) amossys.fr>                |
# |       - Rémy Delion <remy.delion (a) amossys.fr>                          |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Standard library imports                                                  |
# +---------------------------------------------------------------------------+
from typing import Dict, Union  # noqa: F401

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Local application imports                                                 |
# +---------------------------------------------------------------------------+
from netzob.Model.Vocabulary.Domain.Variables.AbstractVariable import AbstractVariable
from netzob.Model.Vocabulary.Domain.Variables.Nodes.AbstractVariableNode import AbstractVariableNode
from netzob.Model.Vocabulary.Domain.Variables.Nodes.Repeat import Repeat
from netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt import Alt
from netzob.Model.Vocabulary.Domain.Variables.Nodes.Agg import Agg
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.AbstractType import AbstractType  # noqa: F401
from netzob.Model.Vocabulary.AbstractField import AbstractField
from netzob.Model.Vocabulary.Types.Integer import Integer
from netzob.Model.Vocabulary.Types.String import String
from netzob.Model.Vocabulary.Types.Raw import Raw
from netzob.Model.Vocabulary.Types.HexaString import HexaString
from netzob.Model.Vocabulary.Types.BitArray import BitArray
from netzob.Model.Vocabulary.Types.IPv4 import IPv4
from netzob.Model.Vocabulary.Types.Timestamp import Timestamp
from netzob.Fuzzing.Mutator import Mutator, FuzzingMode
from netzob.Fuzzing.Mutators.AltMutator import AltMutator
from netzob.Fuzzing.Mutators.AggMutator import AggMutator
from netzob.Fuzzing.Mutators.RepeatMutator import RepeatMutator
from netzob.Fuzzing.Mutators.DomainMutator import DomainMutator  # noqa: F401
from netzob.Fuzzing.Mutators.IntegerMutator import IntegerMutator
from netzob.Fuzzing.Mutators.StringMutator import StringMutator
from netzob.Fuzzing.Mutators.TimestampMutator import TimestampMutator
from netzob.Fuzzing.Mutators.IPv4Mutator import IPv4Mutator
from netzob.Fuzzing.Mutators.BitArrayMutator import BitArrayMutator
from netzob.Fuzzing.Mutators.RawMutator import RawMutator
from netzob.Fuzzing.Mutators.HexaStringMutator import HexaStringMutator
from netzob.Common.Utils.Decorators import NetzobLogger, public_api


class MaxFuzzingException(Exception):
    pass


@NetzobLogger
class Fuzz(object):
    r"""The Fuzz class is the entry point for the fuzzing component.

    We can apply fuzzing on symbols, fields, variables and types
    through the :meth:`set <.Fuzz.set>` method.

    The Fuzz constructor expects some parameters:

    :param counterMax: The max number of mutations to produce (a :class:`int`
                       should be used to represent an absolute value, whereas
                       a :class:`float` should be used to represent a ratio in
                       percent).
    :type counterMax: :class:`int` or :class:`float`, optional, default to
                      :attr:`COUNTER_MAX_DEFAULT` = 2**32


    The Fuzz class provides the following public variables:

    :var counterMax: The max number of mutations to produce.
    :vartype counterMax: :class:`int` or :class:`float`

    """

    mappingTypesMutators = {}   # type: Dict[AbstractType, Union[DomainMutator, dict]]
    mappingFieldsMutators = {}  # type: Dict[Field, DomainMutator]

    # Initialize mapping of types with their mutators
    @staticmethod
    def _initializeMappings():
        Fuzz.mappingFieldsMutators = {}

        Fuzz.mappingTypesMutators = {}
        Fuzz.mappingTypesMutators[Integer] = (IntegerMutator, {})
        Fuzz.mappingTypesMutators[String] = (StringMutator, {})
        Fuzz.mappingTypesMutators[HexaString] = (HexaStringMutator, {})
        Fuzz.mappingTypesMutators[Raw] = (RawMutator, {})
        Fuzz.mappingTypesMutators[BitArray] = (BitArrayMutator, {})
        Fuzz.mappingTypesMutators[IPv4] = (IPv4Mutator, {})
        Fuzz.mappingTypesMutators[Timestamp] = (TimestampMutator, {})
        Fuzz.mappingTypesMutators[Repeat] = (RepeatMutator, {})
        Fuzz.mappingTypesMutators[Alt] = (AltMutator, {})
        Fuzz.mappingTypesMutators[Agg] = (AggMutator, {})

    @public_api
    def __init__(self, counterMax=DomainMutator.COUNTER_MAX_DEFAULT):
        # type: (Union[int, float]) -> None

        # Initialize variables from parameters
        self.counterMax = counterMax

        # Initialize mapping between Types and default Mutators with default
        # configuration
        Fuzz._initializeMappings()
        self.mappingTypesMutators = Fuzz.mappingTypesMutators

        # Initialize mapping between Field/Symbols and Mutators
        self.mappingFieldsMutators = Fuzz.mappingFieldsMutators

    @public_api
    def set(self,
            key,
            mode=FuzzingMode.GENERATE,
            generator='xorshift',
            seed=None,
            counterMax=DomainMutator.COUNTER_MAX_DEFAULT,
            **kwargs):
        r"""The :meth:`set <.Fuzz.set>` method specifies the fuzzing
        strategy for a symbol, a field, a variable or a type.

        The :meth:`set <.Fuzz.set>` method expects some parameters:

        :param key: The targeted object (either a symbol, a field, a
                    variable or a type).
        :param mode: The fuzzing strategy, which can be either:

                     * ``FuzzingMode.MUTATE``: in this mode, the specialization process generates a legitimate message from a symbol, then some mutations are applied to it.
                     * ``FuzzingMode.GENERATE``: in this mode, the fuzzing component directly produces a random message.

                     Default value is :attr:`FuzzingMode.GENERATE`.

        :param generator: The underlying generator used to produce
                          pseudo-random or deterministic
                          values.

                          Default generator is ``'xorshift'``, which is
                          efficient to produce unique pseudo-random
                          numbers.

                          Available generators from :class:`randomstate` module are:

                          * ``'mt19937'``
                          * ``'mlfg_1279_861'``
                          * ``'mrg32k3a'``
                          * ``'pcg32'``
                          * ``'pcg64'``
                          * ``'xorshift128'``
                          * ``'xoroshiro128plus'``
                          * ``'xorshift1024'``
                          * ``'dsfmt'``

                          A deterministic is also available
                          (``generator='determinist'``), and
                          may be used in case where a domain has an
                          interval.

        :param seed: An integer used to initialize the underlying
                     generator.

                     Default value is :attr:`Mutator.SEED_DEFAULT` = 10.

        :param counterMax: An integer used to limit the number of
                           mutations.

                           Default value is :attr:`COUNTER_MAX_DEFAULT` = 2**32.

        :param kwargs: Some context dependent parameters (see below)
                       (optional).
        :type key: :class:`Field
                   <netzob.Model.Vocabulary.Field.Field>`,
                   or :class:`Symbol
                   <netzob.Model.Vocabulary.Symbol.Symbol>`,
                   or :class:`Variable
                   <netzob.Model.Vocabulary.Domain.Variables.AbstractVariable.AbstractVariable>`,
                   or :class:`AbstractType
                   <netzob.Model.Vocabulary.Types.AbstractType.AbstractType>`, required
        :type mode: :class:`Enum`, optional
        :type generator: :class:`iter`, optional
        :type seed: :class:`int`, optional
        :type counterMax: :class:`int`, optional
        :type kwargs: :class:`dict`, optional

        The ``kwargs`` parameter is used to provide specific options
        depending on the targeted object type. Available options are
        described in the following table:

        Integer options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be generated between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be generated in [0, 2^N-1], where N is the bitsize (storage) of the field.
                              * If it is a tuple of integers (min, max), the values will be generated between min and max.

                              Default value is dependant on the chosen generator: 

                              * If the generator is `determinist`, default interval will be :attr:`FuzzingInterval.DEFAULT_INTERVAL`.
                              * Else, default interval will be :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated values have to be encoded.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        ====================  =================================================


        String options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        endChar               The :class:`str` character(s) which will end the string. This terminal symbol will be mutated by truncating its value if defined on several bytes.

                              Default value is :attr:`DEFAULT_END_CHAR`. It is used to set the eos parameter of :class:`String <netzob.Model.Vocabulary.Types.String>`.
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be randomly generated with a size between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be randomly generated with a size of [0, 2^N-1], where N is the length in bits of the integer used to represent the String length.
                              * If it is a tuple of integers (min, max), the values will be randomly generated with a size between min and max.

                              Default value is :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated length will be encoded. This parameter should be used in conjunction with :attr:`FuzzingInterval.FULL_INTERVAL` or with a tuple interval, in order to generate String with a length bigger than the original full interval. This parameter will not have any effect when used with :attr:`FuzzingInterval.DEFAULT_INTERVAL`.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        naughtyStrings        The :class:`list` of potentially dangerous :class:`str` elements.

                              Default value is :attr:`StringMutator.DEFAULT_NAUGHTY_STRINGS`.

        ====================  =================================================

        The :attr:`StringMutator.DEFAULT_NAUGHTY_STRINGS` default value is the following:

        .. code-block:: python

           DEFAULT_NAUGHTY_STRINGS = [
                 'System("ls -al /")',
                 '`ls -al /`',
                 'Kernel.exec("ls -al /")',
                 'Kernel.exit(1)',
                 '%x("ls -al /")',
                 '<img \\x00src=x onerror="alert(1)">',
                 '$ENV{"HOME"}',
                 '%d',
                 '%s']



        Raw options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be randomly generated with a size between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be randomly generated with a size of [0, 2^N-1], where N is the length in bits of the integer used to represent the Raw data length.
                              * If it is a tuple of integers (min, max), the values will be randomly generated with a size between min and max.

                              Default value is :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated length will be encoded. This parameter should be used in conjunction with :attr:`FuzzingInterval.FULL_INTERVAL` or with a tuple interval, in order to generate Raw data with a length bigger than the original full interval. This parameter will not have any effect when used with :attr:`FuzzingInterval.DEFAULT_INTERVAL`.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        ====================  =================================================


        HexaString options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be randomly generated with a size between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be randomly generated with a size of [0, 2^N-1], where N is the length in bits of the integer used to represent the HexaString length.
                              * If it is a tuple of integers (min, max), the values will be randomly generated with a size between min and max.

                              Default value is :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated length will be encoded. This parameter should be used in conjunction with :attr:`FuzzingInterval.FULL_INTERVAL` or with a tuple interval, in order to generate HexaStrings with a length bigger than the original full interval. This parameter will not have any effect when used with :attr:`FuzzingInterval.DEFAULT_INTERVAL`.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        ====================  =================================================


        BitArray options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be randomly generated with a size between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be randomly generated with a size of [0, 2^N-1], where N is the length in bits of the integer used to represent the BitArray length.
                              * If it is a tuple of integers (min, max), the values will be randomly generated with a size between min and max.

                              Default value is :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated length will be encoded. This parameter should be used in conjunction with :attr:`FuzzingInterval.FULL_INTERVAL` or with a tuple interval, in order to generate BitArrays with a length bigger than the original full interval. This parameter will not have any effect when used with :attr:`FuzzingInterval.DEFAULT_INTERVAL`.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        ====================  =================================================


        Timestamp options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        *No option*
        ====================  =================================================


        IPv4 options:

        .. tabularcolumns:: |p{3cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        *No option*
        ====================  =================================================


        Alt options:

        .. tabularcolumns:: |p{4cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        mutateChild           If :const:`True`, the children variables will also be fuzzed.

                              Default value is :const:`False`.
        mappingTypesMutators  A :class:`dict` used to override the global default mapping of types with their default mutators.

                              Default value is ``{}``.
        maxDepth              An :class:`int` used to limit the recursive calls to the mutator.

                              Default value is ``AltMutator.DEFAULT_MAX_DEPTH = 20``
        ====================  =================================================


        Agg options:

        .. tabularcolumns:: |p{4cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        mutateChild           If :const:`True`, the children variables will also be fuzzed.

                              Default value is :const:`False`.
        mappingTypesMutators  A :class:`dict` used to override the global default mapping of types with their default mutators.

                              Default value is ``{}``.
        ====================  =================================================


        Repeat options:

        .. tabularcolumns:: |p{4cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        mutateChild           If :const:`True`, the children variables will also be fuzzed.

                              Default value is :const:`False`.
        mappingTypesMutators  A :class:`dict` used to override the global default mapping of types with their default mutators.

                              Default value is ``{}``.
        interval              The scope of values to generate.

                              * If set to :attr:`FuzzingInterval.DEFAULT_INTERVAL`, the values will be randomly generated with a size between the min and max values of the domain.
                              * If set to :attr:`FuzzingInterval.FULL_INTERVAL`, the values will be randomly generated with a size of [0, 2^N-1], where N is the length in bits of the integer used to represent the number of repetitions.
                              * If it is a tuple of integers (min, max), the values will be randomly generated with a size between min and max.

                              Default value is :attr:`FuzzingInterval.FULL_INTERVAL`.

        lengthBitSize         The size in bits of the memory on which the generated length will be encoded. This parameter should be used in conjunction with :attr:`FuzzingInterval.FULL_INTERVAL` or with a tuple interval, in order to generate a Repeat with a length bigger than the original full interval. This parameter will not have any effect when used with :attr:`FuzzingInterval.DEFAULT_INTERVAL`.

                              The following sizes are available:

                              * ``None`` (default value), which indicates to use the unit size set in the field domain.
                              * ``UnitSize.SIZE_1``
                              * ``UnitSize.SIZE_4``
                              * ``UnitSize.SIZE_8``
                              * ``UnitSize.SIZE_16``
                              * ``UnitSize.SIZE_24``
                              * ``UnitSize.SIZE_32``
                              * ``UnitSize.SIZE_64``
        ====================  =================================================


        Optional options:

        .. tabularcolumns:: |p{4cm}|p{10cm}|

        ====================  =================================================
               Option                           Description
        ====================  =================================================
        mutateChild           If :const:`True`, the children variable will also be fuzzed.

                              Default value is :const:`False`.
        mappingTypesMutators  A :class:`dict` used to override the global default mapping of types with their default mutators.

                              Default value is ``{}``.
        ====================  =================================================


        The following examples show the different usages of the fuzzing
        component.

        **Basic fuzzing example**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data = Field(domain=int8())
        >>> symbol = Symbol(fields=[f_data])
        >>> fuzz.set(f_data)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00'


        **Fuzzing example of a field that contains an integer**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data = Field(name="data", domain=int16(interval=(1, 4)))
        >>> symbol = Symbol(name="sym", fields=[f_data])
        >>> fuzz.set(f_data, interval=(20, 32000))
        >>> next(symbol.specialize(fuzz=fuzz))
        b'U*'


        **Fuzzing example of a field that contains a size relationship with another field**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data = Field(name="data", domain=int16(3))
        >>> f_size = Field(name="size", domain=Size([f_data], Integer(unitSize=UnitSize.SIZE_16)))
        >>> symbol = Symbol(name="sym", fields=[f_data, f_size])
        >>> fuzz.set(f_size, interval=(20, 32000))
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00\x03U*'


        **Fuzzing example in mutation mode of a field that contains an integer**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data = Field(name="data", domain=int16(2))
        >>> symbol = Symbol(name="sym", fields=[f_data])
        >>> fuzz.set(f_data, mode=FuzzingMode.MUTATE, interval=(20, 32000))
        >>> res = next(symbol.specialize(fuzz=fuzz))
        >>> res != b'\x00\x02'
        True


        **Multiple fuzzing call on the same symbol**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data = Field(name="data", domain=int16(2))
        >>> symbol = Symbol(name="sym", fields=[f_data])
        >>> fuzz.set(f_data, interval=(20, 30000))
        >>> nbFuzz = 1000
        >>> result = set()
        >>> for i in range(nbFuzz):
        ...     result.add(next(symbol.specialize(fuzz=fuzz)))
        >>> len(result) == 1000
        True


        **Fuzzing of a field that contains sub-fields**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8())
        >>> f_data2 = Field(name="data2", domain=int16())
        >>> f_parent = Field(name="parent", domain=[f_data1, f_data2])
        >>> symbol = Symbol(name="sym", fields=[f_parent])
        >>> fuzz.set(f_parent)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00\x00\x00'


        **Fuzzing of a whole symbol, and covering all field storage spaces with default fuzzing strategy per types**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8(interval=(2, 4)))
        >>> f_data2 = Field(name="data2", domain=int8(interval=(5, 8)))
        >>> symbol = Symbol(name="sym", fields=[f_data1, f_data2])
        >>> fuzz.set(symbol, interval=FuzzingInterval.FULL_INTERVAL)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00\x00'


        **Fuzzing and covering full storage space of a field**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8(2))
        >>> f_data2 = Field(name="data2", domain=int8(interval=(10, 20)))
        >>> symbol = Symbol(name="sym", fields=[f_data1, f_data2])
        >>> fuzz.set(f_data2, interval=FuzzingInterval.FULL_INTERVAL)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x02\x00'


        **Fuzzing and covering full storage space of a field, after redefining its storage space from 8 to 16 bits**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8(2))
        >>> f_data2 = Field(name="data2", domain=int8(interval=(10, 20)))
        >>> symbol = Symbol(name="sym", fields=[f_data1, f_data2])
        >>> fuzz.set(f_data2, interval=FuzzingInterval.FULL_INTERVAL, lengthBitSize=UnitSize.SIZE_16)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x02\x00\x00'


        **Fuzzing and changing the default fuzzing parameters for types**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8(2))
        >>> f_data2 = Field(name="data2", domain=int8(4))
        >>> symbol = Symbol(name="sym", fields=[f_data1, f_data2])
        >>> fuzz.set(Integer, interval=(10, 12))
        >>> fuzz.set(symbol)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x0c\x0c'


        **Fuzzing configuration with a global maximum number of mutations**

        >>> from netzob.all import *
        >>> fuzz = Fuzz(counterMax=1)
        >>> f_alt = Field(name="alt", domain=Alt([int8(interval=(1, 4)),
        ...                                       int8(interval=(5, 8))]))
        >>> symbol = Symbol(name="sym", fields=[f_alt])
        >>> fuzz.set(f_alt)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00'
        >>> next(symbol.specialize(fuzz=fuzz))
        Traceback (most recent call last):
        StopIteration


        **Fuzzing configuration with a maximum number of mutations, expressed with an absolute limit, on a symbol**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> field = Field(Agg([uint8(), uint8()]))
        >>> symbol = Symbol([field], name="sym")
        >>> symbol.count()
        65536
        >>> fuzz.set(symbol, counterMax=80)
        >>> idx = 0
        >>> for data in symbol.specialize(fuzz=fuzz):
        ...     # use data
        ...     idx += 1
        >>> print(idx)
        80


        **Fuzzing configuration with a maximum number of mutations, expressed with a ratio, on a symbol**

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> field = Field(Agg([uint8(), uint8()]))
        >>> symbol = Symbol([field], name="sym")
        >>> symbol.count()
        65536
        >>> int(symbol.count() * 0.001)
        65
        >>> fuzz.set(symbol, counterMax=0.001)
        >>> idx = 0
        >>> for data in symbol.specialize(fuzz=fuzz):
        ...     # use data
        ...     idx += 1
        >>> print(idx)
        65
        >>> fuzz = Fuzz()  # This is needed to restore globalCounterMax default value for unit test purpose


        """

        # Handle seed value
        if seed is None:
            seed = Mutator.SEED_DEFAULT

        # Update kwargs with the first 4 parameters. This kwargs will be passed to Mutator constructors
        kwargs.update({'mode': mode, 'generator': generator, 'seed': seed, 'counterMax': counterMax})

        # Case where target key is an AbstractType
        if isinstance(key, type):

            # Update default Mutator parameters for the associated type
            for t in self.mappingTypesMutators:
                if issubclass(key, t):  # Use issubclass() to handle cases where partial() is used (e.g. on Integer types)
                    mutator, mutator_default_parameters = self.mappingTypesMutators[t]
                    mutator_default_parameters.update(kwargs)
                    self.mappingTypesMutators[t] = mutator, mutator_default_parameters
                    break
            else:
                raise TypeError("Unsupported type for key: '{}'".format(type(key)))

        # Case where target key is an AbstractField or AbstractVariable
        elif isinstance(key, (AbstractField, AbstractVariable)):

            self.mappingFieldsMutators[key] = kwargs
            self._normalize_mappingFieldsMutators(key)

        else:
            raise TypeError("Unsupported type for key: '{}'".format(type(key)))

    @public_api
    def unset(self, key):
        r"""The :meth:`unset <.Fuzz.set>` method deactivates the fuzzing for a
        symbol, a field or a variable. It is not possible to unset the
        fuzzing on a type.

        The :meth:`unset <.Fuzz.set>` method expects some parameters:

        :param key: The targeted object (either a symbol, a field or a
                    variable).
        :type key: :class:`Field
                   <netzob.Model.Vocabulary.Field.Field>`,
                   or :class:`Symbol
                   <netzob.Model.Vocabulary.Symbol.Symbol>`,
                   or :class:`Variable
                   <netzob.Model.Vocabulary.Domain.Variables.AbstractVariable.AbstractVariable>`.


        Example of fuzzing of a whole symbol except one field:

        >>> from netzob.all import *
        >>> fuzz = Fuzz()
        >>> f_data1 = Field(name="data1", domain=int8(2))
        >>> f_data2 = Field(name="data2", domain=int8(4))
        >>> symbol = Symbol(name="sym", fields=[f_data1, f_data2])
        >>> fuzz.set(symbol, interval=FuzzingInterval.FULL_INTERVAL)
        >>> fuzz.unset(f_data2)
        >>> next(symbol.specialize(fuzz=fuzz))
        b'\x00\x04'


        """

        from netzob.Model.Vocabulary.Symbol import Symbol

        keys_to_remove = []
        # Handle case where k is a Variable -> nothing to do
        if isinstance(key, AbstractVariable):
            keys_to_remove.append(key)

        # Handle case where k is a Field containing sub-Fields -> we retrieve all its field variables
        elif isinstance(key, Field) and len(key.fields) > 0:
            subfields = key.fields
            keys_to_remove.append(key)
            for f in subfields:
                keys_to_remove.append(f.domain)

        # Handle case where k is a Field -> retrieve the associated variable
        elif isinstance(key, Field):
            keys_to_remove.append(key.domain)

        # Handle case where k is a Symbol -> we retrieve all its field variables
        elif isinstance(key, Symbol):
            subfields = key.getLeafFields(includePseudoFields=True)
            keys_to_remove.append(key)
            for f in subfields:
                keys_to_remove.append(f.domain)
        else:
            raise Exception("Key must be a Symbol, a Field or a Variable"
                            ", but not a '{}'".format(type(key)))

        # Update keys
        for old_key in keys_to_remove:
            if old_key in self.mappingFieldsMutators.keys():
                self.mappingFieldsMutators.pop(old_key)

    def get(self, key):
        if isinstance(key, type):
            # We return the associated mutator class
            if key in self.mappingTypesMutators:
                return self.mappingTypesMutators[key]
            else:
                return None
        elif isinstance(key, (AbstractField, AbstractVariable)) or isinstance(key, str):
            # We return the associated mutator instance
            if key in self.mappingFieldsMutators:
                return self.mappingFieldsMutators[key]
            else:
                return None
        else:
            raise TypeError("Unsupported type for key: '{}'".format(type(key)))

    @staticmethod
    def _retrieveDefaultMutator(domain, mapping, **kwargs):
        """Instanciate and return the default mutator according to the
        provided domain.

        """

        mutator = None
        mutator_default_parameters = {}
        for t in mapping:

            # Handle mutators for node variables (such as Repeat, Alt and Agg)
            if isinstance(domain, t):
                mutator, mutator_default_parameters = mapping[t]
                break

            # Handle mutators for leaf variables
            else:
                # Two type checks are made here, in order to handle cases where partial() is used (e.g. on Integer types)
                if type(getattr(domain, 'dataType', None)) == t or isinstance(getattr(domain, 'dataType', None), t):
                    mutator, mutator_default_parameters = mapping[t]
                    break
        else:
            raise Exception("Cannot find a default Mutator for the domain '{}'.".format(domain))

        # Update default Mutator parameters with explicitly provided parameters
        mutator_default_parameters.update(kwargs)

        # Instanciate the mutator
        mutatorInstance = mutator(domain, **mutator_default_parameters)

        return mutatorInstance

    def _normalize_mappingFieldsMutators(self, new_key):
        """Normalize the fuzzing configuration.

        Fields described with field name are converted into field
        object, and then all key elements are converted into
        variables.

        """

        # Normalize fuzzing keys
        normalized_new_keys = self._normalizeKeys(new_key=new_key)

        # Normalize fuzzing values
        self._normalizeValues(new_keys=normalized_new_keys)

        # Second loop, to handle cases where domains are complex (Alt, Agg or Repeat)
        keys = {}
        for k, v in self.mappingFieldsMutators.items():
            keys[k] = v
            if isinstance(k, AbstractVariableNode):
                keys.update(self._propagateMutation(k, v))
        self.mappingFieldsMutators.update(keys)

        # Second loop to normalize fuzzing values, after handling complex domains (that may have added news keys:values)
        self._normalizeValues(new_keys=normalized_new_keys)

    def _normalizeKeys(self, new_key):
        """Normalize the keys of the dict containing he relationships between
        domain and mutators.

        This method expects the new_key (a symbol, a field or a
        variable) that triggered the process of normalization, and
        should return the impacted new keys issued form this
        symbol/field/variable.

        """
        from netzob.Model.Vocabulary.Symbol import Symbol

        # Normalize fuzzing keys
        new_keys = {}
        keys_to_remove = []
        normalized_new_keys = []
        for k, v in self.mappingFieldsMutators.items():

            # Handle case where k is a Variable -> nothing to do
            if isinstance(k, AbstractVariable):
                if new_key == k:
                    normalized_new_keys.append(k)

            # Handle case where k is a Field containing sub-Fields -> we retrieve all its field variables
            elif isinstance(k, Field) and len(k.fields) > 0:
                subfields = k.fields
                keys_to_remove.append(k)
                for f in subfields:

                    # We force the replacement of the new key
                    if new_key == k:
                        new_keys[f.domain] = v
                        normalized_new_keys.append(f.domain)

                    # We check if the variable is not already present in the variables to mutate
                    elif f.domain not in self.mappingFieldsMutators.keys():
                        new_keys[f.domain] = v

            # Handle case where k is a Field -> retrieve the associated variable
            elif isinstance(k, Field):
                keys_to_remove.append(k)
                new_keys[k.domain] = v
                if new_key == k:
                    normalized_new_keys.append(k.domain)

            # Handle case where k is a Symbol -> we retrieve all its field variables
            elif isinstance(k, Symbol):
                subfields = k.getLeafFields(includePseudoFields=True)
                keys_to_remove.append(k)
                for f in subfields:

                    # We force the replacement of the new key
                    if new_key == k:
                        new_keys[f.domain] = v
                        normalized_new_keys.append(f.domain)

                    # We check if the variable is not already present in the variables to mutate
                    elif f.domain not in self.mappingFieldsMutators.keys():
                        new_keys[f.domain] = v

            else:
                raise Exception("Fuzzing keys must contain Symbols, Fields or Variables"
                                ", but not a '{}'".format(type(k)))

        # Update keys
        for old_key in keys_to_remove:
            self.mappingFieldsMutators.pop(old_key)
        self.mappingFieldsMutators.update(new_keys)

        return normalized_new_keys

    def _normalizeValues(self, new_keys):
        # Normalize fuzzing values
        keys_to_update = {}
        keys_to_remove = []

        from netzob.Fuzzing.Mutator import Mutator
        for k, v in self.mappingFieldsMutators.items():

            # If the value is already a Mutator instance -> we do nothing
            if isinstance(v, Mutator):
                pass
            # Else, we instanciate the default Mutator according to the type of the object
            else:
                mut_inst = Fuzz._retrieveDefaultMutator(domain=k, mapping=Fuzz.mappingTypesMutators, **v)
                keys_to_update[k] = mut_inst

        # Update keys
        for old_key in keys_to_remove:
            self.mappingFieldsMutators.pop(old_key)
        self.mappingFieldsMutators.update(keys_to_update)

    def _propagateMutation(self, variable, mutator):
        """This method aims at propagating the fuzzing to the children of a
        complex variable (such as Repeat, Alt or Agg). The propagation
        strategy is included in the mutator associated to the parent
        variable.
        """

        tmp_new_keys = {}

        # Propagate also the mutator mode and the seed
        kwargs = {'mode': mutator.mode, 'seed': mutator.seed}#, 'counterMax' : mutator.counterMax}

        if isinstance(variable, Repeat) and isinstance(mutator, RepeatMutator) and mutator.mutateChild:

            # We check if the variable is not already present in the variables to mutate
            if variable.children[0] not in self.mappingFieldsMutators.keys():
                mut_inst = Fuzz._retrieveDefaultMutator(domain=variable.children[0], mapping=mutator.mappingTypesMutators, **kwargs)
                tmp_new_keys[variable.children[0]] = mut_inst

                # Propagate mutation to the child if it is a complex domain
                if isinstance(variable.children[0], AbstractVariableNode):
                    tmp_new_keys.update(self._propagateMutation(variable.children[0], mut_inst))

        elif isinstance(variable, Alt) and isinstance(mutator, AltMutator) and mutator.mutateChild:

            for child in variable.children:
                # We check if the variable is not already present in the variables to mutate
                if child not in self.mappingFieldsMutators.keys():
                    mut_inst = Fuzz._retrieveDefaultMutator(domain=child, mapping=mutator.mappingTypesMutators, **kwargs)
                    tmp_new_keys[child] = mut_inst

                    # Propagate mutation to the child if it is a complex domain
                    if isinstance(child, AbstractVariableNode):
                        tmp_new_keys.update(self._propagateMutation(child, mut_inst))

        elif isinstance(variable, Agg) and isinstance(mutator, AggMutator) and mutator.mutateChild:

            for child in variable.children:
                # We check if the variable is not already present in the variables to mutate
                if child not in self.mappingFieldsMutators.keys():
                    mut_inst = Fuzz._retrieveDefaultMutator(domain=child, mapping=mutator.mappingTypesMutators, **kwargs)
                    tmp_new_keys[child] = mut_inst

                    # Propagate mutation to the child if it is a complex domain
                    if isinstance(child, AbstractVariableNode):
                        tmp_new_keys.update(self._propagateMutation(child, mut_inst))

        return tmp_new_keys


    # PROPERTIES ##

    @property
    def counterMax(self):
        """The maximum number of mutations to produce.

        :getter: Returns the maximum number of mutations.
        :setter: Sets the maximum number of mutations.
        :type: :class:`int` or :class:`float`

        """
        return DomainMutator.globalCounterMax

    @public_api
    @counterMax.setter  # type: ignore
    def counterMax(self, counterMax: Integer):
        DomainMutator.globalCounterMax = counterMax


def _test():
    r"""

    # Test to verify that the RNG covers all values in specific ranges, with negatives and positives number

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=int8(interval=(10, 20)))
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data)
    >>> datas = set()
    >>> for _ in range(2000):
    ...     datas.add(next(symbol.specialize(fuzz=fuzz)))
    >>> len(datas)
    256

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=int8(interval=(-10, 20)))
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data)
    >>> datas = set()
    >>> for _ in range(2000):
    ...     datas.add(next(symbol.specialize(fuzz=fuzz)))
    >>> len(datas)
    256

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=int8(interval=(-20, -10)))
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data)
    >>> datas = set()
    >>> for _ in range(2000):
    ...     datas.add(next(symbol.specialize(fuzz=fuzz)))
    >>> len(datas)
    256


    # Test to verify that the RNG covers all values in specific ranges, with negatives and positives number, with a specific generator

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=uint8())
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data, generator=(0., 0.5, 1.))
    >>> datas = set()
    >>> for _ in range(3):
    ...     datas.add(next(symbol.specialize(fuzz=fuzz)))
    >>> len(datas)
    3
    >>> datas = sorted(datas)
    >>> for elt in datas:
    ...     print(int.from_bytes(elt, byteorder='big'))
    0
    128
    255

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=int8())
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data, generator=(0., 0.5, 1.))
    >>> datas = set()
    >>> for _ in range(3):
    ...     datas.add(next(symbol.specialize(fuzz=fuzz)))
    >>> len(datas)
    3
    >>> datas = sorted(datas)
    >>> for elt in datas:
    ...     print(int.from_bytes(elt, byteorder='big', signed=True))
    0
    127
    -128


    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f1 = Field(uint8())
    >>> f2 = Field(uint8(interval=(0, 254)))
    >>> symbol = Symbol([f1, f2])
    >>> fuzz.set(symbol, interval=FuzzingInterval.DEFAULT_INTERVAL)
    >>> g = symbol.specialize(fuzz=fuzz)
    >>> a = []
    >>> for i in range(symbol.count()):
    ...     data = next(g)
    ...     a.append(data)
    >>> len(a)
    65280
    >>> len(set(a))
    65280
    >>> symbol.count()
    65280


    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> f1 = Field(uint8(interval=(0, 3)))
    >>> f2 = Field(Size(f1))
    >>> symbol = Symbol([f1, f2])
    >>> fuzz.set(Integer, interval=FuzzingInterval.DEFAULT_INTERVAL)
    >>> fuzz.set(f1)
    >>> g = symbol.specialize(fuzz=fuzz)
    >>> a = []
    >>> for i in range(symbol.count()):
    ...     a.append(next(g))
    >>> len(a)
    4
    >>> a
    [b'\x00\x01', b'\x03\x01', b'\x01\x01', b'\x02\x01']
    >>> len(set(a))
    4
    >>> symbol.count()
    4

    """


def _test_seed():
    r"""
    
    This test verifies that the fuzzing seed ensures predictibility of generated values

    >>> from netzob.all import *
    >>> from netzob.Fuzzing.Mutator import Mutator

    >>> # Set seed for fuzzing generation
    >>> saved_seed = Mutator.SEED_DEFAULT
    >>> Mutator.SEED_DEFAULT = 42

    >>> # Fuzz an integer
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=uint8())
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data)
    >>> datas = []
    >>> for _ in range(20):
    ...     datas.append(next(symbol.specialize(fuzz=fuzz)))
    >>> datas
    [b'\x00', b's', b'T', b'\xe6', b'\xe9', b':', b'\xe3', b'`', b'{', b'\x1c', b'\xfc', b'#', b'\x96', b'\x02', b'\x12', b'\x82', b'\xb6', b'+', b'\xde', b'\x18']

    >>> # Fuzz an integer
    >>> fuzz = Fuzz()
    >>> f_data = Field(domain=uint8())
    >>> symbol = Symbol(fields=[f_data])
    >>> fuzz.set(f_data)
    >>> datas = []
    >>> for _ in range(20):
    ...     datas.append(next(symbol.specialize(fuzz=fuzz)))
    >>> datas
    [b'\x00', b's', b'T', b'\xe6', b'\xe9', b':', b'\xe3', b'`', b'{', b'\x1c', b'\xfc', b'#', b'\x96', b'\x02', b'\x12', b'\x82', b'\xb6', b'+', b'\xde', b'\x18']

    >>> # Restore original seed value
    >>> Mutator.SEED_DEFAULT = saved_seed

    """


def _test_max_mutations():
    r"""

    **Fuzzing configuration with a global maximum number of mutations**

    >>> from netzob.all import *
    >>> fuzz = Fuzz(counterMax=1)
    >>> f_alt = Field(name="alt", domain=Alt([int8(interval=(1, 4)),
    ...                                       int8(interval=(5, 8))]))
    >>> symbol = Symbol(name="sym", fields=[f_alt])
    >>> fuzz.set(f_alt)
    >>> next(symbol.specialize(fuzz=fuzz))
    b'\x00'
    >>> next(symbol.specialize(fuzz=fuzz))
    Traceback (most recent call last):
    StopIteration


    **Fuzzing configuration with a maximum number of mutations, expressed with an absolute limit, on a symbol**

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> field = Field(Agg([uint8(), uint8()]))
    >>> symbol = Symbol([field], name="sym")
    >>> symbol.count()
    65536
    >>> fuzz.set(symbol, counterMax=80)
    >>> idx = 0
    >>> for data in symbol.specialize(fuzz=fuzz):
    ...     # use data
    ...     idx += 1
    >>> print(idx)
    80


    **Fuzzing configuration with a maximum number of mutations, expressed with a ratio, on a symbol**

    >>> from netzob.all import *
    >>> fuzz = Fuzz()
    >>> field = Field(Agg([uint8(), uint8()]))
    >>> symbol = Symbol([field], name="sym")
    >>> symbol.count()
    65536
    >>> int(symbol.count() * 0.001)
    65
    >>> fuzz.set(symbol, counterMax=0.001)
    >>> idx = 0
    >>> for data in symbol.specialize(fuzz=fuzz):
    ...     # use data
    ...     idx += 1
    >>> print(idx)
    65
    >>> fuzz = Fuzz()  # This is needed to restore globalCounterMax default value for unit test purpose

    """
