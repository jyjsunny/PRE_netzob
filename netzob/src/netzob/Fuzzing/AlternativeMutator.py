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
from typing import Dict  # noqa: F401

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Local application imports                                                 |
# +---------------------------------------------------------------------------+
from netzob.Fuzzing.DomainMutator import DomainMutator
from netzob.Common.Utils.Decorators import typeCheck
from netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt import Alt
from netzob.Model.Vocabulary.Domain.Variables.Leafs.Data import Data
from netzob.Fuzzing.PseudoRandomIntegerMutator \
    import PseudoRandomIntegerMutator
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.Integer import uint8le


class RecursionException(Exception):
    pass

class AlternativeMutator(DomainMutator):
    """The alternative mutator.

    The AlternativeMutator constructor expects some parameters:

    :param domain: The domain of the field to mutate.
    :param mode: If set to :attr:`MutatorMode.GENERATE`, :meth:`generate` will be
        used to produce the value.
        If set to :attr:`MutatorMode.MUTATE <netzob.Fuzzing.DomainMutator.MutatorMode.MUTATE>`,
        :meth:`mutate` will be used to produce the value.
        Default value is :attr:`MutatorMode.GENERATE`.
    :param mutateChild: If :const:`True`, the subfield has to be mutated.
        Default value is :const:`False`.
    :type domain: :class:`AbstractVariable
        <netzob.Model.Vocabulary.Domain.Variables.AbstractVariable>`, required
    :type mode: :class:`int`, optional
    :type mutateChild: :class:`bool`, optional
    :raises: :class:`Exception` if domain is not valid

    >>> from netzob.all import *
    >>> subAlt = Alt([Integer(12), String("abc")])
    >>> Alt = Alt([Integer(34), subAlt])
    >>> mutator = AlternativeMutator(Alt, seed=10)
    >>> mutator.generate()
    1
    >>> mutator.currentDepth
    1
    >>> mutator.generate()
    0
    >>> mutator.currentDepth
    2
    >>> mutator.generate()
    1
    >>> mutator.currentDepth
    3

    Constant definitions:
    """

    DEFAULT_MAX_DEPTH = 20
    DATA_TYPE = Alt

    def __init__(self,
                 domain,
                 mutateChild=True,
                 mappingTypesMutators={},
                 maxDepth=DEFAULT_MAX_DEPTH,
                 **kwargs):
        self._mutateChild = mutateChild
        self.mappingTypesMutators = mappingTypesMutators
        self._maxDepth = maxDepth

        # Call parent init
        super().__init__(domain, **kwargs)

        # Configure internal mutator to determine the alternative position to select at each call to generate()
        domain_interval = Data(uint8le(interval=(0, len(domain.children))))
        self._positionMutator = PseudoRandomIntegerMutator(domain=domain_interval)
        self._currentDepth = 0

    @property
    def positionMutator(self):
        """
        Property (getter/setter).
        The PRNG mutator used to get the random position of the type in the
        alternative list.
        It enables to change the position mutator, but with the condition that
        the class object inherits
        :class:`PseudoRandomIntegerMutator <netzob.Fuzzing.PseudoRandomIntegerMutator>`.

        :rtype: :class:`PseudoRandomIntegerMutator \
        <netzob.Fuzzing.PseudoRandomIntegerMutator>`
        """
        return self._positionMutator

    @positionMutator.setter
    def positionMutator(self, posMutator):
        self._positionMutator = posMutator

    @property
    def maxDepth(self):
        """
        Property (getter/setter).
        Recursivity limit in mutating an :class:`Alt <netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt.Alt>` type.
        When this limit is reached in :meth:`generate` method, an exception is
        raised.

        :rtype: :class:`int`
        """
        return self._maxDepth

    @maxDepth.setter
    @typeCheck(int)
    def maxDepth(self, maxDepthValue):
        self._maxDepth = maxDepthValue

    @property
    def mutateChild(self):
        """
        Property (getter).
        If true, the sub-field has to be mutated.
        Default value is False.

        :type: :class:`bool`
        """
        return self._mutateChild

    @mutateChild.setter
    @typeCheck(bool)
    def mutateChild(self, mutateChild):
        self._mutateChild = mutateChild

    @property
    def mappingTypesMutators(self):
        """Return the mapping that set the default mutator for each type.

        :type: :class:`dict`
        """
        return self._mappingTypesMutators

    @mappingTypesMutators.setter
    @typeCheck(dict)
    def mappingTypesMutators(self, mappingTypesMutators):
        """Override the global default mapping of types with their default
        mutators.
        """
        from netzob.Fuzzing.Fuzz import Fuzz
        self._mappingTypesMutators = Fuzz.mappingTypesMutators.copy()
        self._mappingTypesMutators.update(mappingTypesMutators)

    @property
    def currentDepth(self):
        """
        Property (getter).
        Return the current depth in searching a type different of
        :class:`Alt <netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt.Alt>` in :meth:`generate`.

        :type: :class:`bool`
        :raises: :class:`RecursionError` if _currentDepth is None
        """
        if self._currentDepth is None:
            raise ValueError("Current depth is None : generate() has to be \
called, first")
        return self._currentDepth

    def generate(self):
        """This is the fuzz generation method of the alternative field.

        It selects randomly the type among the alternative list, by using
        :attr:`positionMutator`, and stores it in :attr:`randomType`.

        If the mutation encounters recursivity (:class:`Alt <netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt.Alt>`
        containing :class:`Alt <netzob.Model.Vocabulary.Domain.Variables.Nodes.Alt.Alt>`),
        infinite loop is avoided by controlling the number of iterations
        **currentDepth** with **maxDepth**.

        If **currentDepth** exceeds **maxDepth**, a RecursionError is raised.

        :return: None
        :rtype: :class:`None`
        :raises: :class:`RecursionError`
        """
        # Call parent generate() method
        super().generate()

        self._currentDepth += 1
        if self._currentDepth >= self._maxDepth:
            raise RecursionException("max depth reached ({})".format(self._maxDepth))

        pos = self._positionMutator.generateInt()
        return pos
