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
import abc
from bitarray import bitarray

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Local application imports                                                 |
# +---------------------------------------------------------------------------+
from netzob.Common.Utils.Decorators import typeCheck, NetzobLogger
from netzob.Model.Vocabulary.Domain.Variables.AbstractVariable import AbstractVariable
from netzob.Model.Vocabulary.Domain.Variables.Scope import Scope
from netzob.Model.Vocabulary.Domain.Parser.ParsingPath import ParsingException
from netzob.Model.Vocabulary.Types.AbstractType import AbstractType


@NetzobLogger
class AbstractVariableLeaf(AbstractVariable):
    """Represents a leaf in the variable definition of a field.

    A leaf is a variable with no children. Most of of leaf variables
    are :class:`Data <netzob.Model.Vocabulary.Domain.Variables.Leafs.Data.Data>` variables and
    :class:`AbstractRelation <netzob.Model.Vocabulary.Domain.Variables.Leafs.Relations.AbstractRelation.AbstractRelation>`.

    """

    def __init__(self, varType, name=None, dataType=None, scope=None):
        super(AbstractVariableLeaf, self).__init__(
            varType, name=name, scope=scope)

        self.dataType = dataType

    def isnode(self):
        return False

    def count(self, fuzz=None):
        from netzob.Fuzzing.Mutators.DomainMutator import FuzzingMode
        if fuzz is not None and fuzz.get(self) is not None and fuzz.get(self).mode in [FuzzingMode.GENERATE, FuzzingMode.FIXED]:
            # Retrieve the mutator
            mutator = fuzz.get(self)
            return mutator.count()
        else:
            return self.dataType.count()

    def parse(self, parsingPath, acceptCallBack=True, carnivorous=False):
        """@toto TO BE DOCUMENTED"""

        if self.scope is None:
            raise Exception(
                "Cannot parse if the variable has no assigned Scope.")

        try:
            if self.isDefined(parsingPath):
                if self.scope == Scope.CONSTANT or self.scope == Scope.SESSION:
                    return self.valueCMP(
                        parsingPath, acceptCallBack, carnivorous=carnivorous)
                elif self.scope == Scope.MESSAGE:
                    return self.learn(
                        parsingPath, acceptCallBack, carnivorous=carnivorous)
                elif self.scope == Scope.NONE:
                    return self.domainCMP(
                        parsingPath, acceptCallBack, carnivorous=carnivorous)
            else:
                if self.scope == Scope.CONSTANT:
                    self._logger.debug(
                        "Cannot parse '{0}' as scope is CONSTANT and no value is available.".
                        format(self))
                    return []
                elif self.scope == Scope.MESSAGE or self.scope == Scope.SESSION:
                    return self.learn(
                        parsingPath, acceptCallBack, carnivorous=carnivorous)
                elif self.scope == Scope.NONE:
                    return self.domainCMP(
                        parsingPath, acceptCallBack, carnivorous=carnivorous)
        except ParsingException:
            self._logger.info("Error in parsing of variable")
            return []

        raise Exception("Not yet implemented: {0}.".format(self.scope))

    #
    # methods that must be defined to support the abstraction process
    #
    @abc.abstractmethod
    def isDefined(self, parsingPath):
        raise NotImplementedError("method isDefined is not implemented")

    @abc.abstractmethod
    def domainCMP(self, parsingPath, acceptCallBack, carnivorous):
        raise NotImplementedError("method domainCMP is not implemented")

    @abc.abstractmethod
    def valueCMP(self, parsingPath, acceptCallBack, carnivorous):
        raise NotImplementedError("method valueCMP is not implemented")

    @abc.abstractmethod
    def learn(self, parsingPath, acceptCallBack, carnivorous):
        raise NotImplementedError("method learn is not implemented")

    def getVariables(self):
        return [self]

    def specialize(self, parsingPath, fuzz=None, acceptCallBack=True):
        """Specializes a Leaf"""

        from netzob.Fuzzing.Fuzz import MaxFuzzingException

        # Fuzzing has priority over generating a legitimate value
        from netzob.Fuzzing.Mutators.DomainMutator import FuzzingMode
        if fuzz is not None and fuzz.get(self) is not None and fuzz.get(self).mode in [FuzzingMode.GENERATE, FuzzingMode.FIXED]:

            # Retrieve the mutator
            mutator = fuzz.get(self)

            def fuzz_generate():
                for _ in range(self.count(fuzz=fuzz)):

                    try:
                        # Mutate a value according to the current field attributes
                        generated_value = mutator.generate()
                    except MaxFuzzingException:
                        self._logger.debug("Maximum mutation counter reached")
                        break
                    else:
                        # Convert the return bytes into bitarray
                        value = bitarray(endian='big')
                        value.frombytes(generated_value)

                        # Associate the generated value to the current variable
                        newParsingPath = parsingPath.clone()
                        newParsingPath.addResult(self, value)
                        yield newParsingPath

            return fuzz_generate()

        if self.scope is None:
            raise Exception(
                "Cannot specialize if the variable has no assigned Scope.")

        if self.isDefined(parsingPath):
            if self.scope == Scope.CONSTANT or self.scope == Scope.SESSION:
                newParsingPaths = self.use(parsingPath, acceptCallBack)
            elif self.scope == Scope.MESSAGE:
                newParsingPaths = self.regenerateAndMemorize(parsingPath, acceptCallBack)
            elif self.scope == Scope.NONE:
                newParsingPaths = self.regenerate(parsingPath, acceptCallBack)
        else:
            if self.scope == Scope.CONSTANT:
                self._logger.debug(
                    "Cannot specialize '{0}' as scope is CONSTANT and no value is available.".
                    format(self))
                newParsingPaths = iter(())
            elif self.scope == Scope.MESSAGE or self.scope == Scope.SESSION:
                newParsingPaths = self.regenerateAndMemorize(parsingPath, acceptCallBack)
            elif self.scope == Scope.NONE:
                newParsingPaths = self.regenerate(parsingPath, acceptCallBack)

        if fuzz is not None and fuzz.get(self) is not None and fuzz.get(self).mode == FuzzingMode.MUTATE:

            def fuzz_mutate():
                for path in newParsingPaths:
                    generatedData = path.getData(self)

                    # Retrieve the mutator
                    mutator = fuzz.get(self)

                    while True:
                        # Mutate a value according to the current field attributes
                        mutator.mutate(generatedData)
                        yield path

            return fuzz_mutate()
        else:
            return newParsingPaths

    def str_structure(self, deepness=0):
        """Returns a string which denotes
        the current field definition using a tree display"""

        tab = ["     " for x in range(deepness - 1)]
        tab.append("|--   ")
        tab.append("{0}".format(self))
        return ''.join(tab)

    def getFixedBitSize(self):
        self._logger.debug("Determine the deterministic size of the value of "
                           "the leaf variable")

        if not hasattr(self, 'dataType'):
            return super().getFixedBitSize()

        return self.dataType.getFixedBitSize()


    ## Properties

    @property
    def dataType(self):
        """The datatype used to encode the result of the computed relation field.

        :type: :class:`AbstractType <netzob.Model.Vocabulary.Types.AbstractType.AbstractType>`
        """

        return self.__dataType

    @dataType.setter  # type: ignore
    @typeCheck(AbstractType)
    def dataType(self, dataType):
        if dataType is None:
            raise TypeError("Datatype cannot be None")
        (minSize, maxSize) = dataType.size
        if maxSize is None:
            raise ValueError(
                "The datatype of a relation field must declare its length")
        self.__dataType = dataType
