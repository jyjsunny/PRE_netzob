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
# |       - Georges Bossert <georges.bossert (a) supelec.fr>                  |
# |       - Frédéric Guihéry <frederic.guihery (a) amossys.fr>                |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Standard library imports                                                  |
# +---------------------------------------------------------------------------+

# +---------------------------------------------------------------------------+
# | Related third party imports                                               |
# +---------------------------------------------------------------------------+
from netzob.Common.Utils.Decorators import typeCheck, NetzobLogger
from netzob.Model.Vocabulary.Domain.Variables.Memory import Memory
from netzob.Model.Vocabulary.Messages.AbstractMessage import AbstractMessage
from netzob.Model.Vocabulary.Domain.Parser.MessageParser import MessageParser, InvalidParsingPathException
from netzob.Model.Vocabulary.Messages.RawMessage import RawMessage

from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Domain.Parser.ParsingPath import ParsingPath
from netzob.Model.Vocabulary.Types.TypeConverter import TypeConverter
from netzob.Model.Vocabulary.Types.BitArray import BitArray
from netzob.Model.Vocabulary.Types.Raw import Raw
from netzob.Model.Vocabulary.Domain.Parser.FieldParser import FieldParser
from netzob.Model.Vocabulary.Types.AbstractType import AbstractType, UnitSize

@NetzobLogger
class FlowParser(object):
    r"""    In some cases, a message can also represent multiple consecutive messages. For instance, TCP flows embeds
    consecutive payloads with no delimiter. To deal with such case, the `class:MessageParser` can be parametrized to
    enable multiple consecutive symbols to abstract a single message.

    >>> from netzob.all import *
    >>> payload1 = "aabb"
    >>> payload2 = "ccdd"
    >>> message = RawMessage(payload1 + payload2)
    >>> s1 = Symbol(fields=[Field(String("aabb"))], name="s1")
    >>> s2 = Symbol(fields=[Field(String("ccdd"))], name="s2")
    >>> mp = FlowParser()
    >>> result = mp.parseFlow(message, [s1, s2])
    >>> print([(s.name, values) for (s, values) in result])
    [('s1', [bitarray('01100001011000010110001001100010')]), ('s2', [bitarray('01100011011000110110010001100100')])]


    >>> from netzob.all import *
    >>> payload1 = "hello netzob"
    >>> payload2 = "hello kurt"
    >>> message = RawMessage(payload1 + payload2)
    >>> f1 = Field(String("hello "), name="f0")
    >>> f2 = Field(String(nbChars=(1, 10)), name="f1")
    >>> s1 = Symbol(fields=[f1, f2], name="s1")
    >>> fp = FlowParser()
    >>> result = fp.parseFlow(message, [s1])
    >>> print([(s.name, values) for (s, values) in result])
    [('s1', [bitarray('011010000110010101101100011011000110111100100000'), bitarray('011011100110010101110100011110100110111101100010')]), ('s1', [bitarray('011010000110010101101100011011000110111100100000'), bitarray('01101011011101010111001001110100')])]


    >>> from netzob.all import *
    >>> content = "hello netzob" * 100
    >>> message = RawMessage(content)
    >>> f1 = Field(String("hello"), name="f1")
    >>> f2 = Field(String(" "), name="f2")
    >>> f3 = Field(String("netzob"), name="f3")
    >>> s1 = Symbol(fields = [f1, f2, f3], name="s1")
    >>> s2 = Symbol(fields = [Field("nawak")], name="s2")
    >>> fp = FlowParser()
    >>> result = fp.parseFlow(message, [s2, s1])
    >>> print([s.name for (s, values) in result])
    ['s1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1', 's1']


    Here is an applied example of the use of FlowParser to analyze an HTTP2 response flow.

    >>> from netzob.all import *
    >>> import binascii
    >>> hex_content = "485454502f312e312031303120537769746368696e672050726f746f636f6c730d0a446174653a204d6f6e2c2032382044656320323031352031323a33333a333420474d540d0a5365727665723a2068326f2f312e342e322d616c706861310d0a436f6e6e656374696f6e3a20757067726164650d0a757067726164653a206832630d0a0d0a00001204000000000000020000000000030000006400040004000000005b01040000000188768c9c47602bb4b8961d15ce30ff6196d07abe9413ca5f29141002da8115c659b8cb4a62d1bf5f87497ca589d34d1f6c96d07abe9413ca5f29141002da8115c643719794c5a37f628bfe5b71e08a318d60b327f352848fd24a8f00013d0001000000010a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e222022687474703a2f2f7777772e77332e6f72672f54522f7868746d6c312f4454442f7868746d6c312d7472616e736974696f6e616c2e647464223e0a3c68746d6c20786d6c6e733d22687474703a2f2f7777772e77332e6f72672f313939392f7868746d6c223e0a20203c686561643e0a202020203c7469746c653e5468697320697320616e206578616d706c6520213c2f7469746c653e0a20203c2f686561643e0a20203c626f64793e0a202020203c68313e4578616d706c6520706167653c2f68313e0a202020203c703e436f6e74656e74206f662074686520706167653c2f703e0909090920200a20203c2f626f64793e0a3c2f68746d6c3e0a0a"
    >>> msg = RawMessage(binascii.unhexlify(hex_content))
    >>> msg1 = RawMessage(binascii.unhexlify(hex_content)[:134])
    >>> msg2 = RawMessage(binascii.unhexlify(hex_content)[134:134+27])
    >>> msg3 = RawMessage(binascii.unhexlify(hex_content)[134+27:134+27+100])
    >>> msg4 = RawMessage(binascii.unhexlify(hex_content)[134+27+100:])
    >>> # symbols definitions
    >>> SWITCHING_PROTOCOLS_HTTP = Symbol(name = "Switching_protocols_http")
    >>> f00 = Field("HTTP/1.1 101 Switching Protocols\r\n")
    >>> f01 = Field(Raw(nbBytes=(0,150)), name="VARIOUS")
    >>> f02 = Field(String("Connection: upgrade\r\n"))
    >>> f03 = Field(String("upgrade: h2c\r\n\r\n"))
    >>> SWITCHING_PROTOCOLS_HTTP.fields = [f00, f01, f02, f03]
    >>> fp = FlowParser()
    >>> fp.parseFlow(msg1, [SWITCHING_PROTOCOLS_HTTP])
    [(Switching_protocols_http, [bitarray('01001000010101000101010001010000001011110011000100101110001100010010000000110001001100000011000100100000010100110111011101101001011101000110001101101000011010010110111001100111001000000101000001110010011011110111010001101111011000110110111101101100011100110000110100001010'), bitarray('010001000110000101110100011001010011101000100000010011010110111101101110001011000010000000110010001110000010000001000100011001010110001100100000001100100011000000110001001101010010000000110001001100100011101000110011001100110011101000110011001101000010000001000111010011010101010000001101000010100101001101100101011100100111011001100101011100100011101000100000011010000011001001101111001011110011000100101110001101000010111000110010001011010110000101101100011100000110100001100001001100010000110100001010'), bitarray('010000110110111101101110011011100110010101100011011101000110100101101111011011100011101000100000011101010111000001100111011100100110000101100100011001010000110100001010'), bitarray('01110101011100000110011101110010011000010110010001100101001110100010000001101000001100100110001100001101000010100000110100001010')])]
    >>> SETTINGS_WITH_PARAMETERS = Symbol(name = "Settings_small_max_header_list_size")    
    >>> f10 = Field(name="Length")
    >>> f11 = Field(name="Type", domain=Raw(b'\x04'))
    >>> f12 = Field(name="Flags", domain=Raw(b'\x00'))
    >>> f13 = Field(name="Stream Identifier", domain=Raw(b"\x00\x00\x00\x00"))
    >>> f14 = Field(name="Settings", domain = Repeat(Agg( [ Alt( [ Raw(b"\x00\x01"), Raw(b"\x00\x02"), Raw(b"\x00\x03"), Raw(b"\x00\x04"), Raw(b"\x00\x05"), Raw(b"\x00\x06"),] ), Raw(nbBytes=4)] ), nbRepeat = (1,10) ) )
    >>> f10.domain = Size([f14], dataType = Raw(nbBytes=3, unitSize=UnitSize.SIZE_32))
    >>> SETTINGS_WITH_PARAMETERS.fields = [f10, f11, f12, f13, f14]
    >>> fp.parseFlow(msg2, [SETTINGS_WITH_PARAMETERS])
    [(Settings_small_max_header_list_size, [bitarray('000000000000000000010010'), bitarray('00000100'), bitarray('00000000'), bitarray('00000000000000000000000000000000'), bitarray('000000000000001000000000000000000000000000000000000000000000001100000000000000000000000001100100000000000000010000000000000001000000000000000000')])]

    >>> HEADERS_STREAM_OPEN_STREAM_1_END_HEADERS = Symbol(name = "Headers_stream")
    >>> f20 = Field(name="Length")
    >>> f21 = Field(name="Type", domain=Raw(b'\x01'))
    >>> f22 = Field(name="Flags", domain=Raw(b'\x04'))
    >>> f23 = Field(name="Stream Identifier", domain=Raw(b'\x00\x00\x00\x01'))
    >>> f24 = Field(domain=Raw(nbBytes=(0,1000)))
    >>> f20.domain = Size(f24, dataType = Raw(nbBytes=3, unitSize=UnitSize.SIZE_32))
    >>> HEADERS_STREAM_OPEN_STREAM_1_END_HEADERS.fields = [f20, f21, f22, f23, f24]
    >>> fp.parseFlow(msg3, [HEADERS_STREAM_OPEN_STREAM_1_END_HEADERS])
    [(Headers_stream, [bitarray('000000000000000001011011'), bitarray('00000001'), bitarray('00000100'), bitarray('00000000000000000000000000000001'), bitarray('10001000011101101000110010011100010001110110000000101011101101001011100010010110000111010001010111001110001100001111111101100001100101101101000001111010101111101001010000010011110010100101111100101001000101000001000000000010110110101000000100010101110001100101100110111000110010110100101001100010110100011011111101011111100001110100100101111100101001011000100111010011010011010001111101101100100101101101000001111010101111101001010000010011110010100101111100101001000101000001000000000010110110101000000100010101110001100100001101110001100101111001010011000101101000110111111101100010100010111111111001011011011100011110000010001010001100011000110101100000101100110010011111110011010100101000010010001111110100100100101010001111')])]

    >>> DATA_END_STREAM_STREAM_1 = Symbol(name = "Data")
    >>> f30 = Field(name="Length", domain=Raw(nbBytes=3))
    >>> f31 = Field(name="Type", domain=Raw(b'\x00'))
    >>> f32 = Field(name="Flags", domain=Raw(b'\x01'))
    >>> f33 = Field(name="Stream Identifier", domain=Raw(b'\x00\x00\x00\x01'))
    >>> f34 = Field(domain=Raw(nbBytes=(0,1000)))
    >>> f30.domain = Size(f34, dataType = Raw(nbBytes=3, unitSize=UnitSize.SIZE_32))
    >>> DATA_END_STREAM_STREAM_1.fields = [f30, f31, f32, f33, f34]
    >>> fp.parseFlow(msg4, [DATA_END_STREAM_STREAM_1])
    [(Data, [bitarray('000000000000000100111101'), bitarray('00000000'), bitarray('00000001'), bitarray('00000000000000000000000000000001'), bitarray('0000101000111100001000010100010001001111010000110101010001011001010100000100010100100000011010000111010001101101011011000010000001010000010101010100001001001100010010010100001100100000001000100010110100101111001011110101011100110011010000110010111100101111010001000101010001000100001000000101100001001000010101000100110101001100001000000011000100101110001100000010000001010100011100100110000101101110011100110110100101110100011010010110111101101110011000010110110000101111001011110100010101001110001000100010000000100010011010000111010001110100011100000011101000101111001011110111011101110111011101110010111001110111001100110010111001101111011100100110011100101111010101000101001000101111011110000110100001110100011011010110110000110001001011110100010001010100010001000010111101111000011010000111010001101101011011000011000100101101011101000111001001100001011011100111001101101001011101000110100101101111011011100110000101101100001011100110010001110100011001000010001000111110000010100011110001101000011101000110110101101100001000000111100001101101011011000110111001110011001111010010001001101000011101000111010001110000001110100010111100101111011101110111011101110111001011100111011100110011001011100110111101110010011001110010111100110001001110010011100100111001001011110111100001101000011101000110110101101100001000100011111000001010001000000010000000111100011010000110010101100001011001000011111000001010001000000010000000100000001000000011110001110100011010010111010001101100011001010011111001010100011010000110100101110011001000000110100101110011001000000110000101101110001000000110010101111000011000010110110101110000011011000110010100100000001000010011110000101111011101000110100101110100011011000110010100111110000010100010000000100000001111000010111101101000011001010110000101100100001111100000101000100000001000000011110001100010011011110110010001111001001111100000101000100000001000000010000000100000001111000110100000110001001111100100010101111000011000010110110101110000011011000110010100100000011100000110000101100111011001010011110000101111011010000011000100111110000010100010000000100000001000000010000000111100011100000011111001000011011011110110111001110100011001010110111001110100001000000110111101100110001000000111010001101000011001010010000001110000011000010110011101100101001111000010111101110000001111100000100100001001000010010000100100100000001000000000101000100000001000000011110000101111011000100110111101100100011110010011111000001010001111000010111101101000011101000110110101101100001111100000101000001010')])]

    >>> fp = FlowParser()
    >>> fp.parseFlow(msg, [SWITCHING_PROTOCOLS_HTTP, DATA_END_STREAM_STREAM_1, SETTINGS_WITH_PARAMETERS, HEADERS_STREAM_OPEN_STREAM_1_END_HEADERS])
    [(Switching_protocols_http, [bitarray('01001000010101000101010001010000001011110011000100101110001100010010000000110001001100000011000100100000010100110111011101101001011101000110001101101000011010010110111001100111001000000101000001110010011011110111010001101111011000110110111101101100011100110000110100001010'), bitarray('010001000110000101110100011001010011101000100000010011010110111101101110001011000010000000110010001110000010000001000100011001010110001100100000001100100011000000110001001101010010000000110001001100100011101000110011001100110011101000110011001101000010000001000111010011010101010000001101000010100101001101100101011100100111011001100101011100100011101000100000011010000011001001101111001011110011000100101110001101000010111000110010001011010110000101101100011100000110100001100001001100010000110100001010'), bitarray('010000110110111101101110011011100110010101100011011101000110100101101111011011100011101000100000011101010111000001100111011100100110000101100100011001010000110100001010'), bitarray('01110101011100000110011101110010011000010110010001100101001110100010000001101000001100100110001100001101000010100000110100001010')]), (Settings_small_max_header_list_size, [bitarray('000000000000000000010010'), bitarray('00000100'), bitarray('00000000'), bitarray('00000000000000000000000000000000'), bitarray('000000000000001000000000000000000000000000000000000000000000001100000000000000000000000001100100000000000000010000000000000001000000000000000000')]), (Headers_stream, [bitarray('000000000000000001011011'), bitarray('00000001'), bitarray('00000100'), bitarray('00000000000000000000000000000001'), bitarray('10001000011101101000110010011100010001110110000000101011101101001011100010010110000111010001010111001110001100001111111101100001100101101101000001111010101111101001010000010011110010100101111100101001000101000001000000000010110110101000000100010101110001100101100110111000110010110100101001100010110100011011111101011111100001110100100101111100101001011000100111010011010011010001111101101100100101101101000001111010101111101001010000010011110010100101111100101001000101000001000000000010110110101000000100010101110001100100001101110001100101111001010011000101101000110111111101100010100010111111111001011011011100011110000010001010001100011000110101100000101100110010011111110011010100101000010010001111110100100100101010001111')]), (Data, [bitarray('000000000000000100111101'), bitarray('00000000'), bitarray('00000001'), bitarray('00000000000000000000000000000001'), bitarray('0000101000111100001000010100010001001111010000110101010001011001010100000100010100100000011010000111010001101101011011000010000001010000010101010100001001001100010010010100001100100000001000100010110100101111001011110101011100110011010000110010111100101111010001000101010001000100001000000101100001001000010101000100110101001100001000000011000100101110001100000010000001010100011100100110000101101110011100110110100101110100011010010110111101101110011000010110110000101111001011110100010101001110001000100010000000100010011010000111010001110100011100000011101000101111001011110111011101110111011101110010111001110111001100110010111001101111011100100110011100101111010101000101001000101111011110000110100001110100011011010110110000110001001011110100010001010100010001000010111101111000011010000111010001101101011011000011000100101101011101000111001001100001011011100111001101101001011101000110100101101111011011100110000101101100001011100110010001110100011001000010001000111110000010100011110001101000011101000110110101101100001000000111100001101101011011000110111001110011001111010010001001101000011101000111010001110000001110100010111100101111011101110111011101110111001011100111011100110011001011100110111101110010011001110010111100110001001110010011100100111001001011110111100001101000011101000110110101101100001000100011111000001010001000000010000000111100011010000110010101100001011001000011111000001010001000000010000000100000001000000011110001110100011010010111010001101100011001010011111001010100011010000110100101110011001000000110100101110011001000000110000101101110001000000110010101111000011000010110110101110000011011000110010100100000001000010011110000101111011101000110100101110100011011000110010100111110000010100010000000100000001111000010111101101000011001010110000101100100001111100000101000100000001000000011110001100010011011110110010001111001001111100000101000100000001000000010000000100000001111000110100000110001001111100100010101111000011000010110110101110000011011000110010100100000011100000110000101100111011001010011110000101111011010000011000100111110000010100010000000100000001000000010000000111100011100000011111001000011011011110110111001110100011001010110111001110100001000000110111101100110001000000111010001101000011001010010000001110000011000010110011101100101001111000010111101110000001111100000100100001001000010010000100100100000001000000000101000100000001000000011110000101111011000100110111101100100011110010011111000001010001111000010111101101000011101000110110101101100001111100000101000001010')])]


    

    
    """

    def __init__(self, memory=None):
        if memory is None:
            self.memory = Memory()
        else:
            self.memory = memory

    @typeCheck(AbstractMessage, list)
    def parseFlow(self, message, symbols):
        """This method parses the specified message against the specification of one or multiple consecutive
        symbol. It returns a list of tuples, one tuple for each consecutive symbol that participate in the flow.
        A tuple is made of the symbol's and its alignment of the message part it applies on.
        If an error occurs, an Exception is raised."""

        if message is None:
            raise Exception("Specified cannot be None")
        if symbols is None or len(symbols) == 0:
            raise Exception(
                "Symbols cannot be None and must be a list of at least one symbol"
            )

        data_to_parse_raw = message.data
        data_to_parse_bitarray = TypeConverter.convert(data_to_parse_raw, Raw,
                                                       BitArray)

        for result in self._parseFlow_internal(data_to_parse_bitarray, symbols,
                                               self.memory):
            return result

        raise InvalidParsingPathException(
            "No parsing path returned while parsing '{}'".format(
                repr(data_to_parse_raw)))

    def _parseFlow_internal(self, data_to_parse_bitarray, symbols, memory):
        """Parses the specified data"""

        if data_to_parse_bitarray is None or len(data_to_parse_bitarray) == 0:
            raise Exception("Nothing to parse")

        for symbol in symbols:
            self._logger.debug("Parsing '{}' with Symbol '{}'".format(
                data_to_parse_bitarray, symbol.name))
            flow_parsing_results = []
            try:
                mp = MessageParser(memory=memory)
                results = mp.parseBitarray(
                    data_to_parse_bitarray.copy(),
                    symbol.getLeafFields(),
                    must_consume_everything=False)

                for parse_result in results:
                    parse_result_len = sum(
                        [len(value) for value in parse_result])

                    remainings_bitarray = data_to_parse_bitarray[
                        parse_result_len:]

                    if len(remainings_bitarray) > 0:
                        self._logger.debug(
                            "Try to parse the remaining data '{}' with another symbol".
                            format(remainings_bitarray))
                        try:
                            child_flow_parsings = self._parseFlow_internal(
                                remainings_bitarray, symbols,
                                memory.duplicate())
                            for child_flow_parsing in child_flow_parsings:
                                flow_parsing_results = [(symbol, parse_result)
                                                        ] + child_flow_parsing

                                yield flow_parsing_results
                        except InvalidParsingPathException:
                            pass
                    else:
                        flow_parsing_results = [(symbol, parse_result)]

                        yield flow_parsing_results

            except InvalidParsingPathException:
                pass
