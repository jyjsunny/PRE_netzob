#-*- coding: utf-8 -*-

#+---------------------------------------------------------------------------+
#|          01001110 01100101 01110100 01111010 01101111 01100010            |
#|                                                                           |
#|               Netzob : Inferring communication protocols                  |
#+---------------------------------------------------------------------------+
#| Copyright (C) 2011-2017 Georges Bossert and Frédéric Guihéry              |
#| This program is free software: you can redistribute it and/or modify      |
#| it under the terms of the GNU General Public License as published by      |
#| the Free Software Foundation, either version 3 of the License, or         |
#| (at your option) any later version.                                       |
#|                                                                           |
#| This program is distributed in the hope that it will be useful,           |
#| but WITHOUT ANY WARRANTY; without even the implied warranty of            |
#| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the              |
#| GNU General Public License for more details.                              |
#|                                                                           |
#| You should have received a copy of the GNU General Public License         |
#| along with this program. If not, see <http://www.gnu.org/licenses/>.      |
#+---------------------------------------------------------------------------+
#| @url      : http://www.netzob.org                                         |
#| @contact  : contact@netzob.org                                            |
#| @sponsors : Amossys, http://www.amossys.fr                                |
#|             Supélec, http://www.rennes.supelec.fr/ren/rd/cidre/           |
#|             ANSSI,   https://www.ssi.gouv.fr                              |
#+---------------------------------------------------------------------------+

#+---------------------------------------------------------------------------+
#| File contributors :                                                       |
#|       - Frédéric Guihéry <frederic.guihery (a) amossys.fr>                |
#+---------------------------------------------------------------------------+

#+---------------------------------------------------------------------------+
#| Standard library imports                                                  |
#+---------------------------------------------------------------------------+
import socket
import binascii
from bitarray import bitarray

#+---------------------------------------------------------------------------+
#| Related third party imports                                               |
#+---------------------------------------------------------------------------+

#+---------------------------------------------------------------------------+
#| Local application imports                                                 |
#+---------------------------------------------------------------------------+
from netzob.Common.Utils.Decorators import typeCheck, NetzobLogger
from netzob.Simulator.AbstractChannel import AbstractChannel, NetUtils
from netzob.Simulator.ChannelBuilder import ChannelBuilder
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Domain.Variables.Leafs.Padding import Padding
from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Types.Raw import Raw
from netzob.Model.Vocabulary.Types.Integer import uint16be


@NetzobLogger
class EthernetChannel(AbstractChannel):
    r"""A EthernetChannel is a communication channel to send Ethernet
    frames. This channel is responsible for building the Ethernet
    layer.

    The EthernetChannel constructor expects some parameters:

    :param remoteMac: This parameter is the remote MAC address to connect to.
    :param localMac: This parameter is the local MAC address.
    :param timeout: The default timeout of the channel for global
                    connection. Default value is blocking (None).
    :type remoteMac: :class:`str` or :class:`netaddr.EUI`, required
    :type localMac: :class:`str` or :class:`netaddr.EUI`, required
    :type timeout: :class:`float`, optional

    .. todo:: add support of netaddr.EUI

    Adding to AbstractChannel variables, the EthernetChannel class provides
    the following public variables:

    :var remoteMac: The remote MAC address to connect to.
    :var localMac: The local MAC address.
    :var interface: The network Interface name such as 'eth0', 'lo', determined
                    with the local MAC address. Read only variable.
    :vartype remoteMac: :class:`str`
    :vartype localMac: :class:`str`
    :vartype interface: :class:`str`


    >>> from netzob.all import *
    >>> from binascii import hexlify
    >>> client = EthernetChannel(
    ...    remoteMac="00:01:02:03:04:05",
    ...    localMac="00:06:07:08:09:10")
    >>> client.open()
    >>> symbol = Symbol([Field("ABC")])
    >>> client.write(symbol.specialize())
    17
    >>> client.close()

    """

    ## Class attributes ##

    ETH_P_ALL = 3
    FAMILIES = ["ethernet"]

    @typeCheck(str, str)
    def __init__(self,
                 remoteMac,
                 localMac,
                 timeout=AbstractChannel.DEFAULT_TIMEOUT):
        super(EthernetChannel, self).__init__(timeout=timeout)
        self.remoteMac = remoteMac
        self.localMac = localMac
        self.__interface = NetUtils.getLocalInterfaceFromMac(self.localMac)

        if self.__interface is None:
            raise Exception(
                "No interface found for '{}' MAC address".format(self.localMac))

        self.initHeader()

    @staticmethod
    def getBuilder():
        return EthernetChannelBuilder

    def initHeader(self):
        eth_dst = Field(name='eth.dst', domain=Raw(self.macToBitarray(self.remoteMac)))
        eth_src = Field(name='eth.src', domain=Raw(self.macToBitarray(self.localMac)))
        eth_type = Field(name='eth.type', domain=uint16be())
        eth_payload = Field(name='eth.payload', domain=Raw())
        # PADDING field is present if frame length < 60 bytes (+ 4 optional CRC bytes)
        ethPaddingVariable = Padding([eth_dst,
                                      eth_src,
                                      eth_type,
                                      eth_payload],
                                     data=Raw(nbBytes=1),
                                     modulo=8*60,
                                     once=True)
        eth_padding = Field(ethPaddingVariable, "eth.padding")
        self.header = Symbol(name='Ethernet layer', fields=[eth_dst,
                                                            eth_src,
                                                            eth_type,
                                                            eth_payload,
                                                            eth_padding])

    def open(self, timeout=AbstractChannel.DEFAULT_TIMEOUT):
        """Open the communication channel. If the channel is a client, it
        starts to connect to the specified server.

        :param timeout: The default timeout of the channel for opening
                        connection and waiting for a message. Default value
                        is blocking (None).
        :type timeout: :class:`float`, optional
        :raise: RuntimeError if the channel is already opened

        """

        super().open(timeout=timeout)

        self._socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(EthernetChannel.ETH_P_ALL))
        self._socket.settimeout(timeout or self.timeout)
        self._socket.bind((self.interface, EthernetChannel.ETH_P_ALL))
        self.isOpen = True

    def close(self):
        """Close the communication channel."""
        if self._socket is not None:
            self._socket.close()
        self.isOpen = False

    def read(self):
        """Read the next message on the communication channel.
        """
        if self._socket is not None:
            (data, _) = self._socket.recvfrom(65535)

            # Remove Ethernet header from received data
            ethHeaderLen = 14
            if len(data) > ethHeaderLen:
                data = data[ethHeaderLen:]

            return data
        else:
            raise Exception("socket is not available")

    def sendReceive(self, data):
        """Write on the communication channel and returns the next packet
        coming from the destination address.

        :param data: the data to write on the channel
        :type data: :class:`bytes`
        """
        if self._socket is not None:

            rawRemoteMac = binascii.unhexlify(self.remoteMac.replace(':', ''))
            self.write(data)
            while True:
                (data, _) = self._socket.recvfrom(65535)
                if data[6:12] == rawRemoteMac:
                    # Remove Ethernet header from received data
                    ethHeaderLen = 14
                    if len(data) > ethHeaderLen:
                        data = data[ethHeaderLen:]
                    return data
        else:
            raise Exception("socket is not available")

    def write(self, data, upperProtocol=0x0800, rate=None, duration=None):
        """Write to the communication channel the specified data.

        :param data: The data to write on the channel.
        :param rate: This specifies the bandwidth in octets to respect during
                     traffic emission (should be used with duration= parameter).
        :param upperProtocol: The protocol following Ethernet in the stack.
                              Default value is IPv4 (0x0800)
        :param duration: This tells how much seconds the symbol is continuously
                         written on the channel.
        :type data: :class:`bytes`, required
        :type upperProtocol: :class:`int`, optional
        :type rate: :class:`int`, optional
        :type duration: :class:`int`, optional
        :return: The amount of written data, in bytes.
        :rtype: :class:`int`
        """
        self._setProtocol(upperProtocol)
        return super().write(data, rate=rate, duration=duration)

    def writePacket(self, data):
        """Write on the communication channel the specified data

        :param data: the data to write on the channel
        :type data: :class:`bytes`
        """

        if self._socket is None:
            raise Exception("socket is not available")

        self.header_presets["eth.payload"] = data
        packet = self.header.specialize(presets=self.header_presets)
        len_data = self._socket.sendto(packet, (self.interface,
                                                EthernetChannel.ETH_P_ALL))
        return len_data

    def macToBitarray(self, addr):
        """Converts a mac address represented as a string to its bitarray value.

        >>> client = EthernetChannel('00:01:02:03:04:05', '06:07:08:09:10:11')
        >>> client.macToBitarray('00:01:02:03:04:05')
        bitarray('000000000000000100000010000000110000010000000101')
        >>> client.macToBitarray(b'\\x00\\x01\\x02\\x03\\x04\\x05')
        bitarray('000000000000000100000010000000110000010000000101')
        """

        if addr is None:
            return bitarray(48)

        if isinstance(addr, bytes):
            addr = binascii.hexlify(addr).decode()

        numeric = int(addr.replace(":", ""), 16)
        binary = bin(numeric)[2:]
        binLength = len(binary)
        if binLength > 48:
            raise Exception("Binary overflow while converting hexadecimal value")

        binary = "0" * (48 - binLength) + binary
        return bitarray(binary)

    @typeCheck(int)
    def _setProtocol(self, upperProtocol):
        if upperProtocol < 0 or upperProtocol > 0xffff:
            raise TypeError("Upper protocol should be between 0 and 0xffff")

        self.header_presets['eth.type'] = upperProtocol

    # Properties

    @property
    def remoteMac(self):
        """Remote hardware address (MAC)

        :type: :class:`str`
        """
        return self.__remoteMac

    @remoteMac.setter  # type: ignore
    @typeCheck(str)
    def remoteMac(self, remoteMac):
        if remoteMac is None:
            raise TypeError("remoteMac cannot be None")
        self.__remoteMac = remoteMac

    @property
    def localMac(self):
        """Local hardware address (MAC)

        :type: :class:`str`
        """
        return self.__localMac

    @localMac.setter  # type: ignore
    @typeCheck(str)
    def localMac(self, localMac):
        if localMac is None:
            raise TypeError("localMac cannot be None")
        self.__localMac = localMac

    @property
    def interface(self):
        """Local network interface name (such as 'eth0', 'lo').

        :type: :class:`str`
        """
        return self.__interface


class EthernetChannelBuilder(ChannelBuilder):
    """
    This builder is used to create an
    :class:`~netzob.Simulator.Channel.EthernetChannel.EthernetChannel` instance

    >>> from netzob.Simulator.Channels.NetInfo import NetInfo
    >>> netinfo = NetInfo(dst_addr="00:11:22:33:44:55",
    ...                   src_addr="55:44:33:22:11:00",
    ...                   protocol=0x0800,
    ...                   interface="eth0")
    >>> chan = EthernetChannelBuilder().set_map(netinfo.getDict()).build()
    >>> assert isinstance(chan, EthernetChannel)
    """

    def __init__(self):
        super().__init__(EthernetChannel)

    def set_src_addr(self, value):
        self.attrs['localMac'] = value

    def set_dst_addr(self, value):
        self.attrs['remoteMac'] = value
