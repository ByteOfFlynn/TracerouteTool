# Code modified or adapted from: CS 372 course work, "Computer Networking: A Top-Down Approach" by Kurose and Ross, and https://docs.python.org/3/library/socket.html

# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

# Run the error codes
ICMP_ERROR_MESSAGES = {
    3: {  # Unreachable
        0: "Network Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed and Don't Fragment was Set",
        5: "Source Route Failed",
        6: "Destination Network Unknown",
        7: "Destination Host Unknown",
        8: "Source Host Isolated",
        9: "Communication with Destination Network is Administratively Prohibited",
        10: "Communication with Destination Host is Administratively Prohibited",
        11: "Network Unreachable for Type of Service",
        12: "Host Unreachable for Type of Service",
        13: "Communication Administratively Prohibited",
        14: "Host Precedence Violation",
        15: "Precedence Cutoff in Effect",
    },
    11: {  # Time exceeded
        0: "Time to Live exceeded in Transit",
        1: "Fragment Reassembly Time Exceeded",
    },
}

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpType = 0
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetChecksum = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(
                    self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {
                  "Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count +
                                           1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {
                      hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(
                    checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = (checksum >> 16) + \
                checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            # Used to track overall round trip time
            data_time = struct.pack("d", time.time())
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            # packHeader() and encodeData() transfer data to their respective bit
            self.__packHeader()
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Compare packet
            sentIdentifier = self.getPacketIdentifier()
            recvIdentifier = icmpReplyPacket.getIcmpIdentifier()
            identifierIsValid = sentIdentifier == recvIdentifier
            icmpReplyPacket.setIcmpIdentifier_isValid(identifierIsValid)

            # Compare sequence
            sentSequence = self.getPacketSequenceNumber()
            recvSequence = icmpReplyPacket.getIcmpSequenceNumber()
            sequenceIsValid = sentSequence == recvSequence
            icmpReplyPacket.setIcmpSequenceNumber_isValid(sequenceIsValid)

            # Compare raw
            sentData = self.getDataRaw()
            recvData = icmpReplyPacket.getIcmpData()
            dataIsValid = sentData == recvData
            icmpReplyPacket.setIcmpData_isValid(dataIsValid)

            # Validify
            isValidResponse = identifierIsValid and sequenceIsValid and dataIsValid
            icmpReplyPacket.setIsValidResponse(isValidResponse)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 or len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " +
                  self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack(
                'I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                # Send the ICMP Echo Request
                mySocket.sendto(
                    b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)

                if whatReady[0] == []:  # Timeout
                    print(
                        "  *        *        *        *        *    Request timed out.")
                    return None, None, None, None, None

                # recvPacket - bytes object representing data received
                recvPacket, addr = mySocket.recvfrom(1024)
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print(
                        "  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return None, None, None, None, None

                # Fetch the ICMP type and code from the received packet
                icmpHeader = recvPacket[20:28]
                icmpType, icmpCode, icmpChecksum, icmpID, icmpSequence = struct.unpack(
                    "!BBHHH", icmpHeader)

                # RTT Calculation
                rtt = (timeReceived - pingStartTime) * 1000

                if icmpType == 11:  # Time Exceeded
                    print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (Time Exceeded)    %s" %
                          (self.getTtl(), rtt, icmpType, icmpCode, addr[0]))
                    return self.getTtl(), rtt, icmpType, icmpCode, addr[0]

                elif icmpType == 3:  # Destination Unreachable
                    error_message = ICMP_ERROR_MESSAGES.get(
                        icmpType, {}).get(icmpCode, "Unknown Error")
                    print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (%s)    %s" %
                          (self.getTtl(), rtt, icmpType, icmpCode, error_message, addr[0]))
                    return self.getTtl(), rtt, icmpType, icmpCode, addr[0]

                elif icmpType == 0:  # Echo Reply
                    icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(
                        recvPacket)
                    self.__validateIcmpReplyPacketWithOriginalPingData(
                        icmpReplyPacket)
                    icmpReplyPacket.printResultToConsole(
                        self.getTtl(), timeReceived, addr)
                    # Echo reply is the end, so we return
                    return self.getTtl(), rtt, icmpType, icmpCode, addr[0]

                else:
                    # Handling other ICMP types if they occur (though unexpected)
                    print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                          (self.getTtl(), rtt, icmpType, icmpCode, addr[0]))
                    return self.getTtl(), rtt, icmpType, icmpCode, addr[0]

            except timeout:
                print(
                    "  *        *        *        *        *    Request timed out (By Exception).")
                return None, None, None, None, None
            finally:
                mySocket.close()

        def sendTraceRouteEchoRequest(self):
            # If none
            if len(self.__icmpTarget.strip()) <= 0 or len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            # Create socket and set TTL
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL,
                                struct.pack('I', self.getTtl()))
            try:
                # Send echo request
                mySocket.sendto(
                    b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeSent = time.time()
                # Wait
                whatReady = select.select([mySocket], [], [], self.__ipTimeout)
                if whatReady[0] == []:
                    return None, None, None, None, False
                # Receive and extract, calculate RTT, and return
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                icmpHeader = recvPacket[20:28]
                icmpType, icmpCode, icmpChecksum, icmpID, icmpSequence = struct.unpack(
                    "!BBHHH", icmpHeader)
                rtt = (timeReceived - timeSent) * 1000

                return addr[0], rtt, icmpType, icmpCode, icmpType == 0
            except timeout:
                return None, None, None, None, False
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpData_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            # Used to track overall round trip time
            return self.__unpackByFormatAndPosition("d", 28)
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def setIcmpIdentifier_isValid(self, isValid):
            self.__IcmpIdentifier_isValid = isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid

        def setIcmpSequenceNumber_isValid(self, isValid):
            self.__IcmpSequenceNumber_isValid = isValid

        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        def setIcmpData_isValid(self, isValid):
            self.__IcmpData_isValid = isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes_in_double = struct.calcsize("d")
            timeSent = struct.unpack(
                "d", self.__recvPacket[28:28 + bytes_in_double])[0]
            rtt = (timeReceived - timeSent) * 1000

            if self.isValidResponse():
                print(f"  TTL={ttl}    RTT={rtt:.0f} ms    Type={self.getIcmpType()}    "
                      f"Code={self.getIcmpCode()}    Identifier={
                    self.getIcmpIdentifier()}    "
                    f"Sequence Number={self.getIcmpSequenceNumber()}    {addr[0]}")
            else:
                print("Invalid ICMP Reply:")
                if not self.getIcmpIdentifier_isValid():
                    print(f"  Identifier mismatch: Sent={
                          self.getIcmpIdentifier()}, Expected={self.getIcmpIdentifier()}")
                if not self.getIcmpSequenceNumber_isValid():
                    print(f"  Sequence Number mismatch: Sent={
                          self.getIcmpSequenceNumber()}, Expected={self.getIcmpSequenceNumber()}")
                if not self.getIcmpData_isValid():
                    print(f"  Data mismatch: Sent='{
                          self.getIcmpData()}', Expected='{self.getIcmpData()}'")

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        rtt_list = []
        packets_sent = 0
        packets_received = 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            # Get as 16 bit number - Limit based on ICMP header standards
            randomIdentifier = (os.getpid() & 0xffff)
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i
            packets_sent += 1

            icmpPacket.buildPacket_echoRequest(
                packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            ttl, rtt, icmpType, icmpCode, addr = icmpPacket.sendEchoRequest()           # Build IP
            if rtt is not None:
                rtt_list.append(rtt)
                packets_received += 1

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # For statistics
        if rtt_list:
            min_rtt = min(rtt_list)
            max_rtt = max(rtt_list)
            avg_rtt = sum(rtt_list) / len(rtt_list)
        else:
            min_rtt = max_rtt = avg_rtt = 0

        packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
        print("\n--- {} statistics ---".format(host))
        print("{} packets transmitted, {} packets received, {:.1f}% packet loss".format(
            packets_sent, packets_received, packet_loss))
        print(
            "round-trip min/avg/max = {:.3f}/{:.3f}/{:.3f} ms".format(min_rtt, avg_rtt, max_rtt))

    def __sendIcmpTraceRoute(self, host):
        if self.__DEBUG_IcmpHelperLibrary:
            print("sendIcmpTraceRoute Started...")
        max_hops = 50

        print(f"Tracing route to {host} over a maximum of {max_hops} hops:")

        for ttl in range(1, max_hops + 1):
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            icmpPacket.setTtl(ttl)
            randomIdentifier = (os.getpid() & 0xffff)
            packetIdentifier = randomIdentifier
            packetSequenceNumber = ttl
            # Build packet and set target
            icmpPacket.buildPacket_echoRequest(
                packetIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(host)
            address, rtt, icmpType, icmpCode, success = icmpPacket.sendTraceRouteEchoRequest()

            if address:
                error_message = ICMP_ERROR_MESSAGES.get(
                    icmpType, {}).get(icmpCode, "")
                if error_message:
                    error_message = f"({error_message})"
                else:
                    error_message = ""
                print(f"{ttl}\tRTT={rtt:.0f} ms\tType={icmpType}\tCode={
                      icmpCode} {error_message}\t{address}")
            else:
                print(f"{ttl}\t*\tRequest timed out")
            if success and icmpType == 0:
                print("Trace complete.")
                break

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    icmpHelperPing.traceRoute("1.1.1.1")
    # icmpHelperPing.traceRoute("133.11.11.11")
    # icmpHelperPing.traceRoute("200.10.227.250")
    # icmpHelperPing.traceRoute("51.91.60.105")


if __name__ == "__main__":
    main()
