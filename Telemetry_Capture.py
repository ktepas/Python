from PyQt5 import QtWidgets as qtw
from PyQt5 import QtCore as qtc
from PyQt5 import QtGui as qtg

import socket
import struct
import datetime


class MainWindow(qtw.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # UI Setup
        self.setWindowTitle("FC Msg Test Application")

        self.layout = qtw.QGridLayout()

        self.setLayout(self.layout)

        self.msgIDs = {id: [0, None] for id in
                       [4000, 4001, 4002, 4003, 4004, 4005, 4006, 4008, 4009, 4202, 4203, 4204, 4205, 4207, 4208, 4209,
                        4210, 4211, 4212, 4213, 4214, 4215, 4216, 4217, 4220, 4218, 4219, 2300, 3900, 1201, 1202, 1203]}
        self.labels = {}

        for idx, msgId in enumerate(self.msgIDs):
            self.labels[msgId] = qtw.QLabel(f"Message <b>{msgId}</b> Count: 0   Last Timestamp: None")
            self.layout.addWidget(self.labels[msgId])

            # If it's not the last label, add a horizontal separator
            if idx < len(self.msgIDs) - 1:
                separator = qtw.QFrame()
                separator.setFrameShape(qtw.QFrame.HLine)
                separator.setFrameShadow(qtw.QFrame.Sunken)
                self.layout.addWidget(separator)

        self.show()

        # UDP Setup
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(('192.168.101.50', 2224))
        self.udp_socket.setblocking(False)

        # Set up a notifier for the socket
        self.notifier = qtc.QSocketNotifier(self.udp_socket.fileno(), qtc.QSocketNotifier.Read)
        self.notifier.activated.connect(self.read_data)

    def parse_message_4001(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])

        # Extract PIC State and WF Status from the 11th byte

        pic_state = data[20]# Mask out the last 2 bits
          # Only get the last 2 bits

        # Extract the number of one-hop neighbors from the 12th byte
        num_neighbors = data[21]

        return timestamp, pic_state, num_neighbors

    def parse_message_4002(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])

        # Extract major version from the next 2 bytes
        major_version = " ".join([f"{data[i]:02X}" for i in range(20, 21)])

        # Extract minor version from the subsequent 2 bytes
        minor_version = " ".join([f"{data[i]:02X}" for i in range(22, 23)])

        # Extract hash of system files from the next 4 bytes
        hash_system_files = " ".join([f"{data[i]:02X}" for i in range(24, 27)])

        # Extract bootsector from the following byte
        bootsector = data[28]

        return timestamp, major_version, minor_version, hash_system_files, bootsector

    def parse_message_4003(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])


        bitmap = data[20]

        return timestamp, bitmap

    def parse_message_4004(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])
        bitmap = data[20]
        return timestamp, bitmap

    def parse_message_4005(self, data):



        timestamp = data[12:19]  # Assuming big endian format and 8-byte timestamp
        sw_red_partition = data[20]
        sw_black_partition = data[21]
        sw_css_partition = data[22]
        dom0 = data[23]

        return timestamp, sw_red_partition, sw_black_partition, sw_css_partition, dom0


    def parse_message_4006(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])


        network = data[20]

        return timestamp, network


    def parse_message_4007(self, data):
        # Extract timestamp from the first 10 bytes
        timestamp = " ".join([f"{data[i]:02X}" for i in range(12, 20)])


        node_id = data[20]
        alarm_id = data [21]
        alarm_count = data [22:29]

        return timestamp, node_id, alarm_id, alarm_count

    def parse_message_4008(self, data):


        timestamp = data[12:20]  # Assuming big endian format and 8-byte timestamp
        nd_request_tx_cnt = data[20:23]
        nd_request_rx_cnt = data[24:27]
        nd_response_tx_cnt = data[28:31]
        nd_response_rx_cnt = data[32:36]

        return timestamp, nd_request_tx_cnt, nd_request_rx_cnt, nd_response_tx_cnt, nd_response_rx_cnt

    def read_data(self):
        try:
            data, addr = self.udp_socket.recvfrom(1024)
            if len(data) >= 12:  # Only attempt to unpack if data is at least 12 bytes
                _, _, _, _, msgId, _ = struct.unpack('!HHHHHH', data[:12])
                # Check if this message ID is one we're tracking
                if msgId in self.msgIDs:
                    self.msgIDs[msgId][0] += 1
                    self.msgIDs[msgId][1] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # debug prints
                    # print("This is the message and data")
                    # bytes_msg = " ".join([f"{data[i]:02X}" for i in range(8, 10)])
                    # print(msgId, bytes_msg)

                    if msgId == 4000:  # Only process data for msgId 4000
                        # self.msgIDs[msgId][0] += 1
                        # self.msgIDs[msgId][1] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        #print("heartbeat data: ", data)

                        # Extracting 9th and 10th bytes and converting to hex
                        bytes_9_10 = " ".join(
                            [f"{data[i]:02X}" for i in range(8, 10)])  # Note: Python uses 0-based indexing
                        data_hex = " ".join([f"{byte:02X}" for byte in data])  # Convert data to hex format
                        timestamp_h = " ".join([f"{data[i]:02X}" for i in range(12, 20)])

                        # Extracting everything from byte 20 onwards and converting to hex
                        data_from_22_onwards = " ".join([f"{byte:02X}" for byte in data[20:]])

                        # Extract the 24th byte and convert to decimal
                        byte_24 = data[23] if len(data) > 23 else None
                        byte_24_decimal = int(byte_24) if byte_24 is not None else "N/A"

                        # Extract bytes starting from the 25th byte, with length = byte_24_decimal
                        tlv0_start = 24  # Index for the 25th byte
                        tlv0_end = tlv0_start + byte_24_decimal
                        tlv0 = data[tlv0_start:tlv0_end]
                        # print("debug ", tlv0)
                        tlv0_decimal = " ".join([str(byte) for byte in tlv0])
                        # Convert tlv0 bytes to a hex string representation
                        tlv0_hex = " ".join([f"{byte:02X}" for byte in tlv0])

                        # tlv1
                        byte_tlv1 = tlv0_end
                        tlv1_bytes = data[byte_tlv1: byte_tlv1 + 2]
                        tlv1_bytes_string = " ".join([f"{byte:02X}" for byte in tlv1_bytes])
                        if tlv1_bytes_string == "00 01":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv1_length_start = byte_tlv1 + 2
                            tlv1_length_bytes = data[tlv1_length_start: tlv1_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv1_length = int.from_bytes(tlv1_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv1_data_start = tlv1_length_start + 2
                            tlv1_data_end = tlv1_data_start + tlv1_length
                            tlv1_data = data[tlv1_data_start: tlv1_data_start + tlv1_length]
                            tlv1_data_string = " ".join([f"{byte:02X}" for byte in tlv1_data])

                        # tlv2
                        byte_tlv2 = tlv1_data_end
                        tlv2_bytes = data[byte_tlv2: byte_tlv2 + 2]
                        tlv2_bytes_string = " ".join([f"{byte:02X}" for byte in tlv2_bytes])
                        if tlv2_bytes_string == "00 02":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv2_length_start = byte_tlv2 + 2
                            tlv2_length_bytes = data[tlv2_length_start: tlv2_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv2_length = int.from_bytes(tlv2_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv2_data_start = tlv2_length_start + 2
                            tlv2_data_end = tlv2_data_start + tlv2_length
                            tlv2_data = data[tlv2_data_start: tlv2_data_start + tlv2_length]
                            tlv2_data_string = " ".join([f"{byte:02X}" for byte in tlv2_data])

                        # tlv3
                        byte_tlv3 = tlv2_data_end
                        tlv3_bytes = data[byte_tlv3: byte_tlv3 + 2]
                        tlv3_bytes_string = " ".join([f"{byte:02X}" for byte in tlv3_bytes])
                        if tlv3_bytes_string == "00 03":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv3_length_start = byte_tlv3 + 2
                            tlv3_length_bytes = data[tlv3_length_start: tlv3_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv3_length = int.from_bytes(tlv3_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv3_data_start = tlv3_length_start + 2
                            tlv3_data_end = tlv3_data_start + tlv3_length
                            tlv3_data = data[tlv3_data_start: tlv3_data_start + tlv3_length]
                            tlv3_data_string = " ".join([f"{byte:02X}" for byte in tlv3_data])
                        else:
                            tlv4_data_string = "N/A"

                        # tlv4
                        byte_tlv4 = tlv3_data_end
                        tlv4_bytes = data[byte_tlv4: byte_tlv4 + 2]
                        tlv4_bytes_string = " ".join([f"{byte:02X}" for byte in tlv4_bytes])
                        if tlv4_bytes_string == "00 04":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv4_length_start = byte_tlv4 + 2
                            tlv4_length_bytes = data[tlv4_length_start: tlv4_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv4_length = int.from_bytes(tlv4_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv4_data_start = tlv4_length_start + 2
                            tlv4_data_end = tlv4_data_start + tlv4_length
                            tlv4_data = data[tlv4_data_start: tlv4_data_start + tlv4_length]
                            tlv4_data_string = " ".join([f"{byte:02X}" for byte in tlv4_data])
                        else:
                            tlv4_data_string = "N/A"
                            tlv4_data_end = tlv3_data_end

                        # tlv5
                        byte_tlv5 = tlv4_data_end
                        tlv5_bytes = data[byte_tlv5: byte_tlv5 + 2]
                        tlv5_bytes_string = " ".join([f"{byte:02X}" for byte in tlv5_bytes])
                        if tlv5_bytes_string == "00 05":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv5_length_start = byte_tlv5 + 2
                            tlv5_length_bytes = data[tlv5_length_start: tlv5_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv5_length = int.from_bytes(tlv5_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv5_data_start = tlv5_length_start + 2
                            tlv5_data_end = tlv5_data_start + tlv5_length
                            tlv5_data = data[tlv5_data_start: tlv5_data_start + tlv5_length]
                            tlv5_data_string = " ".join([f"{byte:02X}" for byte in tlv5_data])
                        else:
                            tlv5_data_string = "N/A"
                            tlv5_data_end = tlv3_data_end

                        # tlv6
                        byte_tlv6 = tlv5_data_end
                        tlv6_bytes = data[byte_tlv6: byte_tlv6 + 2]
                        tlv6_bytes_string = " ".join([f"{byte:02X}" for byte in tlv6_bytes])
                        if tlv6_bytes_string == "00 06":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv6_length_start = byte_tlv6 + 2
                            tlv6_length_bytes = data[tlv6_length_start: tlv6_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv6_length = int.from_bytes(tlv6_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv6_data_start = tlv6_length_start + 2
                            tlv6_data_end = tlv6_data_start + tlv6_length
                            tlv6_data = data[tlv6_data_start: tlv6_data_start + tlv6_length]
                            tlv6_data_string = " ".join([f"{byte:02X}" for byte in tlv6_data])
                        else:
                            tlv6_data_string = "N/A"
                            tlv6_data_end = tlv3_data_end

                        # tlv7
                        byte_tlv7 = tlv6_data_end
                        tlv7_bytes = data[byte_tlv7: byte_tlv7 + 2]
                        tlv7_bytes_string = " ".join([f"{byte:02X}" for byte in tlv7_bytes])
                        if tlv7_bytes_string == "00 07":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv7_length_start = byte_tlv7 + 2
                            tlv7_length_bytes = data[tlv7_length_start: tlv7_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv7_length = int.from_bytes(tlv7_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv7_data_start = tlv7_length_start + 2
                            tlv7_data_end = tlv7_data_start + tlv7_length
                            tlv7_data = data[tlv7_data_start: tlv7_data_start + tlv7_length]
                            tlv7_data_string = " ".join([f"{byte:02X}" for byte in tlv7_data])
                        else:
                            tlv7_data_string = "N/A"
                            tlv7_data_end = tlv3_data_end

                        # tlv8
                        byte_tlv8 = tlv7_data_end
                        tlv8_bytes = data[byte_tlv8: byte_tlv8 + 2]
                        tlv8_bytes_string = " ".join([f"{byte:02X}" for byte in tlv8_bytes])
                        if tlv8_bytes_string == "00 08":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv8_length_start = byte_tlv8 + 2
                            tlv8_length_bytes = data[tlv8_length_start: tlv8_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv8_length = int.from_bytes(tlv8_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv8_data_start = tlv8_length_start + 2
                            tlv8_data_end = tlv8_data_start + tlv8_length
                            tlv8_data = data[tlv8_data_start: tlv8_data_start + tlv8_length]
                            tlv8_data_string = " ".join([f"{byte:02X}" for byte in tlv8_data])
                        else:
                            tlv8_data_string = "N/A"
                            tlv8_data_end = tlv3_data_end

                        # tlv9
                        byte_tlv9 = tlv8_data_end
                        tlv9_bytes = data[byte_tlv9: byte_tlv9 + 2]
                        tlv9_bytes_string = " ".join([f"{byte:02X}" for byte in tlv9_bytes])
                        if tlv9_bytes_string == "00 09":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv9_length_start = byte_tlv9 + 2
                            tlv9_length_bytes = data[tlv9_length_start: tlv9_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv9_length = int.from_bytes(tlv9_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv9_data_start = tlv9_length_start + 2
                            tlv9_data_end = tlv9_data_start + tlv9_length
                            tlv9_data = data[tlv9_data_start: tlv9_data_start + tlv9_length]
                            tlv9_data_string = " ".join([f"{byte:02X}" for byte in tlv9_data])
                        else:
                            tlv9_data_string = "N/A"
                            tlv9_data_end = tlv3_data_end

                        # tlv10
                        byte_tlv10 = tlv9_data_end
                        tlv10_bytes = data[byte_tlv10: byte_tlv10 + 2]
                        tlv10_bytes_string = " ".join([f"{byte:02X}" for byte in tlv10_bytes])
                        if tlv10_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv10_length_start = byte_tlv10 + 2
                            tlv10_length_bytes = data[tlv10_length_start: tlv10_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv10_length = int.from_bytes(tlv10_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv10_data_start = tlv10_length_start + 2
                            tlv10_data_end = tlv10_data_start + tlv10_length
                            tlv10_data = data[tlv10_data_start: tlv10_data_start + tlv10_length]
                            tlv10_data_string = " ".join([f"{byte:02X}" for byte in tlv10_data])
                        else:
                            tlv10_data_string = "N/A"
                            tlv10_data_end = tlv3_data_end

                        # tlv11
                        byte_tlv11 = tlv10_data_end
                        tlv11_bytes = data[byte_tlv11: byte_tlv11 + 2]
                        tlv11_bytes_string = " ".join([f"{byte:02X}" for byte in tlv11_bytes])
                        if tlv11_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv11_length_start = byte_tlv11 + 2
                            tlv11_length_bytes = data[tlv11_length_start: tlv11_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv11_length = int.from_bytes(tlv11_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv11_data_start = tlv11_length_start + 2
                            tlv11_data_end = tlv11_data_start + tlv11_length
                            tlv11_data = data[tlv11_data_start: tlv11_data_start + tlv11_length]
                            tlv11_data_string = " ".join([f"{byte:02X}" for byte in tlv11_data])
                        else:
                            tlv11_data_string = "N/A"
                            tlv11_data_end = tlv3_data_end

                        # tlv12
                        byte_tlv12 = tlv11_data_end
                        tlv12_bytes = data[byte_tlv12: byte_tlv12 + 2]
                        tlv12_bytes_string = " ".join([f"{byte:02X}" for byte in tlv12_bytes])
                        if tlv12_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv12_length_start = byte_tlv12 + 2
                            tlv12_length_bytes = data[tlv12_length_start: tlv12_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv12_length = int.from_bytes(tlv12_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv12_data_start = tlv12_length_start + 2
                            tlv12_data_end = tlv12_data_start + tlv12_length
                            tlv12_data = data[tlv12_data_start: tlv12_data_start + tlv12_length]
                            tlv12_data_string = " ".join([f"{byte:02X}" for byte in tlv12_data])
                        else:
                            tlv12_data_string = "N/A"
                            tlv12_data_end = tlv3_data_end

                        # tlv13
                        byte_tlv13 = tlv12_data_end
                        tlv13_bytes = data[byte_tlv10: byte_tlv10 + 2]
                        tlv13_bytes_string = " ".join([f"{byte:02X}" for byte in tlv13_bytes])
                        if tlv13_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv13_length_start = byte_tlv13 + 2
                            tlv13_length_bytes = data[tlv13_length_start: tlv13_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv13_length = int.from_bytes(tlv13_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv13_data_start = tlv13_length_start + 2
                            tlv13_data_end = tlv13_data_start + tlv13_length
                            tlv13_data = data[tlv13_data_start: tlv13_data_start + tlv13_length]
                            tlv13_data_string = " ".join([f"{byte:02X}" for byte in tlv13_data])
                        else:
                            tlv13_data_string = "N/A"
                            tlv13_data_end = tlv3_data_end

                        # tlv14
                        byte_tlv14 = tlv13_data_end
                        tlv14_bytes = data[byte_tlv14: byte_tlv14 + 2]
                        tlv14_bytes_string = " ".join([f"{byte:02X}" for byte in tlv14_bytes])
                        if tlv14_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv14_length_start = byte_tlv14 + 2
                            tlv14_length_bytes = data[tlv14_length_start: tlv14_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv14_length = int.from_bytes(tlv14_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv14_data_start = tlv14_length_start + 2
                            tlv14_data_end = tlv14_data_start + tlv14_length
                            tlv14_data = data[tlv14_data_start: tlv14_data_start + tlv14_length]
                            tlv14_data_string = " ".join([f"{byte:02X}" for byte in tlv14_data])
                        else:
                            tlv14_data_string = "N/A"
                            tlv14_data_end = tlv3_data_end

                        # tlv15
                        byte_tlv15 = tlv14_data_end
                        tlv15_bytes = data[byte_tlv15: byte_tlv15 + 2]
                        tlv15_bytes_string = " ".join([f"{byte:02X}" for byte in tlv15_bytes])
                        if tlv15_bytes_string == "00 0a":
                            # Extracting the 3rd and 4th byte after tlv1_bytes for the length
                            tlv15_length_start = byte_tlv15 + 2
                            tlv15_length_bytes = data[tlv15_length_start: tlv15_length_start + 2]
                            # Assuming the length bytes are in big-endian format
                            tlv15_length = int.from_bytes(tlv15_length_bytes, byteorder='big')

                            # Extracting the data bytes after the length, as determined by tlv1_length
                            tlv15_data_start = tlv15_length_start + 2
                            tlv15_data_end = tlv15_data_start + tlv15_length
                            tlv15_data = data[tlv15_data_start: tlv15_data_start + tlv15_length]
                            tlv15_data_string = " ".join([f"{byte:02X}" for byte in tlv15_data])
                        else:
                            tlv15_data_string = "N/A"
                            tlv15_data_end = tlv3_data_end

                        #Add the TLV print messages here
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp Data: {timestamp_h} <b>TLV0:</b> {tlv0_decimal} <b>TLV1:</b> {tlv1_data_string} <b>TLV2:</b> {tlv2_data_string} <b>TLV3:</b> {tlv3_data_string} <b>TLV4:</b> {tlv4_data_string} <b>TLV5:</b> {tlv5_data_string} <b>TLV6:</b> {tlv6_data_string} <b>TLV7:</b> {tlv7_data_string} <b>TLV8:</b> {tlv8_data_string} <b>TLV9:</b> {tlv9_data_string} <b>TLV10:</b> {tlv10_data_string}")

                    elif msgId == 4001:
                        timestamp, pic_state, wf_status, num_neighbors = self.parse_message_4001(data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} Pic State: {pic_state} Num Neighbors: {num_neighbors}")

                    elif msgId == 4002:
                        timestamp, major_version, minor_version, hash_system_files, bootsector = self.parse_message_4002(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} major version: {major_version} minor version: {minor_version} hash system files: {hash_system_files} bootsector: {bootsector}")

                    elif msgId == 4003:
                        timestamp, major_version, minor_version, hash_system_files, bootsector = self.parse_message_4003(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} bitmap: {bitmap}")
                    elif msgId == 4004:
                        timestamp, major_version, minor_version, hash_system_files, bootsector = self.parse_message_4004(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} bitmap: {bitmap}")


                    elif msgId == 4005:
                        timestamp, sw_red_partition, sw_black_partition, sw_css_partition, dom0 = self.parse_message_4005(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]} Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} SW Red Partition: {sw_red_partition} SW Black Partition: {sw_black_partition} SW CSS Partition: {sw_css_partition} Dom0 (host): {dom0}")

                    elif msgId == 4006:
                        timestamp, major_version, minor_version, hash_system_files, bootsector = self.parse_message_4006(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} network: {network}")

                    elif msgId == 4008:
                        timestamp, nd_request_tx_cnt, nd_request_rx_cnt, nd_response_tx_cnt, nd_response_rx_cnt = self.parse_message_4008(
                            data)
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]} Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)} Timestamp: {timestamp} ND requestTxCnt: {nd_request_tx_cnt} ND requestRxCnt: {nd_request_rx_cnt} ND responseTxCnt: {nd_response_tx_cnt} ND responseRxCnt: {nd_response_rx_cnt}")

                    else:
                        self.labels[msgId].setText(
                            f"Message <b>{msgId}</b> Count: {self.msgIDs[msgId][0]}   Last Timestamp: {self.msgIDs[msgId][1]} Data Length: {len(data)}")

        except BlockingIOError:
            pass


# Bytes 9-10: {bytes_9_10} Data Length: {len(data)} Data: {data_from_22_onwards}

if __name__ == '__main__':
    app = qtw.QApplication([])
    mw = MainWindow()
    app.exec_()
