from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QTableWidget, QTableWidgetItem, 
                             QTextEdit, QWidget, QSplitter, QPushButton)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from scapy.all import Ether, IP, TCP, UDP, ARP, ICMP

from capture_packets import capture_packets  # Packet capture function import
from ids import IntrusionDetectionSystem  # IDS class import


class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)  # Signal for packet updates
    alert_signal = pyqtSignal(str)  # Signal for IDS alerts

    def __init__(self, ids_system):
        super().__init__()
        self.ids_system = ids_system
        self.running = False

    def run(self):
        self.running = True
        capture_packets(self.process_packet)

    def process_packet(self, packet):
        # Emit the packet to update the UI
        self.packet_captured.emit(packet)
        
        # Run the IDS check on the packet
        alert = self.ids_system.generate_alerts(packet)
        if alert:
            self.alert_signal.emit(alert)

    def stop(self):
        self.running = False
        self.terminate()  # Stop the thread gracefully


class AuroraScan(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AuroraScan - Network Packet Analyzer")
        self.setGeometry(200, 100, 1200, 800)

        # IDS instance
        self.ids_system = IntrusionDetectionSystem()

        # Main Layout: Split horizontally for packet list and details/alerts
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create a splitter for better layout control
        splitter = QSplitter(Qt.Horizontal)

        # Packet List Table
        self.packetListDisplay = QTableWidget()
        self.packetListDisplay.setColumnCount(5)
        self.packetListDisplay.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol'])
        self.packetListDisplay.itemSelectionChanged.connect(self.display_selected_packet_details)
        splitter.addWidget(self.packetListDisplay)

        # Right side: Packet details and alerts
        right_layout = QVBoxLayout()
        self.packetDetailDisplay = QTextEdit()
        self.packetDetailDisplay.setReadOnly(True)
        right_layout.addWidget(QLabel("Packet Details"))
        right_layout.addWidget(self.packetDetailDisplay)

        self.packetBytesDisplay = QTextEdit()
        self.packetBytesDisplay.setReadOnly(True)
        right_layout.addWidget(QLabel("Packet Bytes"))
        right_layout.addWidget(self.packetBytesDisplay)

        self.idsAlertDisplay = QTextEdit()
        self.idsAlertDisplay.setReadOnly(True)
        self.idsAlertDisplay.setPlaceholderText("IDS Alerts will appear here...")
        right_layout.addWidget(QLabel("IDS Alerts"))
        right_layout.addWidget(self.idsAlertDisplay)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)

        main_layout.addWidget(splitter)

        # Control buttons
        control_layout = QHBoxLayout()
        self.startButton = QPushButton("Start Capture")
        self.startButton.clicked.connect(self.start_capture)
        control_layout.addWidget(self.startButton)

        self.stopButton = QPushButton("Stop Capture")
        self.stopButton.clicked.connect(self.stop_capture)
        self.stopButton.setEnabled(False)  # Disable initially
        control_layout.addWidget(self.stopButton)

        main_layout.addLayout(control_layout)

        # Packet capture thread
        self.capture_thread = PacketCaptureThread(self.ids_system)
        self.capture_thread.packet_captured.connect(self.update_packet_list)
        self.capture_thread.alert_signal.connect(self.add_ids_alert)

        # Storage for captured packets
        self.packets = []

    def start_capture(self):
        self.capture_thread.start()
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def stop_capture(self):
        self.capture_thread.stop()
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def update_packet_list(self, packet):
        row = self.packetListDisplay.rowCount()
        self.packetListDisplay.insertRow(row)

        # Extract packet data
        time = packet.time
        src = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst = packet[IP].dst if packet.haslayer(IP) else "N/A"
        protocol = packet.sprintf("%IP.proto%") if packet.haslayer(IP) else packet.__class__.__name__

        # Populate the table
        self.packetListDisplay.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.packetListDisplay.setItem(row, 1, QTableWidgetItem(str(time)))
        self.packetListDisplay.setItem(row, 2, QTableWidgetItem(src))
        self.packetListDisplay.setItem(row, 3, QTableWidgetItem(dst))
        self.packetListDisplay.setItem(row, 4, QTableWidgetItem(protocol))

        self.packets.append(packet)

    def display_selected_packet_details(self):
        current_row = self.packetListDisplay.currentRow()
        if current_row >= 0:
            packet = self.packets[current_row]
            details = packet.show(dump=True)  # Show packet details
            self.packetDetailDisplay.setText(details)
            self.packetBytesDisplay.setText(bytes(packet).hex())

    def add_ids_alert(self, alert_message):
        self.idsAlertDisplay.append(f"<span style='color:red;'>{alert_message}</span>")


if __name__ == "__main__":
    app = QApplication([])
    window = AuroraScan()
    window.show()
    app.exec()
