import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QTableWidget, QTableWidgetItem, 
                             QTextEdit, QWidget, QSplitter, QPushButton, QDialog, 
                             QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from scapy.all import Ether, IP, TCP, UDP

# Import the packet capturing function and IDS system
from capture_packets import capture_packets
from ids import IntrusionDetectionSystem


from PyQt5.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, 
    QMessageBox, QSpacerItem, QSizePolicy, QGraphicsDropShadowEffect, QWidget
)
from PyQt5.QtGui import QPixmap, QFont, QColor
from PyQt5.QtCore import Qt, QPropertyAnimation, QRect

class LoginDialog(QDialog):
    """A sleek, modern login dialog for AuroraScan."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login - AuroraScan")
        self.setFixedSize(700, 500)  # Centered, large window size
        self.setStyleSheet("background-color: #1e1e1e; color: white; border-radius: 15px;")

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(50, 50, 50, 50)  # Better padding around edges
        main_layout.setSpacing(30)  # Space between elements

        # Tool Logo and Name
        header_layout = QHBoxLayout()
        header_layout.setAlignment(Qt.AlignCenter)

        # Logo (replace with your logo path)
        logo_label = QLabel()
        pixmap = QPixmap("logo.png").scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)

        # Animated tool name
        self.title_label = QLabel("AuroraScan")
        self.title_label.setFont(QFont("Arial", 36, QFont.Bold))
        self.title_label.setStyleSheet("color: #4CAF50;")
        self.title_label.setAlignment(Qt.AlignCenter)

        # Create a drop shadow effect for the tool name
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 255, 0, 120))  # Green glow
        shadow.setOffset(0, 0)
        self.title_label.setGraphicsEffect(shadow)

        header_layout.addWidget(logo_label)
        header_layout.addWidget(self.title_label)

        # User Input Fields (Centered)
        input_layout = QVBoxLayout()
        input_layout.setAlignment(Qt.AlignCenter)

        self.username_input = self._create_input_field("Enter your username")
        self.password_input = self._create_input_field("Enter your password", password=True)

        input_layout.addWidget(QLabel("Username:"))
        input_layout.addWidget(self.username_input)
        input_layout.addWidget(QLabel("Password:"))
        input_layout.addWidget(self.password_input)

        # Login Button (Animated)
        self.login_button = QPushButton("Login")
        self.login_button.setFont(QFont("Arial", 18, QFont.Bold))
        self.login_button.setStyleSheet(
            """
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 10px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #66BB6A;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
            """
        )
        self.login_button.clicked.connect(self.authenticate)
        self._animate_button(self.login_button)  # Add animation

        # Add everything to the main layout
        main_layout.addLayout(header_layout)
        main_layout.addLayout(input_layout)
        main_layout.addWidget(self.login_button, alignment=Qt.AlignCenter)

    def _create_input_field(self, placeholder, password=False):
        """Helper method to create styled input fields."""
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder)
        input_field.setFont(QFont("Arial", 16))
        input_field.setStyleSheet(
            """
            QLineEdit {
                background-color: #2e2e2e;
                color: white;
                border: 1px solid #4CAF50;
                border-radius: 8px;
                padding: 10px;
            }
            QLineEdit:focus {
                border: 2px solid #66BB6A;
            }
            """
        )
        if password:
            input_field.setEchoMode(QLineEdit.Password)
        return input_field

    def _animate_button(self, button):
        """Create a subtle animation for the login button."""
        animation = QPropertyAnimation(button, b"geometry")
        animation.setDuration(300)
        animation.setStartValue(QRect(200, 380, 300, 50))
        animation.setEndValue(QRect(180, 380, 340, 55))
        animation.setLoopCount(-1)  # Infinite loop for a pulsating effect
        animation.start()

    def authenticate(self):
        """Check credentials and proceed to AuroraScan if valid."""
        username = self.username_input.text()
        password = self.password_input.text()

        # Replace with real authentication logic
        if username == "admin" and password == "password":
            QMessageBox.information(self, "Success", "Welcome to AuroraScan!")
            self.accept()  # Close dialog and proceed
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password!")
class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)
    alert_signal = pyqtSignal(str)

    def __init__(self, ids_system):
        super().__init__()
        self.ids_system = ids_system

    def run(self):
        capture_packets(self.process_packet)

    def process_packet(self, packet):
        self.packet_captured.emit(packet)
        alert = self.ids_system.generate_alerts(packet)
        if alert:
            self.alert_signal.emit(alert)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AuroraScan")
        self.setGeometry(100, 100, 1200, 800)

        self.ids_system = IntrusionDetectionSystem()

        main_layout = QVBoxLayout()
        splitter = QSplitter(Qt.Vertical)

        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter filter expression (e.g., 'tcp', 'ip src 192.168.1.1')")
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_input)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        filter_layout.addWidget(self.start_button)
        filter_layout.addWidget(self.stop_button)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol"])
        self.packet_table.cellClicked.connect(self.display_packet_details)

        self.packet_details = QTextEdit()
        self.packet_details.setFont(QFont("Courier", 10))
        self.packet_details.setReadOnly(True)

        self.packet_bytes = QTextEdit()
        self.packet_bytes.setFont(QFont("Courier", 10))
        self.packet_bytes.setReadOnly(True)

        self.info_text = QLabel("Info: ")

        self.alerts_text = QTextEdit()
        self.alerts_text.setFont(QFont("Courier", 10))
        self.alerts_text.setReadOnly(True)
        self.alerts_text.setPlaceholderText("IDS Alerts will be displayed here...")

        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.addWidget(self.packet_details)
        bottom_splitter.addWidget(self.packet_bytes)

        splitter.addWidget(self.packet_table)
        splitter.addWidget(bottom_splitter)
        splitter.addWidget(self.alerts_text)

        main_layout.addLayout(filter_layout)
        main_layout.addWidget(splitter)
        main_layout.addWidget(self.info_text)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.packet_capture_thread = PacketCaptureThread(self.ids_system)
        self.packet_capture_thread.packet_captured.connect(self.display_packet_summary)
        self.packet_capture_thread.alert_signal.connect(self.add_alert_to_display)

    def start_capture(self):
        self.packet_capture_thread.start()

    def stop_capture(self):
        self.packet_capture_thread.terminate()

    def display_packet_summary(self, packet):
        """
        Display packet summary in the table and generate IDS alerts if needed.
        :param packet: Scapy packet object
        """
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)

        # Safely check and display source and destination IP addresses
        try:
            src = packet[IP].src if packet.haslayer(IP) else 'N/A'
            dst = packet[IP].dst if packet.haslayer(IP) else 'N/A'
        except AttributeError:
            src = 'N/A'
            dst = 'N/A'

        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(str(packet.time)))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(src))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(dst))

        # Get the protocol name if available
        protocol = packet.sprintf("%IP.proto%") if packet.haslayer(IP) else packet.__class__.__name__
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(protocol))

        # Store the packet object for later retrieval when clicked
        self.packet_table.item(row_position, 0).setData(Qt.UserRole, packet)

        # Check for IDS alerts (example condition)
        self.check_ids_alerts(packet)

    def check_ids_alerts(self, packet):
        """
        Check if the captured packet matches any IDS rules.
        :param packet: Scapy packet object
        """
        # Example rule: Alert on any TCP packet from a specific IP (e.g., 192.168.1.100)
        if packet.haslayer(TCP) and packet[IP].src == "192.168.1.100":
            alert_message = f"ALERT: Suspicious TCP packet detected from {packet[IP].src}!"
            self.alerts_text.append(alert_message)

    def display_packet_details(self, row, column):
        """
        Display detailed packet information in the packet details and bytes pane.
        :param row: Selected row in the packet table
        :param column: Selected column in the packet table
        """
        packet = self.packet_table.item(row, 0).data(Qt.UserRole)

        # Clear the previous details and bytes
        self.packet_details.clear()
        self.packet_bytes.clear()

        # Show packet layers in the details pane
        layer_details = f"<b><font color='blue'>Frame:</font> {packet.time} <br> Length: {len(packet)} bytes</b><br><br>"

        if packet.haslayer(Ether):
            ethernet = packet.getlayer(Ether)
            layer_details += f"<b><font color='green'>Ethernet Layer:</font></b><br>"
            layer_details += f"Source MAC: {ethernet.src}<br>"
            layer_details += f"Destination MAC: {ethernet.dst}<br>"
            layer_details += f"Type: {ethernet.type} (0x0800)<br><br>"

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            layer_details += f"<b><font color='purple'>IP Layer:</font></b><br>"
            layer_details += f"Source IP: {ip_layer.src}<br>"
            layer_details += f"Destination IP: {ip_layer.dst}<br>"
            layer_details += f"Version: {ip_layer.version}<br>"
            layer_details += f"Header Length: {ip_layer.ihl * 4} bytes<br>"
            layer_details += f"Time to live: {ip_layer.ttl}<br>"
            layer_details += f"Protocol: {ip_layer.proto}<br>"
            layer_details += f"Total Length: {ip_layer.len}<br>"
            layer_details += f"Identification: 0x{ip_layer.id:04x}<br><br>"

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            layer_details += f"<b><font color='red'>TCP Layer:</font></b><br>"
            layer_details += f"Source Port: {tcp_layer.sport}<br>"
            layer_details += f"Destination Port: {tcp_layer.dport}<br>"
            layer_details += f"Sequence Number: {tcp_layer.seq}<br>"
            layer_details += f"Acknowledgment Number: {tcp_layer.ack}<br>"
            layer_details += f"Flags: {tcp_layer.flags}<br>"
            layer_details += f"Window Size: {tcp_layer.window}<br>"
            layer_details += f"Checksum: 0x{tcp_layer.chksum:04x} [Validation: {'Good' if tcp_layer.chksum == 0 else 'Bad'}]<br>"
            layer_details += f"<b>[Expert Analysis]: This is an ACK for a zero-window probe</b><br><br>"

        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            layer_details += f"<b><font color='brown'>UDP Layer:</font></b><br>"
            layer_details += f"Source Port: {udp_layer.sport}<br>"
            layer_details += f"Destination Port: {udp_layer.dport}<br>"
            layer_details += f"Length: {udp_layer.len}<br>"
            layer_details += f"Checksum: {udp_layer.chksum}<br><br>"

        # Add the layer details to the text widget
        self.packet_details.append(layer_details)

        # Display raw bytes
        raw_bytes = bytes(packet).hex().upper()
        byte_display = " ".join([raw_bytes[i:i + 2] for i in range(0, len(raw_bytes), 2)])
        self.packet_bytes.setText(byte_display)

    def add_alert_to_display(self, alert_message):
        """
        Display IDS alert messages in the alert pane.
        :param alert_message: IDS alert text
        """
        self.alerts_text.append(alert_message)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Show the login dialog before opening the main window
    login_dialog = LoginDialog()
    if login_dialog.exec_() == QDialog.Accepted:
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())  