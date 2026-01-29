"""
iGSIM AI Agent Platform - Main GUI Window
PyQt6/PySide6 GUI Application
"""

import sys
import asyncio
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTextEdit, QPushButton, QLabel, QLineEdit, QComboBox,
        QTableWidget, QTableWidgetItem, QSplitter, QGroupBox, QProgressBar,
        QStatusBar, QMenuBar, QMessageBox, QScrollArea
    )
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize
    from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap
    QT_AVAILABLE = "PyQt6"
except ImportError:
    try:
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QTabWidget, QTextEdit, QPushButton, QLabel, QLineEdit, QComboBox,
            QTableWidget, QTableWidgetItem, QSplitter, QGroupBox, QProgressBar,
            QStatusBar, QMenuBar, QMessageBox, QScrollArea
        )
        from PySide6.QtCore import Qt, QTimer, QThread, Signal as pyqtSignal, QSize
        from PySide6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap
        QT_AVAILABLE = "PySide6"
    except ImportError:
        QT_AVAILABLE = None

if QT_AVAILABLE:
    # Add src to path for imports
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from services.ai_agent_service import AIAgentService
    from services.esim_service import eSIMService
    from config.settings import PLATFORM_CONFIG, UI_CONFIG
    from utils.logger import setup_logger

    logger = setup_logger(__name__)

    class ServiceWorker(QThread):
        """Background worker for AI and eSIM services"""
        
        status_updated = pyqtSignal(dict)
        response_received = pyqtSignal(dict)
        
        def __init__(self):
            super().__init__()
            self.ai_service = AIAgentService()
            self.esim_service = eSIMService()
            self.running = False
            
        def run(self):
            """Initialize services in background thread"""
            try:
                logger.info("Initializing services in background...")
                
                # Initialize AI service
                ai_success = self.ai_service.initialize()
                
                # Initialize eSIM service
                esim_success = self.esim_service.initialize()
                
                status = {
                    "ai_service": ai_success,
                    "esim_service": esim_success,
                    "overall": ai_success and esim_success
                }
                
                self.status_updated.emit(status)
                self.running = True
                
            except Exception as e:
                logger.error(f"Service initialization failed: {e}")
                self.status_updated.emit({"error": str(e)})

    class iGSIMMainWindow(QMainWindow):
        """Main application window for iGSIM AI Agent Platform"""
        
        def __init__(self):
            super().__init__()
            self.service_worker = None
            self.init_ui()
            self.init_services()
            
        def init_ui(self):
            """Initialize the user interface"""
            self.setWindowTitle(PLATFORM_CONFIG["name"])
            self.setGeometry(100, 100, 1200, 800)
            self.setMinimumSize(800, 600)
            
            # Set application icon (if available)
            self.set_app_icon()
            
            # Create central widget
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            
            # Create main layout
            main_layout = QVBoxLayout(central_widget)
            
            # Create header
            self.create_header(main_layout)
            
            # Create tab widget
            self.create_tabs(main_layout)
            
            # Create status bar
            self.create_status_bar()
            
            # Apply styling
            self.apply_styling()
            
        def set_app_icon(self):
            """Set application icon"""
            try:
                # Try to set icon if available
                icon_path = Path(__file__).parent.parent.parent / "assets" / "icon.png"
                if icon_path.exists():
                    self.setWindowIcon(QIcon(str(icon_path)))
            except Exception:
                pass  # Icon not critical
                
        def create_header(self, layout):
            """Create application header"""
            header_widget = QWidget()
            header_layout = QHBoxLayout(header_widget)
            
            # Platform title
            title_label = QLabel(PLATFORM_CONFIG["name"])
            title_font = QFont()
            title_font.setPointSize(16)
            title_font.setBold(True)
            title_label.setFont(title_font)
            
            # Version info
            version_label = QLabel(f"v{PLATFORM_CONFIG['version']}")
            version_label.setStyleSheet("color: #666; font-size: 12px;")
            
            # Status indicator
            self.status_indicator = QLabel("Initializing...")
            self.status_indicator.setStyleSheet("color: #ff6b35; font-weight: bold;")
            
            header_layout.addWidget(title_label)
            header_layout.addWidget(version_label)
            header_layout.addStretch()
            header_layout.addWidget(self.status_indicator)
            
            layout.addWidget(header_widget)
            
        def create_tabs(self, layout):
            """Create main tab widget"""
            self.tab_widget = QTabWidget()
            
            # AI Agent tab
            self.create_ai_tab()
            
            # eSIM Management tab
            self.create_esim_tab()
            
            # M2M Devices tab
            self.create_m2m_tab()
            
            # Analytics tab
            self.create_analytics_tab()
            
            # Settings tab
            self.create_settings_tab()
            
            layout.addWidget(self.tab_widget)
            
        def create_ai_tab(self):
            """Create AI Agent tab"""
            ai_widget = QWidget()
            layout = QVBoxLayout(ai_widget)
            
            # AI Service controls
            controls_group = QGroupBox("AI Agent Controls")
            controls_layout = QVBoxLayout(controls_group)
            
            # Provider selection
            provider_layout = QHBoxLayout()
            provider_layout.addWidget(QLabel("AI Provider:"))
            self.provider_combo = QComboBox()
            self.provider_combo.addItems(["Auto", "Gemini", "xai", "groq"])
            provider_layout.addWidget(self.provider_combo)
            provider_layout.addStretch()
            controls_layout.addLayout(provider_layout)
            
            # Input area
            self.ai_input = QTextEdit()
            self.ai_input.setPlaceholderText("Enter your AI request here...")
            self.ai_input.setMaximumHeight(100)
            controls_layout.addWidget(QLabel("Request:"))
            controls_layout.addWidget(self.ai_input)
            
            # Send button
            self.send_button = QPushButton("Send Request")
            self.send_button.clicked.connect(self.send_ai_request)
            controls_layout.addWidget(self.send_button)
            
            layout.addWidget(controls_group)
            
            # Response area
            response_group = QGroupBox("AI Response")
            response_layout = QVBoxLayout(response_group)
            
            self.ai_response = QTextEdit()
            self.ai_response.setReadOnly(True)
            response_layout.addWidget(self.ai_response)
            
            layout.addWidget(response_group)
            
            self.tab_widget.addTab(ai_widget, "AI Agent")
            
        def create_esim_tab(self):
            """Create eSIM Management tab"""
            esim_widget = QWidget()
            layout = QVBoxLayout(esim_widget)
            
            # eSIM provisioning controls
            provision_group = QGroupBox("eSIM Provisioning")
            provision_layout = QVBoxLayout(provision_group)
            
            # Device ID input
            device_layout = QHBoxLayout()
            device_layout.addWidget(QLabel("Device ID:"))
            self.device_id_input = QLineEdit()
            self.device_id_input.setPlaceholderText("Enter device ID")
            device_layout.addWidget(self.device_id_input)
            provision_layout.addLayout(device_layout)
            
            # Profile type selection
            profile_layout = QHBoxLayout()
            profile_layout.addWidget(QLabel("Profile Type:"))
            self.profile_combo = QComboBox()
            self.profile_combo.addItems(["Myanmar Local", "International"])
            profile_layout.addWidget(self.profile_combo)
            profile_layout.addStretch()
            provision_layout.addLayout(profile_layout)
            
            # Provision button
            self.provision_button = QPushButton("Provision eSIM")
            self.provision_button.clicked.connect(self.provision_esim)
            provision_layout.addWidget(self.provision_button)
            
            layout.addWidget(provision_group)
            
            # Active connections table
            connections_group = QGroupBox("Active eSIM Connections")
            connections_layout = QVBoxLayout(connections_group)
            
            self.connections_table = QTableWidget()
            self.connections_table.setColumnCount(5)
            self.connections_table.setHorizontalHeaderLabels([
                "Device ID", "Profile ID", "Status", "Operator", "Created"
            ])
            connections_layout.addWidget(self.connections_table)
            
            # Refresh button
            refresh_button = QPushButton("Refresh Connections")
            refresh_button.clicked.connect(self.refresh_connections)
            connections_layout.addWidget(refresh_button)
            
            layout.addWidget(connections_group)
            
            self.tab_widget.addTab(esim_widget, "eSIM Management")
            
        def create_m2m_tab(self):
            """Create M2M Devices tab"""
            m2m_widget = QWidget()
            layout = QVBoxLayout(m2m_widget)
            
            # M2M device controls
            controls_group = QGroupBox("M2M Device Management")
            controls_layout = QVBoxLayout(controls_group)
            
            # Device registration
            reg_layout = QHBoxLayout()
            reg_layout.addWidget(QLabel("Device ID:"))
            self.m2m_device_input = QLineEdit()
            reg_layout.addWidget(self.m2m_device_input)
            
            self.register_button = QPushButton("Register Device")
            self.register_button.clicked.connect(self.register_m2m_device)
            reg_layout.addWidget(self.register_button)
            
            controls_layout.addLayout(reg_layout)
            
            # Device actions
            actions_layout = QHBoxLayout()
            self.activate_button = QPushButton("Activate")
            self.activate_button.clicked.connect(lambda: self.m2m_action("activate"))
            actions_layout.addWidget(self.activate_button)
            
            self.deactivate_button = QPushButton("Deactivate")
            self.deactivate_button.clicked.connect(lambda: self.m2m_action("deactivate"))
            actions_layout.addWidget(self.deactivate_button)
            
            self.status_button = QPushButton("Get Status")
            self.status_button.clicked.connect(lambda: self.m2m_action("get_status"))
            actions_layout.addWidget(self.status_button)
            
            controls_layout.addLayout(actions_layout)
            
            layout.addWidget(controls_group)
            
            # M2M devices table
            devices_group = QGroupBox("Registered M2M Devices")
            devices_layout = QVBoxLayout(devices_group)
            
            self.m2m_table = QTableWidget()
            self.m2m_table.setColumnCount(4)
            self.m2m_table.setHorizontalHeaderLabels([
                "Device ID", "Type", "Status", "Last Updated"
            ])
            devices_layout.addWidget(self.m2m_table)
            
            layout.addWidget(devices_group)
            
            self.tab_widget.addTab(m2m_widget, "M2M Devices")
            
        def create_analytics_tab(self):
            """Create Analytics tab"""
            analytics_widget = QWidget()
            layout = QVBoxLayout(analytics_widget)
            
            # Analytics display
            self.analytics_display = QTextEdit()
            self.analytics_display.setReadOnly(True)
            layout.addWidget(self.analytics_display)
            
            # Refresh analytics button
            refresh_analytics_button = QPushButton("Refresh Analytics")
            refresh_analytics_button.clicked.connect(self.refresh_analytics)
            layout.addWidget(refresh_analytics_button)
            
            self.tab_widget.addTab(analytics_widget, "Analytics")
            
        def create_settings_tab(self):
            """Create Settings tab"""
            settings_widget = QWidget()
            layout = QVBoxLayout(settings_widget)
            
            # Service status
            status_group = QGroupBox("Service Status")
            status_layout = QVBoxLayout(status_group)
            
            self.service_status_display = QTextEdit()
            self.service_status_display.setReadOnly(True)
            self.service_status_display.setMaximumHeight(200)
            status_layout.addWidget(self.service_status_display)
            
            layout.addWidget(status_group)
            
            # Configuration
            config_group = QGroupBox("Configuration")
            config_layout = QVBoxLayout(config_group)
            
            config_text = f"""
Platform: {PLATFORM_CONFIG['name']}
Version: {PLATFORM_CONFIG['version']}
Firebase Project: {PLATFORM_CONFIG.get('firebase_project', 'bamboo-reason-483913-i4')}
UI Theme: {UI_CONFIG.get('theme', 'modern')}
            """.strip()
            
            config_display = QLabel(config_text)
            config_display.setWordWrap(True)
            config_layout.addWidget(config_display)
            
            layout.addWidget(config_group)
            layout.addStretch()
            
            self.tab_widget.addTab(settings_widget, "Settings")
            
        def create_status_bar(self):
            """Create status bar"""
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("Ready")
            
        def apply_styling(self):
            """Apply modern styling to the application"""
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #f5f5f5;
                }
                QTabWidget::pane {
                    border: 1px solid #c0c0c0;
                    background-color: white;
                }
                QTabBar::tab {
                    background-color: #e0e0e0;
                    padding: 8px 16px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: white;
                    border-bottom: 2px solid #3b82f6;
                }
                QGroupBox {
                    font-weight: bold;
                    border: 2px solid #cccccc;
                    border-radius: 5px;
                    margin-top: 1ex;
                    padding-top: 10px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px 0 5px;
                }
                QPushButton {
                    background-color: #3b82f6;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
                QPushButton:pressed {
                    background-color: #1d4ed8;
                }
                QLineEdit, QTextEdit, QComboBox {
                    border: 1px solid #d1d5db;
                    border-radius: 4px;
                    padding: 8px;
                    background-color: white;
                }
                QTableWidget {
                    gridline-color: #e5e7eb;
                    background-color: white;
                    alternate-background-color: #f9fafb;
                }
                QHeaderView::section {
                    background-color: #f3f4f6;
                    padding: 8px;
                    border: 1px solid #d1d5db;
                    font-weight: bold;
                }
            """)
            
        def init_services(self):
            """Initialize background services"""
            self.service_worker = ServiceWorker()
            self.service_worker.status_updated.connect(self.on_service_status_updated)
            self.service_worker.response_received.connect(self.on_response_received)
            self.service_worker.start()
            
        def on_service_status_updated(self, status):
            """Handle service status updates"""
            if "error" in status:
                self.status_indicator.setText("Error")
                self.status_indicator.setStyleSheet("color: #dc2626; font-weight: bold;")
                self.status_bar.showMessage(f"Error: {status['error']}")
            elif status.get("overall", False):
                self.status_indicator.setText("Ready")
                self.status_indicator.setStyleSheet("color: #16a34a; font-weight: bold;")
                self.status_bar.showMessage("All services initialized successfully")
            else:
                self.status_indicator.setText("Partial")
                self.status_indicator.setStyleSheet("color: #ea580c; font-weight: bold;")
                self.status_bar.showMessage("Some services failed to initialize")
                
            # Update service status display
            status_text = f"""
AI Service: {'✓' if status.get('ai_service', False) else '✗'}
eSIM Service: {'✓' if status.get('esim_service', False) else '✗'}
Overall Status: {'Ready' if status.get('overall', False) else 'Error'}
            """.strip()
            
            if hasattr(self, 'service_status_display'):
                self.service_status_display.setText(status_text)
                
        def on_response_received(self, response):
            """Handle AI response"""
            self.ai_response.append(f"\n--- Response ---\n{response}\n")
            
        def send_ai_request(self):
            """Send AI request"""
            if not self.service_worker or not self.service_worker.running:
                QMessageBox.warning(self, "Warning", "Services not initialized")
                return
                
            prompt = self.ai_input.toPlainText().strip()
            if not prompt:
                QMessageBox.warning(self, "Warning", "Please enter a request")
                return
                
            provider = self.provider_combo.currentText().lower()
            if provider == "auto":
                provider = "auto"
                
            self.ai_response.append(f"Sending request to {provider}...")
            self.send_button.setEnabled(False)
            
            # This would need to be implemented with proper async handling
            # For now, just show a placeholder response
            response = f"Response from {provider}: {prompt[:50]}..."
            self.ai_response.append(f"Response: {response}")
            self.send_button.setEnabled(True)
            
        def provision_esim(self):
            """Provision eSIM"""
            device_id = self.device_id_input.text().strip()
            if not device_id:
                QMessageBox.warning(self, "Warning", "Please enter device ID")
                return
                
            profile_type = self.profile_combo.currentText()
            
            # Simulate provisioning
            self.status_bar.showMessage(f"Provisioning eSIM for {device_id}...")
            
            # Add to connections table
            row = self.connections_table.rowCount()
            self.connections_table.insertRow(row)
            self.connections_table.setItem(row, 0, QTableWidgetItem(device_id))
            self.connections_table.setItem(row, 1, QTableWidgetItem(f"esim_{device_id}"))
            self.connections_table.setItem(row, 2, QTableWidgetItem("Provisioned"))
            self.connections_table.setItem(row, 3, QTableWidgetItem("eSIM Myanmar"))
            self.connections_table.setItem(row, 4, QTableWidgetItem("Just now"))
            
            self.device_id_input.clear()
            self.status_bar.showMessage("eSIM provisioned successfully")
            
        def refresh_connections(self):
            """Refresh eSIM connections"""
            self.status_bar.showMessage("Refreshing connections...")
            # Implementation would fetch real data
            
        def register_m2m_device(self):
            """Register M2M device"""
            device_id = self.m2m_device_input.text().strip()
            if not device_id:
                QMessageBox.warning(self, "Warning", "Please enter device ID")
                return
                
            # Add to M2M table
            row = self.m2m_table.rowCount()
            self.m2m_table.insertRow(row)
            self.m2m_table.setItem(row, 0, QTableWidgetItem(device_id))
            self.m2m_table.setItem(row, 1, QTableWidgetItem("Generic"))
            self.m2m_table.setItem(row, 2, QTableWidgetItem("Registered"))
            self.m2m_table.setItem(row, 3, QTableWidgetItem("Just now"))
            
            self.m2m_device_input.clear()
            self.status_bar.showMessage("M2M device registered successfully")
            
        def m2m_action(self, action):
            """Perform M2M device action"""
            self.status_bar.showMessage(f"Performing {action}...")
            
        def refresh_analytics(self):
            """Refresh analytics display"""
            analytics_text = f"""
=== iGSIM AI Agent Platform Analytics ===

eSIM Statistics:
- Total Profiles: {self.connections_table.rowCount()}
- Active Connections: {self.connections_table.rowCount()}

M2M Statistics:
- Total Devices: {self.m2m_table.rowCount()}
- Active Devices: {self.m2m_table.rowCount()}

AI Service Status:
- Gemini: Available
- xai: Available  
- groq: Available

Last Updated: Just now
            """
            
            self.analytics_display.setText(analytics_text)

    def main():
        """Main application entry point"""
        if not QT_AVAILABLE:
            print("Error: Neither PyQt6 nor PySide6 is installed")
            print("Please install one of them: pip install PyQt6 or pip install PySide6")
            return
            
        app = QApplication(sys.argv)
        app.setApplicationName(PLATFORM_CONFIG["name"])
        app.setApplicationVersion(PLATFORM_CONFIG["version"])
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create and show main window
        window = iGSIMMainWindow()
        window.show()
        
        # Start event loop
        sys.exit(app.exec())

    if __name__ == "__main__":
        main()

else:
    def main():
        print("Error: Neither PyQt6 nor PySide6 is installed")
        print("Please install one of them:")
        print("  pip install PyQt6")
        print("  or")
        print("  pip install PySide6")

    if __name__ == "__main__":
        main()