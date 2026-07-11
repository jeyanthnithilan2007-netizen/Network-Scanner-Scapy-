import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import json
import os
from datetime import datetime
import socket
import ipaddress
import subprocess
import sys
import platform

# Try to import Scapy, with fallback for installation
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, UDP, sr, sniff, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not installed. Please install it using: pip install scapy")

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Professional Network Scanner")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)
        
        # Set minimum size
        self.root.minsize(900, 650)
        
        # Colors and Styles
        self.bg_color = "#f0f4f8"
        self.primary_color = "#1a237e"
        self.secondary_color = "#0d47a1"
        self.accent_color = "#ff6f00"
        self.success_color = "#2e7d32"
        self.danger_color = "#c62828"
        self.info_color = "#00695c"
        self.warning_color = "#e65100"
        
        # Initialize variables
        self.scanning = False
        self.scan_results = []
        self.device_history = []
        self.history_file = "network_scan_history.json"
        self.load_history()
        
        # Configure root window
        self.root.configure(bg=self.bg_color)
        
        # Check Scapy availability
        if not SCAPY_AVAILABLE:
            self.show_scapy_installation_guide()
        
        # Setup UI
        self.setup_ui()
        
        # Get local IP and network
        self.update_network_info()
        
    def show_scapy_installation_guide(self):
        """Show guide for installing Scapy"""
        messagebox.showwarning(
            "Scapy Not Found",
            "Scapy is not installed on your system.\n\n"
            "To install Scapy, run one of these commands:\n"
            "• pip install scapy\n"
            "• pip install scapy-python3\n\n"
            "Note: On Linux, you may need to install libpcap-dev:\n"
            "• sudo apt-get install python3-pip libpcap-dev\n"
            "• sudo dnf install python3-pip libpcap-devel\n\n"
            "The tool will still work but network scanning features will be limited."
        )
    
    def update_network_info(self):
        """Get local network information"""
        try:
            # Get host IP
            hostname = socket.gethostname()
            self.local_ip = socket.gethostbyname(hostname)
            
            # Get network range (assuming /24 subnet)
            ip_parts = self.local_ip.split('.')
            self.network_base = '.'.join(ip_parts[:3])
            self.network_range = f"{self.network_base}.0/24"
            
            # Update status bar
            self.status_label.config(text=f"Ready | Local IP: {self.local_ip} | Network: {self.network_range}")
            
            # Update network info in UI
            self.ip_label.config(text=f"Your IP: {self.local_ip}")
            self.network_label.config(text=f"Network: {self.network_range}")
            
            # Set default scan target
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, self.network_range)
            
        except Exception as e:
            self.status_label.config(text=f"Error getting network info: {str(e)}")
    
    def setup_ui(self):
        """Setup the main UI"""
        # Header
        header_frame = tk.Frame(self.root, bg=self.primary_color, height=70)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🌐 Network Scanner Pro", 
                               font=("Segoe UI", 22, "bold"), 
                               fg="white", bg=self.primary_color)
        title_label.pack(side="left", padx=20, pady=15)
        
        # Info labels in header
        info_frame = tk.Frame(header_frame, bg=self.primary_color)
        info_frame.pack(side="right", padx=20)
        
        self.ip_label = tk.Label(info_frame, text="IP: Loading...", 
                                font=("Segoe UI", 9), fg="#90caf9", bg=self.primary_color)
        self.ip_label.pack(anchor="e")
        
        self.network_label = tk.Label(info_frame, text="Network: Loading...", 
                                     font=("Segoe UI", 9), fg="#90caf9", bg=self.primary_color)
        self.network_label.pack(anchor="e")
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left Panel - Controls
        left_panel = tk.Frame(main_container, bg=self.bg_color)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        # Scan Configuration
        config_frame = tk.LabelFrame(left_panel, text="Scan Configuration", 
                                     font=("Segoe UI", 11, "bold"),
                                     bg=self.bg_color, fg=self.primary_color,
                                     padx=10, pady=10)
        config_frame.pack(fill="x", pady=(0, 10))
        
        # Target
        tk.Label(config_frame, text="Target IP/Network:", 
                font=("Segoe UI", 10), bg=self.bg_color).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.target_entry = tk.Entry(config_frame, font=("Segoe UI", 10), 
                                    bg="white", width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.target_entry.insert(0, "192.168.1.0/24")
        
        # Scan Type
        tk.Label(config_frame, text="Scan Type:", 
                font=("Segoe UI", 10), bg=self.bg_color).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.scan_type_var = tk.StringVar(value="Network Scan")
        scan_types = ["Network Scan (ARP)", "Port Scan", "Ping Sweep", "ARP Scan", "OS Detection"]
        scan_menu = ttk.Combobox(config_frame, textvariable=self.scan_type_var,
                                values=scan_types, state="readonly", width=27)
        scan_menu.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        scan_menu.bind("<<ComboboxSelected>>", self.on_scan_type_change)
        
        # Port Range (for port scan)
        self.port_frame = tk.Frame(config_frame, bg=self.bg_color)
        self.port_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        
        tk.Label(self.port_frame, text="Port Range:", 
                font=("Segoe UI", 10), bg=self.bg_color).pack(side="left", padx=(0, 5))
        
        self.port_range_entry = tk.Entry(self.port_frame, font=("Segoe UI", 10), 
                                        bg="white", width=15)
        self.port_range_entry.pack(side="left")
        self.port_range_entry.insert(0, "1-1000")
        
        tk.Label(self.port_frame, text="(e.g., 22,80,443 or 1-1000)", 
                font=("Segoe UI", 8), bg=self.bg_color, fg="gray").pack(side="left", padx=5)
        
        config_frame.columnconfigure(1, weight=1)
        
        # Scan Buttons
        button_frame = tk.Frame(left_panel, bg=self.bg_color)
        button_frame.pack(fill="x", pady=(0, 10))
        
        self.scan_btn = tk.Button(button_frame, text="🔍 Start Scan", 
                                  font=("Segoe UI", 12, "bold"),
                                  bg=self.success_color, fg="white",
                                  relief="flat", cursor="hand2",
                                  padx=20, pady=10,
                                  command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹ Stop Scan", 
                                  font=("Segoe UI", 12, "bold"),
                                  bg=self.danger_color, fg="white",
                                  relief="flat", cursor="hand2",
                                  padx=20, pady=10,
                                  command=self.stop_scan,
                                  state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        tk.Button(button_frame, text="🗑 Clear Results", 
                 font=("Segoe UI", 10), bg="#e0e0e0", fg=self.primary_color,
                 relief="flat", cursor="hand2", padx=15, pady=10,
                 command=self.clear_results).pack(side="left", padx=5)
        
        # Scan Options
        options_frame = tk.LabelFrame(left_panel, text="Scan Options", 
                                     font=("Segoe UI", 11, "bold"),
                                     bg=self.bg_color, fg=self.primary_color,
                                     padx=10, pady=10)
        options_frame.pack(fill="x", pady=(0, 10))
        
        self.timeout_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Enable Timeout", 
                      variable=self.timeout_var, bg=self.bg_color,
                      font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w")
        
        self.verbose_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Verbose Output", 
                      variable=self.verbose_var, bg=self.bg_color,
                      font=("Segoe UI", 9)).grid(row=0, column=1, sticky="w")
        
        self.detailed_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Detailed Info", 
                      variable=self.detailed_var, bg=self.bg_color,
                      font=("Segoe UI", 9)).grid(row=0, column=2, sticky="w")
        
        # Statistics
        stats_frame = tk.LabelFrame(left_panel, text="Scan Statistics", 
                                   font=("Segoe UI", 11, "bold"),
                                   bg=self.bg_color, fg=self.primary_color,
                                   padx=10, pady=10)
        stats_frame.pack(fill="x", pady=(0, 10))
        
        stats_grid = tk.Frame(stats_frame, bg=self.bg_color)
        stats_grid.pack(fill="x")
        
        self.devices_found_label = tk.Label(stats_grid, text="Devices Found: 0", 
                                           font=("Segoe UI", 10), bg=self.bg_color)
        self.devices_found_label.grid(row=0, column=0, padx=10, sticky="w")
        
        self.ports_found_label = tk.Label(stats_grid, text="Open Ports: 0", 
                                         font=("Segoe UI", 10), bg=self.bg_color)
        self.ports_found_label.grid(row=0, column=1, padx=10, sticky="w")
        
        self.scan_time_label = tk.Label(stats_grid, text="Scan Time: 0s", 
                                       font=("Segoe UI", 10), bg=self.bg_color)
        self.scan_time_label.grid(row=0, column=2, padx=10, sticky="w")
        
        # Right Panel - Results
        right_panel = tk.Frame(main_container, bg=self.bg_color)
        right_panel.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        # Results Notebook (Tabs)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Scan Results Tab
        results_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(results_tab, text="Scan Results")
        
        # Treeview for results
        self.tree_frame = tk.Frame(results_tab, bg=self.bg_color)
        self.tree_frame.pack(fill="both", expand=True)
        
        columns = ("IP", "MAC", "Hostname", "Status", "OS", "Ports")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", height=15)
        
        # Set column headings
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("Status", text="Status")
        self.tree.heading("OS", text="OS")
        self.tree.heading("Ports", text="Open Ports")
        
        # Set column widths
        self.tree.column("IP", width=120)
        self.tree.column("MAC", width=140)
        self.tree.column("Hostname", width=150)
        self.tree.column("Status", width=80)
        self.tree.column("OS", width=120)
        self.tree.column("Ports", width=200)
        
        # Scrollbars
        vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        
        # Detailed Output Tab
        output_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(output_tab, text="Detailed Output")
        
        self.output_text = scrolledtext.ScrolledText(output_tab, 
                                                    font=("Consolas", 10),
                                                    bg="white", fg=self.primary_color,
                                                    height=20)
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Packet Capture Tab
        capture_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(capture_tab, text="Packet Capture")
        
        capture_frame = tk.Frame(capture_tab, bg=self.bg_color)
        capture_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Label(capture_frame, text="Interface:", 
                font=("Segoe UI", 10), bg=self.bg_color).pack(side="left", padx=5)
        
        self.interface_var = tk.StringVar(value="any")
        interface_entry = tk.Entry(capture_frame, textvariable=self.interface_var,
                                  font=("Segoe UI", 10), width=15)
        interface_entry.pack(side="left", padx=5)
        
        tk.Label(capture_frame, text="Packet Count:", 
                font=("Segoe UI", 10), bg=self.bg_color).pack(side="left", padx=5)
        
        self.packet_count_var = tk.StringVar(value="10")
        packet_entry = tk.Entry(capture_frame, textvariable=self.packet_count_var,
                               font=("Segoe UI", 10), width=10)
        packet_entry.pack(side="left", padx=5)
        
        tk.Button(capture_frame, text="▶ Start Capture", 
                 font=("Segoe UI", 10), bg=self.secondary_color, fg="white",
                 relief="flat", cursor="hand2",
                 command=self.start_packet_capture).pack(side="left", padx=5)
        
        self.packet_output = scrolledtext.ScrolledText(capture_tab, 
                                                      font=("Consolas", 9),
                                                      bg="white", fg=self.primary_color,
                                                      height=15)
        self.packet_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # History Tab
        history_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(history_tab, text="History")
        
        self.history_listbox = tk.Listbox(history_tab, font=("Segoe UI", 10),
                                         bg="white", fg=self.primary_color,
                                         height=20)
        self.history_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        # History Buttons
        hist_btn_frame = tk.Frame(history_tab, bg=self.bg_color)
        hist_btn_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Button(hist_btn_frame, text="Clear History", 
                 font=("Segoe UI", 10), bg=self.danger_color, fg="white",
                 relief="flat", cursor="hand2",
                 command=self.clear_history).pack(side="left", padx=5)
        
        tk.Button(hist_btn_frame, text="Export History", 
                 font=("Segoe UI", 10), bg=self.success_color, fg="white",
                 relief="flat", cursor="hand2",
                 command=self.export_history).pack(side="left", padx=5)
        
        # Status Bar
        status_frame = tk.Frame(self.root, bg=self.primary_color, height=30)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                     font=("Segoe UI", 9), 
                                     fg="white", bg=self.primary_color,
                                     anchor="w")
        self.status_label.pack(side="left", padx=10)
        
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate', 
                                           length=150)
        self.progress_bar.pack(side="right", padx=10)
    
    def on_scan_type_change(self, event=None):
        """Show/hide port range based on scan type"""
        scan_type = self.scan_type_var.get()
        if scan_type == "Port Scan":
            self.port_frame.grid()
        else:
            self.port_frame.grid_remove()
    
    def start_scan(self):
        """Start the scanning process"""
        if self.scanning:
            return
        
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or network.")
            return
        
        # Validate target
        try:
            ipaddress.ip_network(target, strict=False)
        except:
            try:
                socket.gethostbyname(target)
            except:
                messagebox.showerror("Error", "Invalid target format.")
                return
        
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress_bar.start()
        self.status_label.config(text=f"Scanning {target}...")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def perform_scan(self, target):
        """Perform the actual scan based on type"""
        scan_type = self.scan_type_var.get()
        start_time = datetime.now()
        
        try:
            if scan_type == "Network Scan (ARP)":
                self.network_scan(target)
            elif scan_type == "Port Scan":
                port_range = self.port_range_entry.get().strip()
                self.port_scan(target, port_range)
            elif scan_type == "Ping Sweep":
                self.ping_sweep(target)
            elif scan_type == "ARP Scan":
                self.arp_scan(target)
            elif scan_type == "OS Detection":
                self.os_detection(target)
            
        except Exception as e:
            self.update_output(f"Error during scan: {str(e)}")
        
        finally:
            elapsed = (datetime.now() - start_time).total_seconds()
            self.scan_time_label.config(text=f"Scan Time: {elapsed:.2f}s")
            self.stop_scan()
    
    def network_scan(self, target):
        """Perform network scan using ARP"""
        if not SCAPY_AVAILABLE:
            self.update_output("Scapy not available. Please install it.")
            return
        
        self.update_output(f"Starting Network Scan on {target}...")
        self.update_output("-" * 50)
        
        try:
            # ARP request
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=3, verbose=False)[0]
            
            devices_found = 0
            open_ports = 0
            
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                
                # Check if device is alive
                status = "Alive"
                
                # Add to treeview
                self.tree.insert("", "end", values=(ip, mac, hostname, status, "Unknown", "N/A"))
                devices_found += 1
                
                self.update_output(f"Found: {ip} ({hostname}) - MAC: {mac}")
                
                # Update statistics
                self.devices_found_label.config(text=f"Devices Found: {devices_found}")
            
            self.update_output(f"\nScan complete. Found {devices_found} devices.")
            
            # Add to history
            self.add_to_history(f"Network Scan: {target}", f"Found {devices_found} devices")
            
        except Exception as e:
            self.update_output(f"Error in network scan: {str(e)}")
    
    def port_scan(self, target, port_range):
        """Perform port scan on target"""
        if not SCAPY_AVAILABLE:
            self.update_output("Scapy not available. Please install it.")
            return
        
        self.update_output(f"Starting Port Scan on {target}...")
        self.update_output("-" * 50)
        
        try:
            # Parse port range
            ports = []
            if '-' in port_range:
                start, end = port_range.split('-')
                ports = list(range(int(start), int(end) + 1))
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
            
            # Limit ports for performance
            if len(ports) > 1000:
                messagebox.showwarning("Warning", "Too many ports. Limiting to 1000.")
                ports = ports[:1000]
            
            open_ports_found = []
            total_ports = len(ports)
            
            self.update_output(f"Scanning {total_ports} ports...")
            
            for i, port in enumerate(ports):
                if not self.scanning:
                    break
                
                # Update progress
                if i % 10 == 0:
                    progress = (i / total_ports) * 100
                    self.status_label.config(text=f"Scanning port {i+1}/{total_ports} ({progress:.1f}%)")
                
                # Create TCP SYN packet
                try:
                    ip = IP(dst=target)
                    tcp = TCP(dport=port, flags="S")
                    packet = ip / tcp
                    
                    # Send packet
                    response = sr1(packet, timeout=1, verbose=False)
                    
                    if response and response.haslayer(TCP):
                        if response[TCP].flags == 18:  # SYN-ACK
                            open_ports_found.append(port)
                            self.update_output(f"Port {port}: OPEN")
                        elif response[TCP].flags == 20:  # RST-ACK
                            pass  # Port closed
                except:
                    pass
            
            if open_ports_found:
                self.update_output(f"\nOpen ports found: {', '.join(map(str, open_ports_found))}")
                self.ports_found_label.config(text=f"Open Ports: {len(open_ports_found)}")
                
                # Update treeview
                self.tree.insert("", "end", values=(target, "N/A", "N/A", "Active", "Unknown", 
                                                   ', '.join(map(str, open_ports_found[:5]))))
            else:
                self.update_output("\nNo open ports found.")
            
            self.add_to_history(f"Port Scan: {target}", f"Found {len(open_ports_found)} open ports")
            
        except Exception as e:
            self.update_output(f"Error in port scan: {str(e)}")
    
    def ping_sweep(self, target):
        """Perform ping sweep using system ping"""
        self.update_output(f"Starting Ping Sweep on {target}...")
        self.update_output("-" * 50)
        
        try:
            # Parse network
            network = ipaddress.ip_network(target, strict=False)
            
            active_hosts = []
            
            for ip in network.hosts():
                if not self.scanning:
                    break
                
                ip_str = str(ip)
                
                # Use system ping
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', '-W', '1', ip_str]
                
                try:
                    result = subprocess.run(command, capture_output=True, timeout=2)
                    if result.returncode == 0:
                        active_hosts.append(ip_str)
                        self.update_output(f"Host {ip_str} is alive")
                        
                        # Add to treeview
                        try:
                            hostname = socket.gethostbyaddr(ip_str)[0]
                        except:
                            hostname = "Unknown"
                        
                        self.tree.insert("", "end", values=(ip_str, "N/A", hostname, "Alive", "Unknown", "N/A"))
                        self.devices_found_label.config(text=f"Devices Found: {len(active_hosts)}")
                except:
                    pass
            
            self.update_output(f"\nPing sweep complete. Found {len(active_hosts)} active hosts.")
            self.add_to_history(f"Ping Sweep: {target}", f"Found {len(active_hosts)} active hosts")
            
        except Exception as e:
            self.update_output(f"Error in ping sweep: {str(e)}")
    
    def arp_scan(self, target):
        """Perform ARP scan for MAC addresses"""
        if not SCAPY_AVAILABLE:
            self.update_output("Scapy not available. Please install it.")
            return
        
        self.update_output(f"Starting ARP Scan on {target}...")
        self.update_output("-" * 50)
        
        try:
            # ARP request
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=2, verbose=False)[0]
            
            devices = []
            for sent, received in result:
                devices.append((received.psrc, received.hwsrc))
                self.update_output(f"IP: {received.psrc} - MAC: {received.hwsrc}")
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except:
                    hostname = "Unknown"
                
                self.tree.insert("", "end", values=(received.psrc, received.hwsrc, hostname, "Active", "Unknown", "N/A"))
            
            self.devices_found_label.config(text=f"Devices Found: {len(devices)}")
            self.update_output(f"\nARP scan complete. Found {len(devices)} devices.")
            self.add_to_history(f"ARP Scan: {target}", f"Found {len(devices)} devices")
            
        except Exception as e:
            self.update_output(f"Error in ARP scan: {str(e)}")
    
    def os_detection(self, target):
        """Attempt OS detection using TTL fingerprinting"""
        if not SCAPY_AVAILABLE:
            self.update_output("Scapy not available. Please install it.")
            return
        
        self.update_output(f"Starting OS Detection on {target}...")
        self.update_output("-" * 50)
        
        try:
            # Send ICMP packet
            ip = IP(dst=target)
            icmp = ICMP()
            packet = ip / icmp
            
            response = sr1(packet, timeout=2, verbose=False)
            
            if response and response.haslayer(IP):
                ttl = response[IP].ttl
                
                # OS fingerprinting based on TTL
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl <= 255:
                    os_guess = "Router/Network Device"
                else:
                    os_guess = "Unknown"
                
                self.update_output(f"Target: {target}")
                self.update_output(f"TTL: {ttl}")
                self.update_output(f"Guessed OS: {os_guess}")
                
                # Update treeview
                self.tree.insert("", "end", values=(target, "N/A", "N/A", "Active", os_guess, "N/A"))
                
                self.add_to_history(f"OS Detection: {target}", f"OS: {os_guess}")
            else:
                self.update_output("No response from target.")
            
        except Exception as e:
            self.update_output(f"Error in OS detection: {str(e)}")
    
    def start_packet_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            self.update_output("Scapy not available. Please install it.")
            return
        
        interface = self.interface_var.get()
        count = int(self.packet_count_var.get())
        
        self.update_output(f"Starting packet capture on {interface}...")
        self.update_output("-" * 50)
        
        try:
            def packet_callback(packet):
                self.packet_output.insert(tk.END, f"{packet.summary()}\n")
                self.packet_output.see(tk.END)
            
            # Start capture in separate thread
            capture_thread = threading.Thread(
                target=lambda: sniff(iface=interface, count=count, prn=packet_callback)
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            self.update_output(f"Capturing {count} packets...")
            
        except Exception as e:
            self.update_output(f"Error in packet capture: {str(e)}")
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress_bar.stop()
        self.status_label.config(text="Scan stopped")
    
    def update_output(self, message):
        """Update output text"""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
    
    def clear_results(self):
        """Clear all scan results"""
        if messagebox.askyesno("Clear Results", "Are you sure you want to clear all results?"):
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.output_text.delete(1.0, tk.END)
            self.devices_found_label.config(text="Devices Found: 0")
            self.ports_found_label.config(text="Open Ports: 0")
            self.scan_time_label.config(text="Scan Time: 0s")
            self.scan_results = []
    
    def add_to_history(self, scan_type, details):
        """Add entry to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} - {scan_type}: {details}"
        self.history_listbox.insert(0, entry)
        
        # Keep only last 100 entries
        if self.history_listbox.size() > 100:
            self.history_listbox.delete(100, tk.END)
        
        self.save_history()
    
    def load_history(self):
        """Load history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.device_history = json.load(f)
        except:
            self.device_history = []
    
    def save_history(self):
        """Save history to file"""
        try:
            history_entries = [self.history_listbox.get(i) for i in range(self.history_listbox.size())]
            with open(self.history_file, 'w') as f:
                json.dump(history_entries, f)
        except:
            pass
    
    def clear_history(self):
        """Clear history"""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all history?"):
            self.history_listbox.delete(0, tk.END)
            self.save_history()
    
    def export_history(self):
        """Export history to file"""
        if self.history_listbox.size() == 0:
            messagebox.showinfo("No History", "No history to export.")
            return
        
        try:
            filename = f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("Network Scanner History\n")
                f.write("=" * 50 + "\n\n")
                entries = [self.history_listbox.get(i) for i in range(self.history_listbox.size())]
                for entry in reversed(entries):
                    f.write(entry + "\n")
            
            messagebox.showinfo("Export Successful", f"History exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export: {str(e)}")

def main():
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()