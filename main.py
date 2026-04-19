import os
import sys
import platform
import shutil
import glob

if platform.system() == 'Linux':
    uid = os.getuid()
    if 'WAYLAND_RUNTIME_DIR' not in os.environ:
        wlr_dir = f'/run/user/{uid}'
        if os.path.exists(wlr_dir):
            os.environ['WAYLAND_RUNTIME_DIR'] = wlr_dir
    if 'XDG_RUNTIME_DIR' not in os.environ:
        xdg_dir = f'/run/user/{uid}'
        if os.path.exists(xdg_dir):
            os.environ['XDG_RUNTIME_DIR'] = xdg_dir
    if 'WAYLAND_DISPLAY' not in os.environ and 'DISPLAY' not in os.environ:
        for name in ['wayland-0', 'wayland-1', 'wayland-2']:
            socket_path = f'/run/user/{uid}/{name}'
            if os.path.exists(socket_path):
                os.environ['WAYLAND_DISPLAY'] = name
                break
        if 'WAYLAND_DISPLAY' not in os.environ:
            x11_dir = '/tmp/.X11-unix'
            if os.path.exists(x11_dir):
                x11_sockets = sorted([f for f in os.listdir(x11_dir) if f.startswith('X')])
                if x11_sockets:
                    os.environ['DISPLAY'] = f':{x11_sockets[0][1:]}'
                    if 'XAUTHORITY' not in os.environ:
                        home = os.path.expanduser('~')
                        xauth_file = os.path.join(home, '.Xauthority')
                        if os.path.exists(xauth_file):
                            os.environ['XAUTHORITY'] = xauth_file

import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import threading
import time
import random
import queue
import netifaces
from scapy.all import *
import json
import ctypes
import subprocess

LANG = {
    'zh': {
        'title': 'DHCP扫描器',
        'system_info': '操作系统',
        'config': '配置',
        'scan_count': '扫描次数',
        'timeout': '超时时间(秒)',
        'available_interfaces': '可用网卡',
        'interface_name': '接口名称',
        'ip': 'IP地址',
        'mac': 'MAC地址',
        'status': '状态',
        'active': '活跃',
        'inactive': '未连接',
        'refresh': '刷新列表',
        'auto_select': '自动选择',
        'current_selection': '当前选择',
        'not_selected': '未选择',
        'save_settings': '保存设置',
        'start_scan': '开始扫描',
        'stop_scan': '停止扫描',
        'dhcp_server_count': '发现DHCP服务器数量',
        'state': '状态',
        'ready': '就绪',
        'scanning': '扫描中',
        'completed': '扫描完成',
        'stopping': '正在停止...',
        'usage': '使用说明',
        'usage_text': '选择网卡 → 设置扫描次数/超时 → 点击开始扫描。发现多个DHCP服务器可能存在网络隐患。',
        'select_interface': '请先选择一个网络接口',
        'no_interfaces': '未找到可用的网络接口',
        'auto_selected': '已自动选择网卡: %s',
        'settings_saved': '设置已保存到配置文件',
        'copy': '复制',
        'clear': '清空',
        'save_to_file': '保存到文件',
        'copied': '结果已复制到剪贴板',
        'saved': '结果已保存到: %s',
        'saved_success': '保存成功',
        'copy_failed': '复制失败',
        'save_failed': '保存失败',
        'nothing_to_save': '没有内容可保存',
        'warning': '警告',
        'cannot_clear': '扫描进行中，无法清空',
        'select_correct_interface': '请手动选择正确的网卡后重试',
        'cannot_find_interface': '错误: 无法找到可用的网卡接口',
        'netifaces_interface': 'netifaces接口: ',
        'scapy_interface': 'scapy接口: ',
        'cannot_get_mac': '无法获取接口MAC地址',
        'lang': '中文',
        'scanning_interface': '正在扫描接口: %s (MAC: %s)',
        'sending_dhcp': '开始发送DHCP Discover包...',
        'scan_round': '第 %d/%d 次扫描...',
        'found_dhcp': '发现DHCP服务器: %s',
        'scan_complete': '扫描完成! 共发现 %d 个DHCP服务器',
        'multiple_warning': '警告: 发现多个DHCP服务器!',
        'possible_causes': '可能原因:',
        'cause_1': '1. 正常的网络设备（路由器、交换机）',
        'cause_2': '2. 有人私自接入的小路由（非法DHCP服务器）',
        'cause_3': '3. 网络配置错误',
        'recommendations': '建议检查:',
        'rec_1': '- 确认所有DHCP服务器都是已知的合法设备',
        'rec_2': '- 联系网络管理员检查未授权的设备',
        'rec_3': '- 考虑启用网络访问控制(NAC)防止非法接入',
        'no_abnormal': '未发现异常DHCP服务器',
        'no_dhcp_found': '未检测到DHCP服务器，可能原因:',
        'no_dhcp_1': '- DHCP服务器未响应',
        'no_dhcp_2': '- 网络配置问题',
        'no_dhcp_3': '- 请尝试增加扫描次数或超时时间',
        'scan_error': '扫描出错: %s',
        'error_title': '错误',
        'macos_tip': '在macOS上，请确保:\n1. 使用sudo运行程序: sudo python3 main.py\n2. 已安装必要的网络库: pip install scapy netifaces\n3. 网络接口工作正常\n4. 防火墙未阻止网络扫描',
        'linux_tip': '在Linux上，请确保:\n1. 使用sudo运行程序: sudo python3 main.py\n2. 已安装必要的网络库: pip install scapy netifaces\n3. 网络接口工作正常\n4. iptables/ufw未阻止网络扫描',
        'windows_tip': '请确保:\n1. 以管理员权限运行程序\n2. 已安装必要的网络库(scapy)\n3. 网络接口工作正常',
    },
    'en': {
        'title': 'DHCP Scanner',
        'system_info': 'OS',
        'config': 'Config',
        'scan_count': 'Scan Count',
        'timeout': 'Timeout (sec)',
        'available_interfaces': 'Available Interfaces',
        'interface_name': 'Interface',
        'ip': 'IP Address',
        'mac': 'MAC Address',
        'status': 'Status',
        'active': 'Active',
        'inactive': 'Inactive',
        'refresh': 'Refresh',
        'auto_select': 'Auto Select',
        'current_selection': 'Selected',
        'not_selected': 'Not Selected',
        'save_settings': 'Save',
        'start_scan': 'Start Scan',
        'stop_scan': 'Stop Scan',
        'dhcp_server_count': 'DHCP Servers Found',
        'state': 'State',
        'ready': 'Ready',
        'scanning': 'Scanning',
        'completed': 'Completed',
        'stopping': 'Stopping...',
        'usage': 'Usage',
        'usage_text': 'Select interface → Set scan count/timeout → Click Start Scan. Multiple DHCP servers may indicate network issues.',
        'select_interface': 'Please select a network interface first',
        'no_interfaces': 'No available network interfaces found',
        'auto_selected': 'Auto selected interface: %s',
        'settings_saved': 'Settings saved to config file',
        'copy': 'Copy',
        'clear': 'Clear',
        'save_to_file': 'Save to File',
        'copied': 'Result copied to clipboard',
        'saved': 'Result saved to: %s',
        'saved_success': 'Saved',
        'copy_failed': 'Copy failed',
        'save_failed': 'Save failed',
        'nothing_to_save': 'Nothing to save',
        'warning': 'Warning',
        'cannot_clear': 'Cannot clear during scan',
        'select_correct_interface': 'Please select the correct interface manually',
        'cannot_find_interface': 'Error: Cannot find available interface',
        'netifaces_interface': 'netifaces: ',
        'scapy_interface': 'scapy: ',
        'cannot_get_mac': 'Cannot get interface MAC address',
        'lang': 'EN',
        'scanning_interface': 'Scanning interface: %s (MAC: %s)',
        'sending_dhcp': 'Sending DHCP Discover packets...',
        'scan_round': 'Scan %d/%d...',
        'found_dhcp': 'Found DHCP server: %s',
        'scan_complete': 'Scan complete! Found %d DHCP server(s)',
        'multiple_warning': 'Warning: Multiple DHCP servers detected!',
        'possible_causes': 'Possible causes:',
        'cause_1': '1. Normal network devices (router, switch)',
        'cause_2': '2. Unauthorized router (rogue DHCP server)',
        'cause_3': '3. Network configuration error',
        'recommendations': 'Recommendations:',
        'rec_1': '- Verify all DHCP servers are known devices',
        'rec_2': '- Contact network admin for unauthorized devices',
        'rec_3': '- Consider NAC to prevent unauthorized access',
        'no_abnormal': 'No abnormal DHCP servers found',
        'no_dhcp_found': 'No DHCP servers detected on this network, possible reasons:',
        'no_dhcp_1': '- DHCP server is not responding',
        'no_dhcp_2': '- Network configuration issue',
        'no_dhcp_3': '- Try increasing scan count or timeout',
        'scan_error': 'Scan error: %s',
        'error_title': 'Error',
        'macos_tip': 'On macOS, ensure:\n1. Run with sudo: sudo python3 main.py\n2. Install required libs: pip install scapy netifaces\n3. Network interface is working\n4. Firewall allows network scanning',
        'linux_tip': 'On Linux, ensure:\n1. Run with sudo: sudo python3 main.py\n2. Install required libs: pip install scapy netifaces\n3. Network interface is working\n4. iptables/ufw allows network scanning',
        'windows_tip': 'Ensure:\n1. Run as administrator\n2. Install required libs (scapy)\n3. Network interface is working',
    }
}

def get_windows_theme():
    if platform.system() != 'Windows':
        return None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return 'dark' if value == 0 else 'light'
    except:
        return 'light'

def request_admin():
    system = platform.system()
    python_exe = sys.executable
    if system == 'Windows':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                script = os.path.abspath(sys.argv[0])
                script_dir = os.path.dirname(script)
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, f'"{script}"', script_dir, 1)
                if ret <= 32:
                    return False
                sys.exit(0)
        except:
            return False
    elif system == 'Darwin':
        is_admin = os.geteuid() == 0
        if not is_admin:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            try:
                cmd = f'''tell application "Terminal"
                    activate
                    set newTab to do script ""
                    delay 0.3
                    do script "clear && echo '╔════════════════════════════════════════╗' && echo '║       DHCP服务器扫描器 - 权限提升      ║' && echo '╚════════════════════════════════════════╝' && echo '' && echo '>>> 正在请求管理员权限...' && echo '>>> 请在下方输入您的登录密码' && echo '>>> ' && sudo \\"{python_exe}\\" \\"{script}\\" {params}" in newTab
                end tell'''
                subprocess.run(['osascript', '-e', cmd], capture_output=True, text=True)
                sys.exit(0)
            except:
                return False
    elif system == 'Linux':
        is_admin = os.geteuid() == 0
        if not is_admin:
            script = os.path.abspath(sys.argv[0])
            env = os.environ.copy()
            if 'DISPLAY' in env:
                subprocess.run(['xhost', 'si:localuser:root'], capture_output=True)
            dbus_addr = env.get('DBUS_SESSION_BUS_ADDRESS')
            if not dbus_addr:
                uid = os.getuid()
                for pattern in [f'/run/user/{uid}/bus', f'/tmp/dbus-*/{uid}']:
                    matches = glob.glob(pattern)
                    if matches:
                        env['DBUS_SESSION_BUS_ADDRESS'] = f'unix:path={matches[0]}'
                        break
            pkexec_path = shutil.which('pkexec')
            if pkexec_path:
                os.execve(pkexec_path, ['pkexec', '--keep-cwd', python_exe, script] + sys.argv[1:], env)
            return False
    return True

def build_dhcp_packet(msg_type, mac, xid=None, ciaddr='0.0.0.0', yiaddr='0.0.0.0',
                      siaddr='0.0.0.0', giaddr='0.0.0.0', options_extra=None):
    """
    构建标准的 DHCP 包（原始字节流）
    msg_type: 1=Discover, 3=Request, 8=Inform
    """
    if xid is None:
        xid = random.randint(1, 0xFFFFFFFF)
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    # BOOTP header
    bootp = struct.pack('!BBBB', 1, 1, 6, 0)  # op, htype, hlen, hops
    bootp += struct.pack('!I', xid)           # xid
    bootp += struct.pack('!H', 0)             # secs
    bootp += struct.pack('!H', 0x8000 if msg_type == 1 else 0)  # flags (broadcast for Discover)
    bootp += socket.inet_aton(ciaddr)         # ciaddr
    bootp += socket.inet_aton(yiaddr)         # yiaddr
    bootp += socket.inet_aton(siaddr)         # siaddr
    bootp += socket.inet_aton(giaddr)         # giaddr
    bootp += mac_bytes + b'\x00' * (16 - len(mac_bytes))  # chaddr
    bootp += b'\x00' * 64                     # sname
    bootp += b'\x00' * 128                    # file
    bootp += b'\x63\x82\x53\x63'              # magic cookie
    # DHCP options
    options = b''
    options += bytes([53, 1, msg_type])       # DHCP message type
    options += bytes([61, 7, 1]) + mac_bytes  # Client identifier
    if options_extra:
        options += options_extra
    options += b'\xff'                        # End option
    # 总长度至少 312 字节
    packet = bootp + options
    if len(packet) < 312:
        packet += b'\x00' * (312 - len(packet))
    return packet

class DHCPScanner:
    def __init__(self, root):
        self.root = root
        self.root.attributes('-alpha', 0.95)
        self.is_dark_theme = get_windows_theme()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        if platform.system() == 'Windows':
            ico_path = os.path.join(script_dir, 'logo.ico')
            if os.path.exists(ico_path):
                self.root.iconbitmap(ico_path)
        else:
            try:
                png_path = os.path.join(script_dir, 'logo.png')
                from tkinter import PhotoImage
                icon = PhotoImage(file=png_path)
                self.root.iconphoto(True, icon)
            except:
                pass

        self.config_file = "dhcp_scanner_config.json"
        self.config = self.load_config()
        self.current_lang = self.config.get('language', 'zh')
        window_width = self.config.get('window_width', 700)
        window_height = self.config.get('window_height', 800)
        self.root.geometry(f"{window_width}x{window_height}")

        self.system = platform.system()
        self.is_mac = self.system == 'Darwin'
        self.is_linux = self.system == 'Linux'

        self.is_scanning = False
        self.scan_thread = None
        self.dhcp_servers = {}   # {ip: {'method': str, 'options': dict}}
        self.local_ips = set(['127.0.0.1', '0.0.0.0'])  # 本机IP集合，用于过滤
        self.sniff_thread = None  # 后台嗅探线程
        self.stop_event = None    # 嗅探线程停止事件

        self.create_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Configure>", self.on_window_resize)

    def t(self, key):
        return LANG[self.current_lang].get(key, key)

    def toggle_language(self):
        self.current_lang = self.lang_var.get()
        self.config['language'] = self.current_lang
        self.save_config()
        self.update_ui_text()
        self.load_interfaces()
        self.restore_last_interface()

    def update_ui_text(self):
        self.root.title(self.t('title'))
        if hasattr(self, 'lang_label'):
            self.lang_label.config(text="语言/language")
        system_info = f"{self.t('system_info')}: {self.system}"
        if self.is_mac:
            system_info += " (macOS)"
        elif self.is_linux:
            system_info += " (Linux)"
        self.system_label.config(text=system_info)
        self.config_label.config(text=f"{self.t('config')}: {self.t('scan_count')}={self.config['scan_count']}, {self.t('timeout')}={self.config['timeout']}")
        self.interfaces_label.config(text=self.t('available_interfaces') + ":")
        self.interface_tree.heading('interface', text=self.t('interface_name'))
        self.interface_tree.heading('ip', text=self.t('ip'))
        self.interface_tree.heading('mac', text=self.t('mac'))
        self.interface_tree.heading('status', text=self.t('status'))
        self.refresh_btn.config(text=self.t('refresh'))
        self.auto_select_btn.config(text=self.t('auto_select'))
        self.selection_label.config(text=self.t('current_selection') + ":")
        self.scan_count_label.config(text=self.t('scan_count') + ":")
        self.timeout_label.config(text=self.t('timeout') + ":")
        self.save_btn.config(text=self.t('save_settings'))
        self.scan_btn.config(text=self.t('start_scan'))
        self.stop_btn.config(text=self.t('stop_scan'))
        self.server_count_label.config(text=self.t('dhcp_server_count') + ":")
        self.state_label.config(text=self.t('state') + ":")
        self.usage_label.config(text=self.t('usage') + ": " + self.t('usage_text'))
        self.status_var.set(self.t('ready'))
        self.selected_interface_var.set(self.t('not_selected'))

    def load_config(self):
        default_config = {
            'scan_count': 3, 'timeout': 5, 'window_width': 700, 'window_height': 800,
            'last_interface': '', 'language': 'zh'
        }
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                for k, v in default_config.items():
                    if k not in config:
                        config[k] = v
                return config
        except:
            pass
        return default_config

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except:
            return False

    def on_window_resize(self, event):
        if event.widget == self.root:
            w, h = event.width, event.height
            if abs(w - self.config.get('window_width', 700)) > 20 or abs(h - self.config.get('window_height', 800)) > 20:
                self.config['window_width'] = w
                self.config['window_height'] = h
                if hasattr(self, 'save_timer'):
                    self.root.after_cancel(self.save_timer)
                self.save_timer = self.root.after(1000, self.save_config)

    def on_closing(self):
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()
        iface = self.get_selected_interface()
        if iface:
            self.config['last_interface'] = iface
        self.save_config()
        self.root.destroy()

    def create_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 语言选择
        lang_frame = ttk.LabelFrame(main_frame, padding="5")
        lang_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10))
        self.lang_var = tk.StringVar(value=self.current_lang)
        self.lang_label = ttk.Label(lang_frame, text="语言/language")
        self.lang_label.pack(side=tk.LEFT, padx=(5,10))
        ttk.Radiobutton(lang_frame, text="中文", variable=self.lang_var, value='zh', command=self.toggle_language).pack(side=tk.LEFT, padx=(0,5))
        ttk.Radiobutton(lang_frame, text="English", variable=self.lang_var, value='en', command=self.toggle_language).pack(side=tk.LEFT)

        # 系统信息
        system_frame = ttk.LabelFrame(main_frame, padding="10")
        system_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10))
        self.system_label = ttk.Label(system_frame)
        self.system_label.grid(row=0, column=0, sticky=tk.W)
        self.config_label = ttk.Label(system_frame, foreground="blue")
        self.config_label.grid(row=0, column=1, sticky=tk.E)

        # 网卡选择
        network_frame = ttk.LabelFrame(main_frame, padding="10")
        network_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10))
        self.interfaces_label = ttk.Label(network_frame)
        self.interfaces_label.grid(row=0, column=0, sticky=tk.W)
        columns = ('interface', 'ip', 'mac', 'status')
        self.interface_tree = ttk.Treeview(network_frame, columns=columns, show='headings', height=5)
        self.interface_tree.heading('interface', text=self.t('interface_name'))
        self.interface_tree.heading('ip', text=self.t('ip'))
        self.interface_tree.heading('mac', text=self.t('mac'))
        self.interface_tree.heading('status', text=self.t('status'))
        self.interface_tree.column('interface', width=120)
        self.interface_tree.column('ip', width=120)
        self.interface_tree.column('mac', width=120)
        self.interface_tree.column('status', width=80)
        self.interface_tree.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5,5))
        scrollbar = ttk.Scrollbar(network_frame, orient=tk.VERTICAL, command=self.interface_tree.yview)
        scrollbar.grid(row=1, column=2, sticky=(tk.N, tk.S))
        self.interface_tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(network_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(5,0))
        self.refresh_btn = ttk.Button(button_frame, command=self.load_interfaces)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0,5))
        self.auto_select_btn = ttk.Button(button_frame, command=self.auto_select_interface)
        self.auto_select_btn.pack(side=tk.LEFT, padx=(5,5))
        self.selected_interface_var = tk.StringVar(value=self.t('not_selected'))
        self.selection_label = ttk.Label(button_frame)
        self.selection_label.pack(side=tk.LEFT, padx=(10,0))
        ttk.Label(button_frame, textvariable=self.selected_interface_var, font=("Arial",10,"bold"), foreground="blue").pack(side=tk.LEFT, padx=(5,0))

        # 扫描控制
        control_frame = ttk.LabelFrame(main_frame, padding="10")
        control_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10))
        param_frame = ttk.Frame(control_frame)
        param_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,5))
        self.scan_count_label = ttk.Label(param_frame)
        self.scan_count_label.pack(side=tk.LEFT)
        self.scan_count_var = tk.IntVar(value=self.config['scan_count'])
        self.scan_count_spin = ttk.Spinbox(param_frame, from_=1, to=10, textvariable=self.scan_count_var, width=8)
        self.scan_count_spin.pack(side=tk.LEFT, padx=(5,20))
        self.timeout_label = ttk.Label(param_frame)
        self.timeout_label.pack(side=tk.LEFT)
        self.timeout_var = tk.IntVar(value=self.config['timeout'])
        self.timeout_spin = ttk.Spinbox(param_frame, from_=1, to=30, textvariable=self.timeout_var, width=8)
        self.timeout_spin.pack(side=tk.LEFT, padx=(5,20))

        action_frame = ttk.Frame(control_frame)
        action_frame.grid(row=1, column=0, columnspan=2, pady=(10,0))
        self.save_btn = ttk.Button(action_frame, command=self.save_current_settings)
        self.save_btn.pack(side=tk.LEFT, padx=(0,5))
        self.scan_btn = ttk.Button(action_frame, command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(5,5))
        self.stop_btn = ttk.Button(action_frame, command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        # 结果显示
        result_frame = ttk.LabelFrame(main_frame, padding="10")
        result_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0,10))
        stats_frame = ttk.Frame(result_frame)
        stats_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10))
        self.server_count_label = ttk.Label(stats_frame)
        self.server_count_label.grid(row=0, column=0, sticky=tk.W)
        self.server_count_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.server_count_var, font=("Arial",12,"bold"), foreground="red").grid(row=0, column=1, padx=(5,20))
        self.state_label = ttk.Label(stats_frame)
        self.state_label.grid(row=0, column=2, sticky=tk.W)
        self.status_var = tk.StringVar(value=self.t('ready'))
        ttk.Label(stats_frame, textvariable=self.status_var, font=("Arial",10)).grid(row=0, column=3, padx=(5,0))

        text_frame = ttk.Frame(result_frame)
        text_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.result_text = tk.Text(text_frame, height=20, width=90)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        self.result_text.config(state=tk.DISABLED)
        self.result_text.bind("<Button-3>", self.show_context_menu)

        self.usage_label = ttk.Label(main_frame, foreground="gray")
        self.usage_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=(5,0))

        # 权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(1, weight=1)

        self.update_ui_text()
        self.load_interfaces()
        self.restore_last_interface()

    def show_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=self.t('copy'), command=self.copy_result_text)
        menu.add_command(label=self.t('clear'), command=self.clear_result_text)
        menu.add_separator()
        menu.add_command(label=self.t('save_to_file'), command=self.save_result_to_file)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_result_text(self):
        try:
            text = self.result_text.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo(self.t('copy'), self.t('copied'))
        except:
            messagebox.showerror(self.t('error_title'), self.t('copy_failed'))

    def clear_result_text(self):
        if self.is_scanning:
            messagebox.showwarning(self.t('warning'), self.t('cannot_clear'))
            return
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.server_count_var.set("0")

    def save_result_to_file(self):
        try:
            text = self.result_text.get(1.0, tk.END)
            if not text.strip():
                messagebox.showinfo(self.t('saved_success'), self.t('nothing_to_save'))
                return
            filename = f"dhcp_scan_result_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)
            messagebox.showinfo(self.t('saved_success'), self.t('saved') % filename)
        except:
            messagebox.showerror(self.t('error_title'), self.t('save_failed'))

    def save_current_settings(self):
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()
        iface = self.get_selected_interface()
        if iface:
            self.config['last_interface'] = iface
        if self.save_config():
            messagebox.showinfo(self.t('saved_success'), self.t('settings_saved'))
            self.update_config_label()
        else:
            messagebox.showerror(self.t('error_title'), self.t('save_failed'))

    def update_config_label(self):
        self.config_label.config(text=f"{self.t('config')}: {self.t('scan_count')}={self.config['scan_count']}, {self.t('timeout')}={self.config['timeout']}")

    def restore_last_interface(self):
        last = self.config.get('last_interface', '')
        if last:
            for item in self.interface_tree.get_children():
                if self.interface_tree.item(item)['values'][0] == last:
                    self.interface_tree.selection_set(item)
                    self.interface_tree.see(item)
                    self.on_interface_select(None)
                    break

    def load_interfaces(self):
        try:
            interfaces = netifaces.interfaces()
            self.interface_tree.delete(*self.interface_tree.get_children())
            available = []
            for iface in interfaces:
                if iface in ['lo', 'lo0', 'lo1']:
                    continue
                addrs = netifaces.ifaddresses(iface)
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
                status = self.t('active') if ip != 'N/A' else self.t('inactive')
                available.append((iface, ip, mac, status))
            if len(available) == 1:
                iface, ip, mac, status = available[0]
                self.selected_interface_var.set(f"{iface} ({ip})")
                self.interface_tree.insert('', 'end', values=(iface, ip, mac, status), tags=('selected',))
                self.interface_tree.see(self.interface_tree.get_children()[-1])
            else:
                for iface, ip, mac, status in available:
                    self.interface_tree.insert('', 'end', values=(iface, ip, mac, status))
                self.interface_tree.tag_configure('selected', background='lightblue')
                self.interface_tree.bind('<<TreeviewSelect>>', self.on_interface_select)
            if not available:
                messagebox.showwarning(self.t('warning'), self.t('no_interfaces'))
        except Exception as e:
            messagebox.showerror(self.t('error_title'), f"Failed to get interfaces: {e}")

    def on_interface_select(self, event):
        sel = self.interface_tree.selection()
        if sel:
            values = self.interface_tree.item(sel[0])['values']
            if values:
                self.selected_interface_var.set(f"{values[0]} ({values[1]})")

    def auto_select_interface(self):
        try:
            interfaces = netifaces.interfaces()
            best = None
            for iface in interfaces:
                if iface in ['lo', 'lo0']:
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue
                if any(p in iface.lower() for p in ['eth','en','enp','ens','enx']):
                    best = iface
                    break
                elif any(p in iface.lower() for p in ['wlan','wlp','wlo']):
                    if best is None:
                        best = iface
            if best is None:
                for iface in interfaces:
                    if netifaces.AF_INET in netifaces.ifaddresses(iface):
                        best = iface
                        break
            if best:
                for item in self.interface_tree.get_children():
                    if self.interface_tree.item(item)['values'][0] == best:
                        self.interface_tree.selection_set(item)
                        self.interface_tree.see(item)
                        self.on_interface_select(None)
                        break
                messagebox.showinfo(self.t('auto_select'), self.t('auto_selected') % best)
            else:
                messagebox.showwarning(self.t('warning'), self.t('no_interfaces'))
        except Exception as e:
            messagebox.showerror(self.t('error_title'), f"Auto select failed: {e}")

    def get_selected_interface(self):
        sel = self.interface_tree.selection()
        if sel:
            values = self.interface_tree.item(sel[0])['values']
            if values:
                return values[0]
        return None

    def send_dhcp_discover(self, interface, count=3, timeout=5):
        self.dhcp_servers = {}
        sniff_filter = "udp port 67 or udp port 68"

        # 停止旧的嗅探线程
        if self.sniff_thread and self.sniff_thread.is_alive():
            if self.stop_event:
                self.stop_event.set()
            try:
                self.sniff_thread.join(timeout=1)
            except:
                pass
        self.sniff_thread = None
        self.stop_event = None

        # 初始化本机IP集合（避免误报）
        self.local_ips = set(['127.0.0.1', '0.0.0.0'])

        try:
            # 确定实际接口名
            valid = get_if_list()
            actual_iface = interface if interface in valid else None
            if not actual_iface:
                for iface in valid:
                    try:
                        addrs = netifaces.ifaddresses(interface)
                        saved_mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
                        scapy_mac = get_if_hwaddr(iface)
                        if saved_mac and scapy_mac and saved_mac.lower() == scapy_mac.lower():
                            actual_iface = iface
                            break
                    except:
                        continue
            if not actual_iface:
                self.update_result(self.t('cannot_find_interface') + "\n")
                return

            mac = get_if_hwaddr(actual_iface)
            if not mac:
                self.update_status(self.t('cannot_get_mac'))
                return

            self.update_status(self.t('scanning_interface') % (actual_iface, mac))
            self.update_result(self.t('sending_dhcp') + "\n")

            # 收集本机所有 IP 地址，避免误报
            try:
                all_addrs = netifaces.ifaddresses(actual_iface)
                for addr in all_addrs.get(netifaces.AF_INET, []):
                    ip = addr.get('addr')
                    if ip:
                        self.local_ips.add(ip)
            except:
                pass

            # 获取本机IP
            local_ip = '0.0.0.0'
            try:
                addrs = netifaces.ifaddresses(actual_iface)
                local_ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', '0.0.0.0')
            except:
                pass

            # 候选网关
            gateway_candidates = []
            if local_ip != '0.0.0.0':
                parts = local_ip.split('.')
                for last in ['1','2','3','254','255']:
                    gateway_candidates.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{last}")

            # 辅助函数：添加发现的服务器（过滤本机IP）
            def add_server(ip, method, options=None):
                if ip in self.local_ips:
                    return
                if ip not in self.dhcp_servers:
                    self.dhcp_servers[ip] = {'method': method, 'options': options or {}}
                    self.update_result((self.t('found_dhcp') % ip) + f" [{method}]\n")

            # 方法1: socket广播
            self.update_result("[1/9] Method 1: Socket UDP Broadcast...\n")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1)
                for i in range(count):
                    if not self.is_scanning: break
                    self.update_result((self.t('scan_round') % (i+1, count)) + "\n")
                    xid = random.randint(1, 0xFFFFFFFF)
                    packet = build_dhcp_packet(1, mac, xid)
                    for _ in range(5):
                        sock.sendto(packet, ('255.255.255.255', 67))
                        time.sleep(0.05)
                    try:
                        while True:
                            data, addr = sock.recvfrom(1024)
                            if data and addr[0] not in self.dhcp_servers:
                                add_server(addr[0], "Socket Broadcast")
                    except socket.timeout:
                        pass
                    time.sleep(0.5)
                sock.close()
            except Exception as e:
                self.update_result(f"Method 1 error: {e}\n")

            # 方法2: Scapy广播 - 使用后台持续嗅探线程
            self.update_result("[2/9] Method 2: Scapy DHCP Broadcast...\n")
            
            # 启动后台嗅探线程（持续运行，后续方法也使用同一队列）
            pkt_queue = queue.Queue()
            self.stop_event = threading.Event()
            
            def scapy_callback(pkt):
                if DHCP in pkt and IP in pkt:
                    ip_src = pkt[IP].src
                    if ip_src not in self.dhcp_servers:
                        pkt_queue.put(ip_src)
            
            self.sniff_thread = threading.Thread(
                target=lambda: sniff(iface=actual_iface, filter=sniff_filter, 
                                   prn=scapy_callback, store=0, 
                                   stop_filter=lambda x: self.stop_event.is_set()),
                daemon=True
            )
            self.sniff_thread.start()
            
            for i in range(count):
                if not self.is_scanning: break
                self.update_result((self.t('scan_round') % (i+1, count)) + "\n")
                try:
                    xid = random.randint(1, 0xFFFFFFFF)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                    ip = IP(src="0.0.0.0", dst="255.255.255.255")
                    udp = UDP(sport=68, dport=67)
                    bootp = BOOTP(op=1, chaddr=mac2str(mac), xid=xid)
                    dhcp = DHCP(options=[("message-type", "discover"), ("end", b'')])
                    packet = ether/ip/udp/bootp/dhcp
                    for _ in range(5):
                        sendp(packet, iface=actual_iface, verbose=False)
                        time.sleep(0.05)
                except Exception as e:
                    self.update_result(f"Scapy send error: {e}\n")
                
                # 从队列中收集响应
                start = time.time()
                while time.time() - start < timeout:
                    try:
                        server_ip = pkt_queue.get_nowait()
                        if server_ip not in self.dhcp_servers:
                            add_server(server_ip, "Scapy Broadcast")
                    except queue.Empty:
                        break
                    if not self.is_scanning: break
                time.sleep(0.3)
            
            # 继续收集剩余响应
            start = time.time()
            while time.time() - start < 1:
                try:
                    server_ip = pkt_queue.get_nowait()
                    if server_ip not in self.dhcp_servers:
                        add_server(server_ip, "Scapy Broadcast")
                except queue.Empty:
                    break

            # 方法3: Unicast到网关 (socket) - 修复macOS权限错误
            if local_ip != '0.0.0.0' and gateway_candidates:
                self.update_result("[3/9] Method 3: Unicast to Gateway...\n")
                for gw in gateway_candidates:
                    if not self.is_scanning or len(self.dhcp_servers) > 0:
                        break
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1)
                        for i in range(2):
                            if not self.is_scanning: break
                            xid = random.randint(1, 0xFFFFFFFF)
                            packet = build_dhcp_packet(1, mac, xid, ciaddr=local_ip, giaddr=gw)
                            sock.sendto(packet, (gw, 67))
                            time.sleep(0.1)
                        try:
                            while True:
                                data, addr = sock.recvfrom(1024)
                                if data and addr[0] not in self.dhcp_servers:
                                    add_server(addr[0], "Unicast Socket")
                        except socket.timeout:
                            pass
                        sock.close()
                    except PermissionError:
                        self.update_result(f"Unicast socket not permitted on macOS, skipping.\n")
                        break  # macOS上不再尝试其他网关
                    except Exception as e:
                        self.update_result(f"Unicast error: {e}\n")

            # 方法4: Scapy Unicast到网关
            if local_ip != '0.0.0.0' and gateway_candidates:
                self.update_result("[4/9] Method 4: Scapy Unicast to Gateway...\n")
                for gw in gateway_candidates:
                    if not self.is_scanning or len(self.dhcp_servers) > 0:
                        break
                    try:
                        for i in range(2):
                            if not self.is_scanning: break
                            xid = random.randint(1, 0xFFFFFFFF)
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                            ip = IP(src=local_ip, dst=gw)
                            udp = UDP(sport=68, dport=67)
                            bootp = BOOTP(op=1, chaddr=mac2str(mac), xid=xid, ciaddr=local_ip, giaddr=gw)
                            dhcp = DHCP(options=[("message-type", "discover"), ("end", b'')])
                            sendp(ether/ip/udp/bootp/dhcp, iface=actual_iface, verbose=False)
                            time.sleep(0.1)
                        # 从共享队列中收集响应
                        start = time.time()
                        while time.time() - start < 2:
                            try:
                                server_ip = pkt_queue.get_nowait()
                                if server_ip not in self.dhcp_servers:
                                    add_server(server_ip, "Scapy Unicast")
                            except queue.Empty:
                                break
                            if not self.is_scanning: break
                    except Exception as e:
                        self.update_result(f"Scapy unicast error: {e}\n")

            # 方法5: ARP扫描（网关 + 子网）
            if local_ip != '0.0.0.0':
                self.update_result("[5/9] Method 5: ARP Scan (Gateway + Subnet)...\n")
                parts = local_ip.split('.')
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
                
                # 首先探测已知网关候选
                for gw in gateway_candidates:
                    if not self.is_scanning or len(self.dhcp_servers) > 0:
                        break
                    try:
                        arp = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(op=1, pdst=gw, psrc=local_ip)
                        for _ in range(3):
                            sendp(arp, iface=actual_iface, verbose=False)
                            time.sleep(0.1)
                    except:
                        pass
                
                # 然后扫描本地子网
                for i in range(1, 255, 10):
                    if not self.is_scanning: break
                    target = f"{prefix}.{i}"
                    arp = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(op=1, pdst=target, psrc=local_ip)
                    sendp(arp, iface=actual_iface, verbose=False, count=2)
                    time.sleep(0.1)

            # 方法6: DHCP Inform (静态IP)
            self.update_result("[6/9] Method 6: DHCP Inform...\n")
            if local_ip != '0.0.0.0':
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.settimeout(2)
                    xid = random.randint(1, 0xFFFFFFFF)
                    packet = build_dhcp_packet(8, mac, xid, ciaddr=local_ip, yiaddr='0.0.0.0')
                    for _ in range(3):
                        sock.sendto(packet, ('255.255.255.255', 67))
                        time.sleep(0.1)
                    try:
                        while True:
                            data, addr = sock.recvfrom(1024)
                            if data and addr[0] not in self.dhcp_servers:
                                add_server(addr[0], "DHCP Inform")
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception as e:
                    self.update_result(f"Inform error: {e}\n")

            # 方法7: DHCP Renewal
            self.update_result("[7/9] Method 7: DHCP Renewal...\n")
            if local_ip != '0.0.0.0':
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.settimeout(2)
                    xid = random.randint(1, 0xFFFFFFFF)
                    packet = build_dhcp_packet(3, mac, xid, ciaddr=local_ip, yiaddr='0.0.0.0')
                    for _ in range(3):
                        sock.sendto(packet, ('255.255.255.255', 67))
                        time.sleep(0.1)
                    try:
                        while True:
                            data, addr = sock.recvfrom(1024)
                            if data and addr[0] not in self.dhcp_servers:
                                add_server(addr[0], "DHCP Renewal")
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception as e:
                    self.update_result(f"Renewal error: {e}\n")

            # 方法8: 伪装裸设备（使用Scapy，跨平台）- 始终启用
            self.update_result("[8/9] Method 8: Naked Device (Raw)...\n")
            try:
                xid = random.randint(1, 0xFFFFFFFF)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                ip = IP(src="0.0.0.0", dst="255.255.255.255")
                udp = UDP(sport=68, dport=67)
                bootp = BOOTP(op=1, chaddr=mac2str(mac), xid=xid)
                dhcp = DHCP(options=[("message-type", "discover"), ("end", b'')])
                packet = ether/ip/udp/bootp/dhcp
                for _ in range(5):
                    sendp(packet, iface=actual_iface, verbose=False)
                    time.sleep(0.05)
                # 从共享队列收集响应
                start = time.time()
                while time.time() - start < 2:
                    try:
                        server_ip = pkt_queue.get_nowait()
                        if server_ip not in self.dhcp_servers:
                            add_server(server_ip, "Naked Device")
                    except queue.Empty:
                        break
                    if not self.is_scanning: break
            except Exception as e:
                self.update_result(f"Naked device error: {e}\n")

            # 方法9: DHCP Relay 检测
            self.update_result("[9/9] Method 9: DHCP Relay Detection...\n")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1)
                xid = random.randint(1, 0xFFFFFFFF)
                packet = build_dhcp_packet(1, mac, xid)
                for _ in range(5):
                    sock.sendto(packet, ('255.255.255.255', 67))
                    time.sleep(0.05)
                try:
                    while True:
                        data, addr = sock.recvfrom(1024)
                        if data and len(data) >= 28:
                            giaddr = data[24:28]
                            if giaddr != b'\x00\x00\x00\x00':
                                relay_ip = socket.inet_ntoa(giaddr)
                                self.update_result(f"[DHCP Relay] Detected at: {relay_ip}\n")
                                break
                except socket.timeout:
                    pass
                sock.close()
            except Exception as e:
                self.update_result(f"Relay detection error: {e}\n")

            # VLAN探测 - 发送DHCP Discover到候选网关并监听响应
            self.update_result("\n[VLAN Detection] Scanning common VLAN gateways...\n")
            
            # 启动短暂的后台嗅探线程
            vlan_queue = queue.Queue()
            vlan_stop = threading.Event()
            
            def vlan_callback(pkt):
                if DHCP in pkt and IP in pkt:
                    ip_src = pkt[IP].src
                    if ip_src not in self.dhcp_servers:
                        vlan_queue.put(ip_src)
            
            vlan_sniff_thread = threading.Thread(
                target=lambda: sniff(iface=actual_iface, filter=sniff_filter,
                                    prn=vlan_callback, store=0,
                                    stop_filter=lambda x: vlan_stop.is_set()),
                daemon=True
            )
            vlan_sniff_thread.start()
            
            # 候选VLAN网关列表
            common_gws = ['10.0.0.1', '10.0.1.1', '10.0.2.1', '172.16.0.1', '172.16.1.1', 
                         '172.16.2.1', '192.168.0.1', '192.168.1.1', '192.168.2.1', 
                         '10.10.0.1', '10.10.1.1']
            
            for gw in common_gws:
                if not self.is_scanning: break
                if len(self.dhcp_servers) > 0:
                    break
                try:
                    # 发送DHCP Discover到网关
                    xid = random.randint(1, 0xFFFFFFFF)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                    ip = IP(src="0.0.0.0", dst=gw)
                    udp = UDP(sport=68, dport=67)
                    bootp = BOOTP(op=1, chaddr=mac2str(mac), xid=xid)
                    dhcp = DHCP(options=[("message-type", "discover"), ("end", b'')])
                    packet = ether/ip/udp/bootp/dhcp
                    sendp(packet, iface=actual_iface, verbose=False)
                    time.sleep(0.1)
                except:
                    pass
            
            # 监听响应（使用 timeout 参数的一半，捕获跨VLAN中继响应）
            vlan_listen_time = max(timeout / 2, 2)
            time.sleep(vlan_listen_time)
            while not vlan_queue.empty():
                server_ip = vlan_queue.get()
                if server_ip not in self.dhcp_servers:
                    add_server(server_ip, "VLAN Discovery")
            
            vlan_stop.set()
            vlan_sniff_thread.join(timeout=1)
            self.update_result("  VLAN scanning completed\n")

            # 扫描完成
            if self.is_scanning:
                self.update_result("\n" + (self.t('scan_complete') % len(self.dhcp_servers)) + "\n")
                if len(self.dhcp_servers) > 1:
                    self.update_result(self.t('multiple_warning') + "\n")
                    self.update_result(self.t('possible_causes') + "\n")
                    self.update_result(self.t('cause_1') + "\n")
                    self.update_result(self.t('cause_2') + "\n")
                    self.update_result(self.t('cause_3') + "\n")
                elif len(self.dhcp_servers) == 1:
                    self.update_result(self.t('no_abnormal') + "\n")
                else:
                    self.update_result(self.t('no_dhcp_found') + "\n")
                    self.update_result(self.t('no_dhcp_1') + "\n")
                    self.update_result(self.t('no_dhcp_2') + "\n")
                    self.update_result(self.t('no_dhcp_3') + "\n")

        except Exception as e:
            self.update_result((self.t('scan_error') % e) + "\n")
        finally:
            # 停止嗅探线程
            if self.sniff_thread and self.sniff_thread.is_alive():
                if self.stop_event:
                    self.stop_event.set()
                try:
                    self.sniff_thread.join(timeout=1)
                except:
                    pass
            self.sniff_thread = None
            self.stop_event = None
            self.scan_completed()

    def start_scan(self):
        iface = self.get_selected_interface()
        if not iface:
            messagebox.showwarning(self.t('warning'), self.t('select_interface'))
            return
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.server_count_var.set("0")
        self.update_status(self.t('scanning'))
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()
        self.save_config()
        self.scan_thread = threading.Thread(
            target=self.send_dhcp_discover,
            args=(iface, self.scan_count_var.get(), self.timeout_var.get()),
            daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self):
        self.is_scanning = False
        self.update_status(self.t('stopping'))
        self.stop_btn.config(state=tk.DISABLED)

    def scan_completed(self):
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.server_count_var.set(str(len(self.dhcp_servers)))
        self.update_status(self.t('completed'))

    def update_status(self, msg):
        self.status_var.set(msg)

    def update_result(self, msg):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, msg)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.root.update_idletasks()


def check_npcap_installed():
    if platform.system() != 'Windows':
        return True
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap")
        winreg.CloseKey(key)
        return True
    except:
        try:
            if os.path.exists(r"C:\Windows\System32\Npcap"):
                return True
        except:
            pass
    return False

def install_npcap():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    installer = os.path.join(script_dir, "npcap-1.87.exe")
    if os.path.exists(installer):
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "open", installer, None, script_dir, 1)
            return ret > 32
        except:
            pass
    return False

def main():
    system = platform.system()
    if system == 'Windows' and not check_npcap_installed():
        if messagebox.askyesno("Npcap未安装", "Npcap是本程序运行的必要组件。\n\n是否立即安装Npcap?"):
            if install_npcap():
                messagebox.showinfo("提示", "Npcap安装程序已启动。\n\n请完成安装后重新运行本程序。")
            else:
                messagebox.showerror("错误", "无法启动Npcap安装程序。\n请手动运行同目录下的 npcap-1.87.exe")
        sys.exit(0)

    # 管理员权限
    try:
        if system == 'Windows':
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except:
        is_admin = False
    if not is_admin:
        request_admin()
    else:
        try:
            import scapy
            import netifaces
        except ImportError:
            return
        if system == 'Windows':
            import ttkbootstrap as ttkb
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                build, _ = winreg.QueryValueEx(key, "CurrentBuild")
                winreg.CloseKey(key)
                is_win10 = int(build) >= 10240
            except:
                is_win10 = False
            theme = "darkly" if (is_win10 and get_windows_theme() == 'dark') else "flatly"
            root = ttkb.Window(themename=theme)
        else:
            root = tk.Tk()
        root.minsize(800, 700)
        app = DHCPScanner(root)
        root.mainloop()

if __name__ == "__main__":
    main()  