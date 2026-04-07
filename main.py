import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import struct
import threading
import time
import netifaces
from scapy.all import *
import ipaddress
import platform
import configparser
import os
import sys
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

def request_admin():
    """请求管理员权限 - 跨平台支持"""
    system = platform.system()
    python_exe = sys.executable
    
    if system == 'Windows':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                script = os.path.abspath(sys.argv[0])
                script_dir = os.path.dirname(script)
                
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", python_exe, f'"{script}"', script_dir, 1
                )
                
                if ret <= 32:
                    print(f"Windows管理员请求失败，错误码: {ret}")
                    return False
                sys.exit(0)
        except Exception as e:
            print(f"Windows管理员请求失败: {e}")
            return False
            
    elif system == 'Darwin':
        is_admin = os.geteuid() == 0
        if not is_admin:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            try:
                cmd = f'''tell application "Terminal"
                    do script "clear
echo '╔════════════════════════════════════════╗'
echo '║       DHCP服务器扫描器 - 权限提升      ║'
echo '╚════════════════════════════════════════╝'
echo ''
echo '>>> 正在请求管理员权限...'
echo '>>> 请在下方输入您的登录密码'
echo '>>> '
sudo \\"{python_exe}\\" \\"{script}\\" {params}
sleep 1
tell application \\"Terminal\\" to quit"
                end tell'''
                result = subprocess.run(['osascript', '-e', cmd], capture_output=True, text=True)
                if result.returncode == 0:
                    sys.exit(0)
                else:
                    print(f"macOS管理员请求失败: {result.stderr}")
            except Exception as e:
                print(f"macOS管理员请求失败: {e}")
            return False
                
    elif system == 'Linux':
        is_admin = os.geteuid() == 0
        if not is_admin:
            script = os.path.abspath(sys.argv[0])
            try:
                result = subprocess.run(['pkexec', python_exe, script] + sys.argv[1:],
                                      capture_output=True, text=True)
                sys.exit(result.returncode)
            except Exception as e:
                try:
                    result = subprocess.run(['sudo', python_exe, script] + sys.argv[1:],
                                          capture_output=True, text=True)
                    sys.exit(result.returncode)
                except Exception as e2:
                    print(f"Linux管理员请求失败: {e2}")
                    return False
    return True

class DHCPScanner:
    def __init__(self, root):
        self.root = root
        self.root.attributes('-alpha', 0.95)

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
            except Exception as e:
                print(f"设置图标失败: {e}")

        # 配置文件路径
        self.config_file = "dhcp_scanner_config.json"

        # 加载配置
        self.config = self.load_config()

        # 语言设置
        self.current_lang = self.config.get('language', 'zh')

        # 设置窗口大小（根据配置调整）
        window_width = self.config.get('window_width', 700)
        window_height = self.config.get('window_height', 800)
        self.root.geometry(f"{window_width}x{window_height}")

        # 系统检测
        self.system = platform.system()
        self.is_mac = self.system == 'Darwin'
        self.is_linux = self.system == 'Linux'

        # 扫描状态
        self.is_scanning = False
        self.scan_thread = None
        self.dhcp_servers = []

        # 创建UI
        self.create_ui()

        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 绑定窗口大小变化事件
        self.root.bind("<Configure>", self.on_window_resize)

    def t(self, key):
        """获取翻译"""
        return LANG[self.current_lang].get(key, key)

    def toggle_language(self):
        """切换语言"""
        self.current_lang = self.lang_var.get()
        self.config['language'] = self.current_lang
        self.save_config()
        self.update_ui_text()
        self.load_interfaces()
        self.restore_last_interface()

    def update_ui_text(self):
        """更新UI文本"""
        self.root.title(self.t('title'))
        
        # 更新系统信息
        system_info = f"{self.t('system_info')}: {self.system}"
        if self.is_mac:
            system_info += " (macOS)"
        elif self.is_linux:
            system_info += " (Linux)"
        self.system_label.config(text=system_info)
        
        # 更新配置信息
        self.config_label.config(text=f"{self.t('config')}: {self.t('scan_count')}={self.config['scan_count']}, {self.t('timeout')}={self.config['timeout']}")
        
        # 更新网卡列表标签
        self.interfaces_label.config(text=self.t('available_interfaces') + ":")
        
        # 更新Treeview列标题
        self.interface_tree.heading('interface', text=self.t('interface_name'))
        self.interface_tree.heading('ip', text=self.t('ip'))
        self.interface_tree.heading('mac', text=self.t('mac'))
        self.interface_tree.heading('status', text=self.t('status'))
        
        # 更新按钮文本
        self.refresh_btn.config(text=self.t('refresh'))
        self.auto_select_btn.config(text=self.t('auto_select'))
        self.selection_label.config(text=self.t('current_selection') + ":")
        
        # 更新扫描参数标签
        self.scan_count_label.config(text=self.t('scan_count') + ":")
        self.timeout_label.config(text=self.t('timeout') + ":")
        
        # 更新操作按钮
        self.save_btn.config(text=self.t('save_settings'))
        self.scan_btn.config(text=self.t('start_scan'))
        self.stop_btn.config(text=self.t('stop_scan'))
        
        # 更新结果统计标签
        self.server_count_label.config(text=self.t('dhcp_server_count') + ":")
        self.state_label.config(text=self.t('state') + ":")
        
        # 更新使用说明
        self.usage_label.config(text=self.t('usage') + ": " + self.t('usage_text'))
        
        # 更新状态
        self.status_var.set(self.t('ready'))
        self.selected_interface_var.set(self.t('not_selected'))

    def load_config(self):
        """加载配置文件"""
        default_config = {
            'scan_count': 3,
            'timeout': 5,
            'window_width': 700,
            'window_height': 800,
            'last_interface': '',
            'language': 'zh'
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # 合并默认配置和保存的配置
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                return default_config
        except Exception as e:
            print(f"加载配置文件出错: {e}")
            return default_config

    def save_config(self):
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"保存配置文件出错: {e}")
            return False

    def on_window_resize(self, event):
        """窗口大小变化时保存配置"""
        if event.widget == self.root:
            width = event.width
            height = event.height
            # 只在窗口大小显著变化时保存，避免频繁写入
            if abs(width - self.config.get('window_width', 700)) > 20 or \
               abs(height - self.config.get('window_height', 800)) > 20:
                self.config['window_width'] = width
                self.config['window_height'] = height
                # 延迟保存，避免频繁写入
                if hasattr(self, 'save_timer'):
                    self.root.after_cancel(self.save_timer)
                self.save_timer = self.root.after(1000, self.save_config)

    def on_closing(self):
        """窗口关闭时保存配置"""
        # 保存当前配置
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()

        # 保存选中的网卡
        interface = self.get_selected_interface()
        if interface:
            self.config['last_interface'] = interface

        self.save_config()
        self.root.destroy()

    def create_ui(self):
        self.root.title(self.t('title'))
        
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 语言选择区域
        lang_frame = ttk.LabelFrame(main_frame, padding="5")
        lang_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.lang_var = tk.StringVar(value=self.current_lang)
        ttk.Label(lang_frame, text="语言/language").pack(side=tk.LEFT, padx=(5, 10))
        ttk.Radiobutton(lang_frame, text="中文", variable=self.lang_var, value='zh', command=self.toggle_language).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Radiobutton(lang_frame, text="English", variable=self.lang_var, value='en', command=self.toggle_language).pack(side=tk.LEFT)

        # 系统信息区域
        system_frame = ttk.LabelFrame(main_frame, padding="10")
        system_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        system_info = f"{self.t('system_info')}: {self.system}"
        if self.is_mac:
            system_info += " (macOS)"
        elif self.is_linux:
            system_info += " (Linux)"

        self.system_label = ttk.Label(system_frame, text=system_info)
        self.system_label.grid(row=0, column=0, sticky=tk.W)

        # 配置信息
        self.config_label = ttk.Label(system_frame, foreground="blue")
        self.config_label.grid(row=0, column=1, sticky=tk.E)

        # 网卡选择区域
        network_frame = ttk.LabelFrame(main_frame, padding="10")
        network_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # 网卡列表
        self.interfaces_label = ttk.Label(network_frame)
        self.interfaces_label.grid(row=0, column=0, sticky=tk.W)

        # 多列显示
        columns = ('interface', 'ip', 'mac', 'status')
        self.interface_tree = ttk.Treeview(network_frame, columns=columns, show='headings', height=5)

        # 设置列
        self.interface_tree.heading('interface', text=self.t('interface_name'))
        self.interface_tree.heading('ip', text=self.t('ip'))
        self.interface_tree.heading('mac', text=self.t('mac'))
        self.interface_tree.heading('status', text=self.t('status'))

        self.interface_tree.column('interface', width=120)
        self.interface_tree.column('ip', width=120)
        self.interface_tree.column('mac', width=120)
        self.interface_tree.column('status', width=80)

        self.interface_tree.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 5))

        # 滚动条
        scrollbar = ttk.Scrollbar(network_frame, orient=tk.VERTICAL, command=self.interface_tree.yview)
        scrollbar.grid(row=1, column=2, sticky=(tk.N, tk.S))
        self.interface_tree.configure(yscrollcommand=scrollbar.set)

        # 按钮
        button_frame = ttk.Frame(network_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(5, 0))

        self.refresh_btn = ttk.Button(button_frame, command=self.load_interfaces)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.auto_select_btn = ttk.Button(button_frame, command=self.auto_select_interface)
        self.auto_select_btn.pack(side=tk.LEFT, padx=(5, 5))

        # 当前选择
        self.selected_interface_var = tk.StringVar(value=self.t('not_selected'))
        self.selection_label = ttk.Label(button_frame)
        self.selection_label.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(button_frame, textvariable=self.selected_interface_var,
                 font=("Arial", 10, "bold"), foreground="blue").pack(side=tk.LEFT, padx=(5, 0))

        # 扫描控制
        control_frame = ttk.LabelFrame(main_frame, padding="10")
        control_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # 扫描参数
        param_frame = ttk.Frame(control_frame)
        param_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))

        self.scan_count_label = ttk.Label(param_frame)
        self.scan_count_label.pack(side=tk.LEFT)
        self.scan_count_var = tk.IntVar(value=self.config['scan_count'])
        scan_count_spin = ttk.Spinbox(param_frame, from_=1, to=10,
                                     textvariable=self.scan_count_var, width=8)
        scan_count_spin.pack(side=tk.LEFT, padx=(5, 20))

        self.timeout_label = ttk.Label(param_frame)
        self.timeout_label.pack(side=tk.LEFT)
        self.timeout_var = tk.IntVar(value=self.config['timeout'])
        timeout_spin = ttk.Spinbox(param_frame, from_=1, to=30,
                                  textvariable=self.timeout_var, width=8)
        timeout_spin.pack(side=tk.LEFT, padx=(5, 20))

        # 按钮
        action_frame = ttk.Frame(control_frame)
        action_frame.grid(row=1, column=0, columnspan=2, pady=(10, 0))

        self.save_btn = ttk.Button(action_frame, command=self.save_current_settings)
        self.save_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.scan_btn = ttk.Button(action_frame, command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(5, 5))
        self.stop_btn = ttk.Button(action_frame, command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        # 结果显示
        result_frame = ttk.LabelFrame(main_frame, padding="10")
        result_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # 结果统计
        stats_frame = ttk.Frame(result_frame)
        stats_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.server_count_label = ttk.Label(stats_frame)
        self.server_count_label.grid(row=0, column=0, sticky=tk.W)
        self.server_count_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.server_count_var,
                 font=("Arial", 12, "bold"), foreground="red").grid(row=0, column=1, padx=(5, 20))

        self.state_label = ttk.Label(stats_frame)
        self.state_label.grid(row=0, column=2, sticky=tk.W)
        self.status_var = tk.StringVar(value=self.t('ready'))
        ttk.Label(stats_frame, textvariable=self.status_var, font=("Arial", 10)).grid(row=0, column=3, padx=(5, 0))

        # 结果列表
        self.result_text = scrolledtext.ScrolledText(result_frame, height=20, width=90)
        self.result_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.result_text.config(state=tk.DISABLED)

        # 右键菜单
        self.result_text.bind("<Button-3>", self.show_context_menu)

        # 使用说明
        self.usage_label = ttk.Label(main_frame, foreground="gray")
        self.usage_label.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))

        # 配置网格权重 - 关键部分，确保结果区域可伸缩
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)  # 结果区域可伸缩
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(1, weight=1)  # 文本区域可伸缩

        # 初始化UI文本
        self.update_ui_text()

        # 加载上次选择的网卡
        self.load_interfaces()
        self.restore_last_interface()

    def show_context_menu(self, event):
        """显示右键菜单"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=self.t('copy'), command=self.copy_result_text)
        menu.add_command(label=self.t('clear'), command=self.clear_result_text)
        menu.add_separator()
        menu.add_command(label=self.t('save_to_file'), command=self.save_result_to_file)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_result_text(self):
        """复制结果文本到剪贴板"""
        try:
            text = self.result_text.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo(self.t('copy'), self.t('copied'))
        except Exception as e:
            messagebox.showerror(self.t('error_title'), self.t('copy_failed') + f": {e}")

    def clear_result_text(self):
        """清空结果文本"""
        if self.is_scanning:
            messagebox.showwarning(self.t('warning'), self.t('cannot_clear'))
            return

        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.server_count_var.set("0")

    def save_result_to_file(self):
        """保存结果到文件"""
        try:
            text = self.result_text.get(1.0, tk.END)
            if not text.strip():
                messagebox.showinfo(self.t('saved_success'), self.t('nothing_to_save'))
                return

            filename = f"dhcp_scan_result_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)

            messagebox.showinfo(self.t('saved_success'), self.t('saved') % filename)
        except Exception as e:
            messagebox.showerror(self.t('error_title'), self.t('save_failed') + f": {e}")

    def save_current_settings(self):
        """保存当前设置到配置文件"""
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()

        # 保存选中的网卡
        interface = self.get_selected_interface()
        if interface:
            self.config['last_interface'] = interface

        if self.save_config():
            messagebox.showinfo(self.t('saved_success'), self.t('settings_saved'))
            # 更新系统信息中的配置显示
            system_frame = self.root.grid_slaves(row=0, column=0)[0].winfo_children()[0]
            config_label = system_frame.grid_slaves(row=0, column=1)[0]
            config_label.config(text=f"{self.t('config')}: {self.t('scan_count')}={self.config['scan_count']}, {self.t('timeout')}={self.config['timeout']}")
        else:
            messagebox.showerror(self.t('error_title'), self.t('save_failed'))

    def restore_last_interface(self):
        """恢复上次选择的网卡"""
        last_interface = self.config.get('last_interface', '')
        if last_interface:
            # 检查接口是否在列表中
            found = False
            for item in self.interface_tree.get_children():
                if self.interface_tree.item(item)['values'][0] == last_interface:
                    self.interface_tree.selection_set(item)
                    self.interface_tree.see(item)
                    self.on_interface_select(None)
                    found = True
                    break
            # 如果没找到，清除保存的接口
            if not found:
                self.config['last_interface'] = ''
                self.save_config()

    def load_interfaces(self):
        """加载所有网络接口"""
        try:
            interfaces = netifaces.interfaces()
            self.interface_tree.delete(*self.interface_tree.get_children())

            available_interfaces = []

            for interface in interfaces:
                # 跳过本地回环接口
                if interface in ['lo', 'lo0', 'lo1']:
                    continue

                # 获取接口信息
                addrs = netifaces.ifaddresses(interface)
                ip_info = addrs.get(netifaces.AF_INET, [{}])[0]
                mac_info = addrs.get(netifaces.AF_LINK, [{}])[0]

                ip = ip_info.get('addr', 'N/A')
                mac = mac_info.get('addr', 'N/A')

                status = self.t('active') if ip != 'N/A' else self.t('inactive')
                available_interfaces.append((interface, ip, mac, status))

            # 自动选择逻辑
            if len(available_interfaces) == 1:
                # 只有一个网卡，自动选择
                interface, ip, mac, status = available_interfaces[0]
                self.selected_interface_var.set(f"{interface} ({ip})")
                self.interface_tree.insert('', 'end', values=(interface, ip, mac, status), tags=('selected',))
                # 滚动到选中项
                self.interface_tree.see(self.interface_tree.get_children()[-1])
            else:
                # 多个网卡
                for interface, ip, mac, status in available_interfaces:
                    self.interface_tree.insert('', 'end', values=(interface, ip, mac, status))

                # 设置选中样式
                self.interface_tree.tag_configure('selected', background='lightblue')

                # 绑定选择事件
                self.interface_tree.bind('<<TreeviewSelect>>', self.on_interface_select)

            if not available_interfaces:
                messagebox.showwarning(self.t('warning'), self.t('no_interfaces'))

        except Exception as e:
            messagebox.showerror(self.t('error_title'), f"Failed to get network interfaces: {e}")
            if self.is_mac or self.is_linux:
                messagebox.showinfo(self.t('usage'), self.t('macos_tip'))

    def on_interface_select(self, event):
        """网卡选择事件处理"""
        selection = self.interface_tree.selection()
        if selection:
            item = self.interface_tree.item(selection[0])
            values = item['values']
            if values:
                interface = values[0]
                ip = values[1]
                self.selected_interface_var.set(f"{interface} ({ip})")

    def auto_select_interface(self):
        """自动选择最佳网卡"""
        try:
            interfaces = netifaces.interfaces()
            best_interface = None

            # 优先级：有线 > 无线 > 其他
            for interface in interfaces:
                if interface in ['lo', 'lo0']:
                    continue

                # 检查是否有IP地址
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET not in addrs:
                    continue

                # 有线网卡优先级更高
                if any(prefix in interface.lower() for prefix in ['eth', 'en', 'enp', 'ens', 'enx']):
                    best_interface = interface
                    break
                # 无线网卡次
                elif any(prefix in interface.lower() for prefix in ['wlan', 'wlp', 'wlo', 'wlp']):
                    if best_interface is None:
                        best_interface = interface

            # 如果没有找到，选择第一个有IP的
            if best_interface is None:
                for interface in interfaces:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        best_interface = interface
                        break

            if best_interface:
                # 更新Treeview选中状态
                for item in self.interface_tree.get_children():
                    if self.interface_tree.item(item)['values'][0] == best_interface:
                        self.interface_tree.selection_set(item)
                        self.interface_tree.see(item)
                        self.on_interface_select(None)
                        break

                messagebox.showinfo(self.t('auto_select'), self.t('auto_selected') % best_interface)
            else:
                messagebox.showwarning(self.t('warning'), self.t('no_interfaces'))

        except Exception as e:
            messagebox.showerror(self.t('error_title'), f"Auto select failed: {e}")

    def get_selected_interface(self):
        """获取选中的网卡"""
        selection = self.interface_tree.selection()
        if selection:
            item = self.interface_tree.item(selection[0])
            values = item['values']
            if values:
                return values[0]
        return None

    def send_dhcp_discover(self, interface, count=3, timeout=5):
        """发送DHCP Discover包"""
        self.dhcp_servers = []
        found_ips = set()
        sniff_filter = "udp port 67 or udp port 68"

        try:
            valid_interfaces = get_if_list()
            actual_interface = None
            
            if interface in valid_interfaces:
                actual_interface = interface
            else:
                for iface in valid_interfaces:
                    try:
                        addrs = netifaces.ifaddresses(interface)
                        mac_info = addrs.get(netifaces.AF_LINK, [{}])[0]
                        saved_mac = mac_info.get('addr', '')
                        scapy_mac = get_if_hwaddr(iface)
                        if saved_mac and scapy_mac and saved_mac.lower() == scapy_mac.lower():
                            actual_interface = iface
                            break
                    except:
                        continue
            
            if not actual_interface:
                self.update_result(self.t('cannot_find_interface') + "\n")
                return
            
            mac = get_if_hwaddr(actual_interface)
            if not mac:
                self.update_status(self.t('cannot_get_mac'))
                return

            self.update_status(self.t('scanning_interface') % (actual_interface, mac))
            self.update_result(self.t('sending_dhcp') + "\n")

            # 获取本机IP
            local_ip = '0.0.0.0'
            try:
                addrs = netifaces.ifaddresses(actual_interface)
                local_ip_info = addrs.get(netifaces.AF_INET, [{}])[0]
                local_ip = local_ip_info.get('addr', '0.0.0.0')
            except:
                pass

            # 计算可能的网关IP
            gateway_candidates = []
            if local_ip != '0.0.0.0':
                ip_parts = local_ip.split('.')
                for last in ['1', '2', '3', '254', '255']:
                    gw = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{last}"
                    gateway_candidates.append(gw)

            # 方法1: 使用socket发送原始UDP广播
            self.update_result("[1/6] Method 1: Socket UDP Broadcast...\n")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1)
                
                for i in range(count):
                    if not self.is_scanning:
                        break
                    self.update_result((self.t('scan_round') % (i+1, count)) + "\n")
                    
                    # 构建DHCP Discover包
                    xid = random.randint(1, 0xFFFFFFFF)
                    
                    # BOOTP头部
                    bootp = b''
                    bootp += struct.pack('!B', 1)  # op
                    bootp += struct.pack('!B', 1)  # htype
                    bootp += struct.pack('!B', 6)  # hlen
                    bootp += struct.pack('!B', 0)  # hops
                    bootp += struct.pack('!I', xid)  # xid
                    bootp += struct.pack('!H', 0)  # secs
                    bootp += struct.pack('!H', 0x8000)  # flags: broadcast
                    bootp += b'\x00' * 4  # ciaddr
                    bootp += b'\x00' * 4  # yiaddr
                    bootp += b'\x00' * 4  # siaddr
                    bootp += b'\x00' * 4  # giaddr
                    
                    # chaddr (16字节)
                    mac_bytes = bytes.fromhex(mac.replace(':', ''))
                    bootp += mac_bytes + b'\x00' * (16 - len(mac_bytes))
                    bootp += b'\x00' * 64  # sname
                    bootp += b'\x00' * 128  # file
                    
                    # Magic cookie
                    bootp += b'\x63\x82\x53\x63'
                    
                    # DHCP选项
                    dhcp_options = b''
                    dhcp_options += b'\x35\x01\x01'  # DHCP Discover
                    dhcp_options += b'\x3d\x07\x01' + mac_bytes  # Client Identifier
                    dhcp_options += b'\xff'  # End
                    
                    packet = bootp + dhcp_options
                    packet = packet[:312] + b'\x00' * max(0, 312 - len(packet))
                    
                    for _ in range(5):
                        sock.sendto(packet, ('255.255.255.255', 67))
                        time.sleep(0.05)
                    
                    # 接收响应
                    try:
                        while True:
                            data, addr = sock.recvfrom(1024)
                            if data and addr[0] not in found_ips:
                                found_ips.add(addr[0])
                                self.update_result((self.t('found_dhcp') % addr[0]) + "\n")
                    except socket.timeout:
                        pass
                    
                    time.sleep(0.5)
                
                sock.close()
            except Exception as e:
                self.update_result(f"Method 1 error: {e}\n")

            # 方法2: Scapy发送DHCP广播
            self.update_result("[2/6] Method 2: Scapy DHCP Broadcast...\n")
            for i in range(count):
                if not self.is_scanning:
                    break
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
                        sendp(packet, iface=actual_interface, verbose=False)
                        time.sleep(0.05)
                    
                    start_time = time.time()
                    while time.time() - start_time < timeout:
                        try:
                            packets = sniff(iface=actual_interface, filter=sniff_filter, 
                                          count=5, timeout=0.5, store=True)
                            for pkt in packets:
                                if DHCP in pkt and IP in pkt:
                                    server_ip = pkt[IP].src
                                    if server_ip not in found_ips:
                                        found_ips.add(server_ip)
                                        self.update_result((self.t('found_dhcp') % server_ip) + "\n")
                        except:
                            pass
                        if not self.is_scanning:
                            break
                except Exception as e:
                    self.update_result(f"Scapy error: {e}\n")
                
                time.sleep(0.3)

            # 方法3: Unicast到网关
            if local_ip != '0.0.0.0' and gateway_candidates:
                self.update_result("[3/6] Method 3: Unicast to Gateway...\n")
                for gw in gateway_candidates:
                    if not self.is_scanning:
                        break
                    if len(found_ips) > 0:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1)
                        
                        for i in range(2):
                            if not self.is_scanning:
                                break
                            xid = random.randint(1, 0xFFFFFFFF)
                            
                            bootp = b''
                            bootp += struct.pack('!B', 1)
                            bootp += struct.pack('!B', 1)
                            bootp += struct.pack('!B', 6)
                            bootp += struct.pack('!B', 0)
                            bootp += struct.pack('!I', xid)
                            bootp += struct.pack('!H', 0)
                            bootp += struct.pack('!H', 0)
                            bootp += socket.inet_aton(local_ip)
                            bootp += b'\x00' * 4
                            bootp += socket.inet_aton(gw)
                            bootp += b'\x00' * 4
                            
                            mac_bytes = bytes.fromhex(mac.replace(':', ''))
                            bootp += mac_bytes + b'\x00' * (16 - len(mac_bytes))
                            bootp += b'\x00' * 64
                            bootp += b'\x00' * 128
                            bootp += b'\x63\x82\x53\x63'
                            
                            dhcp_options = b'\x35\x01\x01\xff'
                            packet = bootp + dhcp_options
                            packet = packet[:312] + b'\x00' * max(0, 312 - len(packet))
                            
                            sock.sendto(packet, (gw, 67))
                            time.sleep(0.1)
                        
                        try:
                            while True:
                                data, addr = sock.recvfrom(1024)
                                if data and addr[0] not in found_ips:
                                    found_ips.add(addr[0])
                                    self.update_result((self.t('found_dhcp') % addr[0]) + "\n")
                        except socket.timeout:
                            pass
                        
                        sock.close()
                    except Exception as e:
                        self.update_result(f"Unicast error: {e}\n")

            # 方法4: Scapy Unicast到网关
            if local_ip != '0.0.0.0' and gateway_candidates:
                self.update_result("[4/6] Method 4: Scapy Unicast to Gateway...\n")
                for gw in gateway_candidates:
                    if not self.is_scanning:
                        break
                    if len(found_ips) > 0:
                        break
                    
                    try:
                        for i in range(2):
                            if not self.is_scanning:
                                break
                            xid = random.randint(1, 0xFFFFFFFF)
                            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                            ip = IP(src=local_ip, dst=gw)
                            udp = UDP(sport=68, dport=67)
                            bootp = BOOTP(op=1, chaddr=mac2str(mac), xid=xid, ciaddr=local_ip, giaddr=gw)
                            dhcp = DHCP(options=[("message-type", "discover"), ("end", b'')])
                            packet = ether/ip/udp/bootp/dhcp
                            
                            sendp(packet, iface=actual_interface, verbose=False)
                            time.sleep(0.1)
                        
                        # 接收
                        start_time = time.time()
                        while time.time() - start_time < 2:
                            try:
                                packets = sniff(iface=actual_interface, filter=sniff_filter, 
                                              count=5, timeout=0.5, store=True)
                                for pkt in packets:
                                    if DHCP in pkt and IP in pkt:
                                        server_ip = pkt[IP].src
                                        if server_ip not in found_ips:
                                            found_ips.add(server_ip)
                                            self.update_result((self.t('found_dhcp') % server_ip) + "\n")
                            except:
                                pass
                    except Exception as e:
                        self.update_result(f"Scapy unicast error: {e}\n")

            # 方法5: ARP探测网关
            if local_ip != '0.0.0.0' and gateway_candidates:
                self.update_result("[5/6] Method 5: ARP Gateway Discovery...\n")
                for gw in gateway_candidates:
                    if not self.is_scanning:
                        break
                    if len(found_ips) > 0:
                        break
                    
                    try:
                        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)/ARP(op=1, pdst=gw, psrc=local_ip)
                        for _ in range(3):
                            sendp(arp_request, iface=actual_interface, verbose=False)
                            time.sleep(0.1)
                    except:
                        pass

            # 方法6: UDP探测67端口
            self.update_result("[6/6] Method 6: UDP Port 67 Scan...\n")
            if local_ip != '0.0.0.0':
                ip_parts = local_ip.split('.')
                subnet_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                
                for i in range(1, 255, 10):
                    if not self.is_scanning:
                        break
                    if len(found_ips) > 0:
                        break
                    
                    target_ip = f"{subnet_prefix}.{i}"
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(0.3)
                        sock.sendto(b'\x01', (target_ip, 67))
                        sock.close()
                    except:
                        pass

            self.dhcp_servers = list(found_ips)

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
            self.scan_completed()

    def start_scan(self):
        """开始扫描"""
        interface = self.get_selected_interface()
        if not interface:
            messagebox.showwarning(self.t('warning'), self.t('select_interface'))
            return

        # 更新UI
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.server_count_var.set("0")
        self.update_status(self.t('scanning'))

        # 保存设置
        self.config['scan_count'] = self.scan_count_var.get()
        self.config['timeout'] = self.timeout_var.get()
        self.save_config()

        # 启动扫描
        self.scan_thread = threading.Thread(
            target=self.send_dhcp_discover,
            args=(interface, self.scan_count_var.get(), self.timeout_var.get()),
            daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self):
        """停止扫描"""
        self.is_scanning = False
        self.update_status(self.t('stopping'))
        self.stop_btn.config(state=tk.DISABLED)

    def scan_completed(self):
        """扫描完成后的UI更新"""
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.server_count_var.set(str(len(self.dhcp_servers)))
        self.update_status(self.t('completed'))

    def update_status(self, message):
        """更新状态信息"""
        self.status_var.set(message)

    def update_result(self, message):
        """更新结果文本"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)
        self.root.update_idletasks()

def main():
    # 检查系统
    system = platform.system()

    # 管理员权限运行
    try:
        if system == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux, macOS
            import os
            is_admin = os.geteuid() == 0
    except:
        is_admin = False

    if not is_admin:
        request_admin()
    else:
        # 检查库
        try:
            import scapy
            import netifaces
        except ImportError as e:
            print(f"缺少必要的库: {e}")
            print("请安装: pip install scapy netifaces")
            return

        # 主窗口
        root = tk.Tk()

        # 设置窗口最小大小
        root.minsize(800, 700)

        # 主循环
        app = DHCPScanner(root)
        root.mainloop()

if __name__ == "__main__":
    main()

