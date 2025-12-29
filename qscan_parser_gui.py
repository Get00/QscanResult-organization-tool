#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import re


class QscanParserGUI:
    OVERVIEW_COLUMNS = ("URL", "服务", "关键词", "IP", "端口", "长度", "操作系统", "产品", "版本", "摘要")
    CRACK_COLUMNS = ("URL", "IP", "端口", "服务", "用户名", "密码", "其他信息", "发现时间")
    UNAUTH_COLUMNS = ("URL", "IP", "端口", "服务", "发现时间", "详细信息")

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Qscan结果解析工具")
        self.root.geometry("1200x700")

        # 数据
        self.scan_results = []
        self.filtered_results = []
        self.crack_results = []
        self.unauth_results = []

        # 每个 Treeview 一个右键菜单（关键修复）
        self.context_menus = {}

        # Tree item -> 原始数据 映射（关键修复：导出/复制拿原始完整数据，而不是界面截断）
        self._overview_iid_map = {}
        self._crack_iid_map = {}
        self._unauth_iid_map = {}

        self.setup_ui()

    # ---------------- UI ----------------

    def setup_ui(self):
        # 统计信息框架
        self.stats_frame = ttk.Frame(self.root)
        self.stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 统计信息标签
        self.stats_label = ttk.Label(self.stats_frame, text="未加载文件", font=("TkDefaultFont", 10))
        self.stats_label.pack(anchor=tk.W)
        
        self.notebook = ttk.Notebook(self.root)
        
        # 设置标签页样式
        style = ttk.Style()
        style.configure("TNotebook.Tab", font=("TkDefaultFont", 10, "bold"), padding=[10, 5])
        
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 标签页
        self.overview_frame = ttk.Frame(self.notebook)
        self.crack_frame = ttk.Frame(self.notebook)
        self.unauth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.overview_frame, text="总览")
        self.notebook.add(self.crack_frame, text="弱口令")
        self.notebook.add(self.unauth_frame, text="未授权访问")

        # ---- 总览页 控制区 ----
        control_frame = ttk.Frame(self.overview_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(control_frame, text="选择扫描结果文件", command=self.load_file).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(control_frame, text="文件类型:").pack(side=tk.LEFT, padx=(10, 5))
        self.file_type_var = tk.StringVar(value="auto")
        ttk.Combobox(
            control_frame,
            textvariable=self.file_type_var,
            values=["auto", "json", "txt", "csv"],
            width=10,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(control_frame, text="搜索:").pack(side=tk.LEFT, padx=(10, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.filter_data())
        ttk.Entry(control_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(control_frame, text="服务类型:").pack(side=tk.LEFT, padx=(10, 5))
        self.service_var = tk.StringVar(value="all")
        service_combo = ttk.Combobox(
            control_frame,
            textvariable=self.service_var,
            values=["all", "ssh", "http", "https", "ftp", "smb", "mssql", "mysql", "oracle", "rdp", "netbios", "ssl"],
            width=10,
            state="readonly",
        )
        service_combo.pack(side=tk.LEFT, padx=(0, 10))
        service_combo.bind("<<ComboboxSelected>>", lambda e: self.filter_data())

        ttk.Button(control_frame, text="导出CSV（全部）", command=self.export_to_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="自适应列宽", command=self.autosize_all_columns).pack(side=tk.LEFT, padx=5)

        # ---- 总览表格 ----
        self.tree = self.create_tree(self.overview_frame, self.OVERVIEW_COLUMNS)

        # ---- 弱口令页 控制区 ----
        crack_control_frame = ttk.Frame(self.crack_frame)
        crack_control_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(crack_control_frame, text="导出弱口令CSV（全部）", command=self.export_crack_to_csv).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Button(crack_control_frame, text="自适应列宽", command=self.autosize_all_columns).pack(side=tk.LEFT, padx=5)

        # ---- 弱口令表格 ----
        self.crack_tree = self.create_tree(self.crack_frame, self.CRACK_COLUMNS)

        # ---- 未授权访问页 控制区 ----
        unauth_control_frame = ttk.Frame(self.unauth_frame)
        unauth_control_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(unauth_control_frame, text="导出未授权CSV（全部）", command=self.export_unauth_to_csv).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        ttk.Button(unauth_control_frame, text="自适应列宽", command=self.autosize_all_columns).pack(side=tk.LEFT, padx=5)

        # ---- 未授权访问表格 ----
        self.unauth_tree = self.create_tree(self.unauth_frame, self.UNAUTH_COLUMNS)

        # 为三个 Treeview 分别创建右键菜单
        self.create_context_menu(self.tree)
        self.create_context_menu(self.crack_tree)
        self.create_context_menu(self.unauth_tree)

    def create_tree(self, parent, columns):
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True)
        # 表格的宽度
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=22, selectmode="extended")

        # 列设置：stretch=False 确保水平滚动条始终有效
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=160, minwidth=80, stretch=False)

        # 添加滚动条
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # 布局
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        return tree

    # ---------------- 右键菜单 ----------------

    def create_context_menu(self, tree: ttk.Treeview):
        """为每个 Treeview 创建独立菜单，避免互相覆盖"""
        menu = tk.Menu(self.root, tearoff=0)

        menu.add_command(label="导出选中行到CSV", command=lambda t=tree: self.export_selected_to_csv(t))
        menu.add_separator()
        menu.add_command(label="复制IP", command=lambda t=tree: self.copy_ip(t))
        menu.add_command(label="复制端口", command=lambda t=tree: self.copy_port(t))
        menu.add_command(label="复制URL", command=lambda t=tree: self.copy_url(t))
        menu.add_command(label="复制IP+端口", command=lambda t=tree: self.copy_ip_port(t))
        menu.add_command(label="复制整行", command=lambda t=tree: self.copy_row(t))
        menu.add_separator()
        menu.add_command(label="全选（当前表格）", command=lambda t=tree: self.select_all(t))

        self.context_menus[tree] = menu

        # Windows/Linux：Button-3，macOS 常见是 Button-2
        tree.bind("<Button-3>", self.show_context_menu)
        tree.bind("<Button-2>", self.show_context_menu)

    def show_context_menu(self, event):
        """右键时：如果点到某行且该行不在选中集合里，就自动选中它"""
        tree = event.widget
        row_id = tree.identify_row(event.y)

        if row_id:
            selected = tree.selection()
            # 右键点未选中行：清空旧选择，选中该行
            if row_id not in selected:
                tree.selection_set((row_id,))
            tree.focus(row_id)

        menu = self.context_menus.get(tree)
        if not menu:
            return

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ---------------- 解析与加载 ----------------

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="选择qscan扫描结果文件",
            filetypes=[
                ("所有支持的文件", "*.json *.txt *.csv"),
                ("JSON文件", "*.json"),
                ("文本文件", "*.txt"),
                ("CSV文件", "*.csv"),
                ("所有文件", "*.*"),
            ],
        )
        if not file_path:
            return

        try:
            file_type = self.file_type_var.get().lower()
            if file_type == "auto":
                if file_path.lower().endswith(".json"):
                    file_type = "json"
                elif file_path.lower().endswith(".csv"):
                    file_type = "csv"
                else:
                    file_type = "txt"

            # qscan 的 json/csv 常见也是“文本行”格式，所以统一走 txt 解析
            self.scan_results = self.parse_txt_file(file_path)
            self.filtered_results = list(self.scan_results)

            self.display_data()
            
            # 更新统计信息
            self.update_statistics(file_path)

            messagebox.showinfo(
                "成功",
                f"成功加载 {len(self.scan_results)} 条扫描结果，其中弱口令结果 {len(self.crack_results)} 条，未授权访问结果 {len(self.unauth_results)} 条",
            )
        except Exception as e:
            messagebox.showerror("错误", f"加载文件时出错: {str(e)}")

    def update_statistics(self, file_path):
        """更新统计信息显示"""
        # 计算各种统计数据
        total_records = len(self.scan_results)
        unique_hosts = set()
        
        # 计算唯一Host:Port数量
        for result in self.scan_results:
            url = result.get("URL", "")
            if url:
                # 提取IP和端口
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", url)
                port_match = re.search(r":(\d{1,5})(?:/|$)", url)
                
                if ip_match:
                    ip = ip_match.group(1)
                    port = port_match.group(1) if port_match else "80"  # 默认端口
                    unique_hosts.add(f"{ip}:{port}")
        
        # 计算Web数量 (http/https)
        web_count = 0
        for result in self.scan_results:
            service = result.get("服务", "").lower()
            if service in ["http", "https"]:
                web_count += 1
        
        # 弱口令数量
        crack_count = len(self.crack_results)
        
        # 未授权访问数量
        unauth_count = len(self.unauth_results)
        
        # 获取文件名
        import os
        filename = os.path.basename(file_path)
        
        # 更新统计信息标签
        stats_text = f"导入的文件名称: {filename} | 记录: {total_records} | 唯一Host:Port: {len(unique_hosts)} | Web: {web_count} | 弱口令: {crack_count} | 未授权: {unauth_count}"
        self.stats_label.config(text=stats_text)

    def parse_txt_file(self, file_path):
        results = []
        self.crack_results = []

        # 尝试 utf-8；失败再回退
        encodings = ["utf-8", "utf-8-sig", "gbk", "latin-1"]
        f = None
        for enc in encodings:
            try:
                f = open(file_path, "r", encoding=enc, errors="strict")
                f.read(1)
                f.seek(0)
                break
            except Exception:
                if f:
                    f.close()
                f = None

        if not f:
            # 最后兜底：忽略错误
            f = open(file_path, "r", encoding="utf-8", errors="ignore")

        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                result = {}

                # URL 提取：匹配 "xxx://..." 或 "http(s)://..."
                url_match = re.match(r"^(\S+)", line)
                if url_match:
                    full_url = url_match.group(1)
                    result["URL"] = full_url

                    # 协议
                    proto = ""
                    m1 = re.match(r"^([^:]+)://", full_url)
                    if m1:
                        proto = m1.group(1)
                    else:
                        m2 = re.match(r"^([^:]+):", full_url)  # 兼容 oracle:// 或 oracle:...
                        if m2:
                            proto = m2.group(1)
                    if proto:
                        result["服务"] = proto

                    # 端口
                    pm = re.search(r":(\d{1,5})(?:/|$)", full_url)
                    if pm:
                        result["端口"] = pm.group(1)

                # IP
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    result["IP"] = ip_match.group(1)

                # 关键词：按空白分隔后第二段
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    result["关键词"] = parts[1]

                # 弱口令检测
                if "CrackSuccess" in line or "crack" in line.lower():
                    crack_info = self.extract_crack_info(line, result.get("URL", ""))
                    if crack_info:
                        self.crack_results.append(crack_info)

                # 未授权访问检测
                if "unauthorized" in line.lower():
                    unauth_info = self.extract_unauth_info(line, result.get("URL", ""))
                    if unauth_info:
                        self.unauth_results.append(unauth_info)

                # key:value 提取
                remaining = line
                if len(parts) >= 1:
                    remaining = remaining[len(parts[0]):].lstrip()
                if len(parts) >= 2:
                    if remaining.startswith(parts[1]):
                        remaining = remaining[len(parts[1]):].lstrip()

                kv_pairs = re.findall(r"(\w+):([^,]+?)(?=\s*,|$)", remaining)
                for key, value in kv_pairs:
                    result[key] = value.strip().rstrip(",")

                self.enhance_result_info(result)

                if result:
                    results.append(result)

        return results

    def enhance_result_info(self, result):
        # 产品
        if result.get("ProductName"):
            product_name = result["ProductName"]
            if "crosoft" in product_name:
                product_name = product_name.replace("crosoft", "Microsoft ")
            result["产品"] = product_name
        elif result.get("Hostname"):
            result["产品"] = result["Hostname"]
        elif result.get("OperatingSystem"):
            result["产品"] = result["OperatingSystem"]
        else:
            result["产品"] = result.get("服务", "Unknown")

        # 版本
        if not result.get("Version") and result.get("OperatingSystem"):
            result["版本"] = result.get("OperatingSystem", "")
        else:
            result["版本"] = result.get("Version", result.get("OperatingSystem", ""))

        # 操作系统
        if result.get("OperatingSystem"):
            result["操作系统"] = result["OperatingSystem"]
        else:
            pn = result.get("ProductName", "")
            if "Windows" in pn:
                result["操作系统"] = "Windows"
            elif "Linux" in pn:
                result["操作系统"] = "Linux"
            else:
                result["操作系统"] = ""

        # FingerPrint 提版本
        if result.get("FingerPrint") and not result.get("Version"):
            fp = result["FingerPrint"]
            vm = re.search(r"/(\d+(?:\.\d+)*)", fp)
            if vm:
                result["Version"] = vm.group(1)
                if not result.get("版本"):
                    result["版本"] = vm.group(1)

        # 摘要
        if result.get("Digest"):
            result["摘要"] = result["Digest"]

        # 长度
        if result.get("Length"):
            result["长度"] = result["Length"]

    def extract_crack_info(self, line, url):
        crack_info = {"URL": url, "IP": "", "端口": "", "服务": "", "用户名": "", "密码": "", "其他信息": "", "发现时间": ""}

        # 从URL中提取IP和端口
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", url)
        if ip_match:
            crack_info["IP"] = ip_match.group(1)
        
        port_match = re.search(r":(\d{1,5})(?:/|$)", url)
        if port_match:
            crack_info["端口"] = port_match.group(1)

        # 如果URL中没有提取到IP，尝试从整行中提取
        if not crack_info["IP"]:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                crack_info["IP"] = ip_match.group(1)
        
        # 如果URL中没有提取到端口，尝试从整行中提取
        if not crack_info["端口"]:
            port_match = re.search(r":(\d{1,5})(?:\s|$|,)", line)
            if port_match:
                crack_info["端口"] = port_match.group(1)

        first = line.split()[0] if line.split() else ""
        m = re.match(r"^([^:]+)://", first)
        if m:
            crack_info["服务"] = m.group(1)
        else:
            m2 = re.match(r"^([^:]+):", first)
            if m2:
                crack_info["服务"] = m2.group(1)

        username_patterns = [r"Username:([^,]+)", r"User:([^,]+)", r"user:([^,]+)", r"username:([^,]+)"]
        password_patterns = [r"Password:([^,]+)", r"Pass:([^,]+)", r"password:([^,]+)", r"pass:([^,]+)"]

        for p in username_patterns:
            mm = re.search(p, line)
            if mm:
                crack_info["用户名"] = mm.group(1).strip()
                break

        for p in password_patterns:
            mm = re.search(p, line)
            if mm:
                crack_info["密码"] = mm.group(1).strip()
                break

        other_patterns = [
            r"SID:([^,]+)",
            r"DB:([^,]+)",
            r"db:([^,]+)",
            r"sid:([^,]+)",
            r"Name:([^,]+)",
            r"name:([^,]+)",
        ]
        other_info = []
        for p in other_patterns:
            mm = re.search(p, line)
            if mm:
                key = p.split(":")[0].upper()
                other_info.append(f"{key}:{mm.group(1).strip()}")
        if other_info:
            crack_info["其他信息"] = "; ".join(other_info)

        return crack_info

    def extract_unauth_info(self, line, url):
        unauth_info = {"URL": url, "IP": "", "端口": "", "服务": "", "发现时间": "", "详细信息": ""}

        # 从URL中提取IP和端口
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", url)
        if ip_match:
            unauth_info["IP"] = ip_match.group(1)
        
        port_match = re.search(r":(\d{1,5})(?:/|$)", url)
        if port_match:
            unauth_info["端口"] = port_match.group(1)

        # 如果URL中没有提取到IP，尝试从整行中提取
        if not unauth_info["IP"]:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                unauth_info["IP"] = ip_match.group(1)
        
        # 如果URL中没有提取到端口，尝试从整行中提取
        if not unauth_info["端口"]:
            port_match = re.search(r":(\d{1,5})(?:\s|$|,)", line)
            if port_match:
                unauth_info["端口"] = port_match.group(1)

        # 从第一部分提取服务类型
        first = line.split()[0] if line.split() else ""
        m = re.match(r"^([^:]+)://", first)
        if m:
            unauth_info["服务"] = m.group(1)
        else:
            m2 = re.match(r"^([^:]+):", first)  # 兼容 mysql:... 格式
            if m2:
                unauth_info["服务"] = m2.group(1)

        # 提取详细信息，包含unauthorized相关的描述
        if "unauthorized" in line.lower():
            # 查找包含unauthorized的详细信息
            # 提取Info, Digest, Length等信息
            info_match = re.search(r'Info:([^,]+)', line)
            if info_match:
                unauth_info["详细信息"] = info_match.group(1).strip()
            else:
                # 如果没有Info字段，尝试从整行提取关键信息
                # 提取所有key:value对
                kv_pairs = re.findall(r"(\w+):([^,]+?)(?=\s*,|$)", line)
                details = []
                for key, value in kv_pairs:
                    if key.lower() != 'info':  # 避免重复
                        details.append(f"{key}:{value.strip().rstrip(',')}")
                if details:
                    unauth_info["详细信息"] = ", ".join(details)

        return unauth_info

    # ---------------- 显示与过滤 ----------------

    def filter_data(self):
        search_term = self.search_var.get().lower().strip()
        service_filter = self.service_var.get().lower().strip()

        filtered = []
        for result in self.scan_results:
            ok_search = True
            if search_term:
                ok_search = any(search_term in str(v).lower() for v in result.values())

            ok_service = True
            if service_filter != "all":
                svc = (result.get("服务") or result.get("Service") or "").lower()
                ok_service = (svc == service_filter)

            if ok_search and ok_service:
                filtered.append(result)

        self.filtered_results = filtered
        self.display_data()

    def display_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.crack_tree.get_children():
            self.crack_tree.delete(item)
        for item in self.unauth_tree.get_children():
            self.unauth_tree.delete(item)

        self._overview_iid_map.clear()
        self._crack_iid_map.clear()
        self._unauth_iid_map.clear()

        for idx, result in enumerate(self.filtered_results):
            iid = f"o{idx}"
            row_values = []
            for col in self.OVERVIEW_COLUMNS:
                val = self.get_value(result, col)
                if col == "URL":
                    val = self.format_url(val)
                shown = (val[:50] + "...") if len(val) > 50 else val
                row_values.append(shown)

            self.tree.insert("", "end", iid=iid, values=row_values)
            self._overview_iid_map[iid] = result

        for idx, result in enumerate(self.crack_results):
            iid = f"c{idx}"
            row_values = []
            for col in self.CRACK_COLUMNS:
                val = self.get_value(result, col)
                if col == "URL":
                    val = self.format_url(val)
                shown = (val[:50] + "...") if len(val) > 50 else val
                row_values.append(shown)

            self.crack_tree.insert("", "end", iid=iid, values=row_values)
            self._crack_iid_map[iid] = result

        for idx, result in enumerate(self.unauth_results):
            iid = f"u{idx}"
            row_values = []
            for col in self.UNAUTH_COLUMNS:
                val = self.get_value(result, col)
                if col == "URL":
                    val = self.format_url(val)
                shown = (val[:50] + "...") if len(val) > 50 else val
                row_values.append(shown)

            self.unauth_tree.insert("", "end", iid=iid, values=row_values)
            self._unauth_iid_map[iid] = result

    # ---------------- 导出 ----------------

    def export_to_csv(self):
        if not self.scan_results:
            messagebox.showwarning("警告", "没有数据可导出")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存CSV文件",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=list(self.OVERVIEW_COLUMNS))
                writer.writeheader()
                for r in self.scan_results:
                    row = {}
                    for col in self.OVERVIEW_COLUMNS:
                        val = self.get_value(r, col)
                        if col == "URL":
                            val = self.format_url(val)
                        row[col] = val
                    writer.writerow(row)
            messagebox.showinfo("成功", f"数据已导出到 {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")

    def export_crack_to_csv(self):
        if not self.crack_results:
            messagebox.showwarning("警告", "没有弱口令数据可导出")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存弱口令CSV文件",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=list(self.CRACK_COLUMNS))
                writer.writeheader()
                for r in self.crack_results:
                    row = {}
                    for col in self.CRACK_COLUMNS:
                        val = self.get_value(r, col)
                        if col == "URL":
                            val = self.format_url(val)
                        row[col] = val
                    writer.writerow(row)
            messagebox.showinfo("成功", f"弱口令数据已导出到 {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")

    def export_unauth_to_csv(self):
        if not self.unauth_results:
            messagebox.showwarning("警告", "没有未授权访问数据可导出")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存未授权访问CSV文件",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=list(self.UNAUTH_COLUMNS))
                writer.writeheader()
                for r in self.unauth_results:
                    row = {}
                    for col in self.UNAUTH_COLUMNS:
                        val = self.get_value(r, col)
                        if col == "URL":
                            val = self.format_url(val)
                        row[col] = val
                    writer.writerow(row)
            messagebox.showinfo("成功", f"未授权访问数据已导出到 {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")

    def export_selected_to_csv(self, tree: ttk.Treeview):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择要导出的行")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存选中行CSV文件",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not file_path:
            return

        fieldnames = list(self.OVERVIEW_COLUMNS) if tree == self.tree else list(self.CRACK_COLUMNS)
        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for iid in selected_items:
                    r = iid_map.get(iid)
                    row = {}
                    if r:
                        for col in fieldnames:
                            val = self.get_value(r, col)
                            if col == "URL":
                                val = self.format_url(val)
                            row[col] = val
                    else:
                        values = tree.item(iid, "values")
                        row = {fieldnames[i]: values[i] if i < len(values) else "" for i in range(len(fieldnames))}
                    writer.writerow(row)

            messagebox.showinfo("成功", f"选中行已导出到 {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")

    # ---------------- 复制 ----------------

    def copy_ip(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择行")
            return

        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map

        out = []
        for iid in selected_items:
            r = iid_map.get(iid)
            if r:
                ip = self.get_value(r, "IP")
                if ip:
                    out.append(ip)

        if out:
            self.copy_to_clipboard("\n".join(out))
            messagebox.showinfo("成功", f"已复制 {len(out)} 个IP到剪贴板")

    def copy_port(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择行")
            return

        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map

        out = []
        for iid in selected_items:
            r = iid_map.get(iid)
            if r:
                port = self.get_value(r, "端口")
                if port:
                    out.append(port)

        if out:
            self.copy_to_clipboard("\n".join(out))
            messagebox.showinfo("成功", f"已复制 {len(out)} 个端口到剪贴板")

    def copy_url(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择行")
            return

        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map
        out = []
        for iid in selected_items:
            r = iid_map.get(iid)
            if r:
                url = self.format_url(self.get_value(r, "URL"))
                if url:
                    out.append(url)

        if out:
            self.copy_to_clipboard("\n".join(out))
            messagebox.showinfo("成功", f"已复制 {len(out)} 个URL到剪贴板")

    def copy_ip_port(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择行")
            return

        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map

        out = []
        for iid in selected_items:
            r = iid_map.get(iid)
            if not r:
                continue
            ip = self.get_value(r, "IP")
            port = self.get_value(r, "端口")
            if ip and port:
                out.append(f"{ip}:{port}")
            elif ip:
                out.append(ip)

        if out:
            self.copy_to_clipboard("\n".join(out))
            messagebox.showinfo("成功", f"已复制 {len(out)} 个IP+端口到剪贴板")

    def copy_row(self, tree):
        selected_items = tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择行")
            return

        columns = self.OVERVIEW_COLUMNS if tree == self.tree else self.CRACK_COLUMNS
        iid_map = self._overview_iid_map if tree == self.tree else self._crack_iid_map

        lines = []
        for iid in selected_items:
            r = iid_map.get(iid)
            if r:
                vals = []
                for col in columns:
                    val = self.get_value(r, col)
                    if col == "URL":
                        val = self.format_url(val)
                    vals.append(val)
                lines.append("\t".join(vals))
            else:
                values = tree.item(iid, "values")
                lines.append("\t".join(str(v) for v in values))

        self.copy_to_clipboard("\n".join(lines))
        messagebox.showinfo("成功", f"已复制 {len(lines)} 行数据到剪贴板")

    def select_all(self, tree):
        children = tree.get_children()
        if children:
            tree.selection_set(children)
            tree.focus(children[0])

    def copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    # ---------------- 工具函数 ----------------

    def get_value(self, d: dict, key: str) -> str:
        if not d:
            return ""
        candidates = [key, key.lower(), key.upper(), key.capitalize(), key.title()]
        for k in candidates:
            if k in d and d.get(k) is not None:
                return str(d.get(k))
        return ""

    def format_url(self, url: str) -> str:
        if not url:
            return ""
        url = str(url)

        if url.startswith("http://") or url.startswith("https://"):
            return url

        ip_port_pattern = r"(\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?)"
        match = re.search(ip_port_pattern, url)
        if match:
            ip_port = match.group(1)
            if "https://" in url:
                return f"https://{ip_port}"
            if "http://" in url:
                return f"http://{ip_port}"
            return ip_port

        return url

    def autosize_all_columns(self):
        self.autosize_columns(self.tree, max_rows=200, max_width=520)
        self.autosize_columns(self.crack_tree, max_rows=200, max_width=520)

    def autosize_columns(self, tree: ttk.Treeview, max_rows=200, max_width=520):
        cols = tree["columns"]
        sample_iids = tree.get_children()[:max_rows]

        for col_idx, col in enumerate(cols):
            best = len(col)
            for iid in sample_iids:
                vals = tree.item(iid, "values")
                if col_idx < len(vals):
                    best = max(best, len(str(vals[col_idx])))

            width = min(max_width, best * 9 + 30)
            tree.column(col, width=width, stretch=False)  # 保持水平滚动条有效


def main():
    root = tk.Tk()
    app = QscanParserGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
