import threading
from pathlib import Path
from queue import Empty, Queue
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.pcap_reader import PcapReadError, read_pcap_summary


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PcapAnalyzerApp(ctk.CTk):
    BACKGROUND = "#070B14"
    SIDEBAR = "#0D1424"
    PANEL = "#111A2E"
    PANEL_HOVER = "#17233B"
    BORDER = "#243454"
    PRIMARY = "#2563EB"
    PRIMARY_HOVER = "#1D4ED8"
    TEXT = "#F1F5F9"
    MUTED = "#94A3B8"
    SUCCESS = "#22C55E"

    def __init__(self):
        super().__init__()

        self.selected_file = None
        self.analysis_queue = Queue()
        self.stat_values = {}

        self.title("PCAP Security Analyzer")
        self.geometry("1200x760")
        self.minsize(1050, 680)
        self.configure(fg_color=self.BACKGROUND)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._configure_table_style()
        self._build_sidebar()
        self._build_main_content()

    def _configure_table_style(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Analyzer.Treeview",
            background=self.PANEL,
            foreground=self.TEXT,
            fieldbackground=self.PANEL,
            borderwidth=0,
            rowheight=38,
            font=("Segoe UI", 11),
        )

        style.configure(
            "Analyzer.Treeview.Heading",
            background="#16213A",
            foreground=self.TEXT,
            borderwidth=0,
            font=("Segoe UI Semibold", 11),
        )

        style.map(
            "Analyzer.Treeview",
            background=[("selected", self.PRIMARY)],
            foreground=[("selected", "#FFFFFF")],
        )

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(
            self,
            width=260,
            corner_radius=0,
            fg_color=self.SIDEBAR,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(8, weight=1)

        logo = ctk.CTkLabel(
            sidebar,
            text="PCAP\nSECURITY ANALYZER",
            justify="left",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=23,
                weight="bold",
            ),
            text_color=self.TEXT,
        )
        logo.grid(row=0, column=0, padx=25, pady=(32, 8), sticky="w")

        subtitle = ctk.CTkLabel(
            sidebar,
            text="Offline Network Forensics",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=self.MUTED,
        )
        subtitle.grid(row=1, column=0, padx=25, pady=(0, 28), sticky="w")

        section_label = ctk.CTkLabel(
            sidebar,
            text="ANALİZ DOSYASI",
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            text_color="#64748B",
        )
        section_label.grid(row=2, column=0, padx=25, pady=(0, 10), sticky="w")

        self.select_button = ctk.CTkButton(
            sidebar,
            text="PCAP Dosyası Seç",
            height=45,
            corner_radius=9,
            fg_color=self.PRIMARY,
            hover_color=self.PRIMARY_HOVER,
            font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
            command=self.select_file,
        )
        self.select_button.grid(
            row=3,
            column=0,
            padx=22,
            pady=(0, 12),
            sticky="ew",
        )

        self.analyze_button = ctk.CTkButton(
            sidebar,
            text="Analizi Başlat",
            height=45,
            corner_radius=9,
            fg_color="#17233B",
            hover_color="#223354",
            border_width=1,
            border_color=self.BORDER,
            font=ctk.CTkFont("Segoe UI", 13, weight="bold"),
            state="disabled",
            command=self.start_analysis,
        )
        self.analyze_button.grid(
            row=4,
            column=0,
            padx=22,
            pady=(0, 22),
            sticky="ew",
        )

        self.progress = ctk.CTkProgressBar(
            sidebar,
            width=210,
            height=8,
            mode="indeterminate",
            progress_color=self.PRIMARY,
            fg_color="#172033",
        )
        self.progress.grid(row=5, column=0, padx=25, pady=(0, 12), sticky="ew")
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(
            sidebar,
            text="Dosya seçilmesi bekleniyor",
            wraplength=205,
            justify="left",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=self.MUTED,
        )
        self.status_label.grid(row=6, column=0, padx=25, sticky="w")

        divider = ctk.CTkFrame(sidebar, height=1, fg_color=self.BORDER)
        divider.grid(row=7, column=0, padx=22, pady=22, sticky="ew")

        version = ctk.CTkLabel(
            sidebar,
            text="Version 1.0 • Offline Analysis",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color="#52617A",
        )
        version.grid(row=9, column=0, padx=25, pady=24, sticky="sw")

    def _build_main_content(self):
        content = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=self.BACKGROUND,
        )
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(content, fg_color="transparent")
        header.grid(
            row=0,
            column=0,
            padx=32,
            pady=(28, 18),
            sticky="ew",
        )
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="Güvenlik Analizi",
            font=ctk.CTkFont("Segoe UI", 28, weight="bold"),
            text_color=self.TEXT,
        )
        title.grid(row=0, column=0, sticky="w")

        description = ctk.CTkLabel(
            header,
            text="PCAP ve PCAPNG dosyalarındaki ağ trafiğini çevrimdışı inceleyin.",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=self.MUTED,
        )
        description.grid(row=1, column=0, pady=(4, 0), sticky="w")

        file_panel = ctk.CTkFrame(
            content,
            height=82,
            corner_radius=12,
            fg_color=self.PANEL,
            border_width=1,
            border_color=self.BORDER,
        )
        file_panel.grid(
            row=1,
            column=0,
            padx=32,
            pady=(0, 18),
            sticky="ew",
        )
        file_panel.grid_columnconfigure(0, weight=1)

        self.file_name_label = ctk.CTkLabel(
            file_panel,
            text="Henüz bir dosya seçilmedi",
            font=ctk.CTkFont("Segoe UI", 15, weight="bold"),
            text_color=self.TEXT,
        )
        self.file_name_label.grid(
            row=0,
            column=0,
            padx=20,
            pady=(15, 2),
            sticky="w",
        )

        self.file_path_label = ctk.CTkLabel(
            file_panel,
            text="Desteklenen biçimler: .pcap ve .pcapng",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=self.MUTED,
        )
        self.file_path_label.grid(
            row=1,
            column=0,
            padx=20,
            pady=(0, 15),
            sticky="w",
        )

        cards_frame = ctk.CTkFrame(content, fg_color="transparent")
        cards_frame.grid(
            row=2,
            column=0,
            padx=32,
            pady=(0, 18),
            sticky="ew",
        )

        for column in range(4):
            cards_frame.grid_columnconfigure(column, weight=1)

        card_data = [
            ("total_packets", "TOPLAM PAKET"),
            ("capture_duration", "YAKALAMA SÜRESİ"),
            ("packets_per_second", "PAKET / SANİYE"),
            ("traffic_type", "TRAFİK TÜRÜ"),
        ]

        for column, (key, title_text) in enumerate(card_data):
            card = ctk.CTkFrame(
                cards_frame,
                height=110,
                corner_radius=12,
                fg_color=self.PANEL,
                border_width=1,
                border_color=self.BORDER,
            )
            card.grid(
                row=0,
                column=column,
                padx=(0 if column == 0 else 6, 0 if column == 3 else 6),
                sticky="ew",
            )
            card.grid_propagate(False)

            title_label = ctk.CTkLabel(
                card,
                text=title_text,
                font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
                text_color=self.MUTED,
            )
            title_label.pack(anchor="w", padx=18, pady=(18, 5))

            value_label = ctk.CTkLabel(
                card,
                text="—",
                font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
                text_color=self.TEXT,
            )
            value_label.pack(anchor="w", padx=18)

            self.stat_values[key] = value_label

        self.tabs = ctk.CTkTabview(
            content,
            corner_radius=12,
            fg_color=self.PANEL,
            segmented_button_fg_color="#111A2E",
            segmented_button_selected_color=self.PRIMARY,
            segmented_button_selected_hover_color=self.PRIMARY_HOVER,
            segmented_button_unselected_color="#17233B",
            segmented_button_unselected_hover_color="#223354",
        )
        self.tabs.grid(
            row=3,
            column=0,
            padx=32,
            pady=(0, 30),
            sticky="nsew",
        )

        overview_tab = self.tabs.add("Genel Bakış")
        protocol_tab = self.tabs.add("Protokoller")
        detection_tab = self.tabs.add("Saldırı Tespitleri")

        overview_tab.grid_rowconfigure(0, weight=1)
        overview_tab.grid_columnconfigure(0, weight=1)

        self.summary_box = ctk.CTkTextbox(
            overview_tab,
            corner_radius=8,
            fg_color="#0C1322",
            border_width=1,
            border_color=self.BORDER,
            font=ctk.CTkFont("Consolas", 13),
            text_color="#D9E6F7",
        )
        self.summary_box.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")
        self._set_summary_text(
            "Bir PCAP dosyası seçip analizi başlatın.\n\n"
            "Analiz işlemi yalnızca dosya üzerinde gerçekleştirilir. "
            "Canlı ağ trafiğine müdahale edilmez."
        )

        protocol_tab.grid_rowconfigure(0, weight=1)
        protocol_tab.grid_columnconfigure(0, weight=1)

        table_container = ctk.CTkFrame(
            protocol_tab,
            fg_color="#0C1322",
            corner_radius=8,
        )
        table_container.grid(
            row=0,
            column=0,
            padx=12,
            pady=12,
            sticky="nsew",
        )
        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        self.protocol_table = ttk.Treeview(
            table_container,
            columns=("protocol", "count", "percentage"),
            show="headings",
            style="Analyzer.Treeview",
        )

        self.protocol_table.heading("protocol", text="Protokol / Katman")
        self.protocol_table.heading("count", text="Paket Sayısı")
        self.protocol_table.heading("percentage", text="Toplam İçindeki Oran")

        self.protocol_table.column("protocol", width=240, anchor="w")
        self.protocol_table.column("count", width=160, anchor="center")
        self.protocol_table.column("percentage", width=190, anchor="center")

        self.protocol_table.grid(
            row=0,
            column=0,
            padx=6,
            pady=6,
            sticky="nsew",
        )

        detection_tab.grid_rowconfigure(0, weight=1)
        detection_tab.grid_columnconfigure(0, weight=1)

        self.detection_text = ctk.CTkTextbox(
            detection_tab,
            corner_radius=8,
            fg_color="#0C1322",
            border_width=1,
            border_color=self.BORDER,
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=self.MUTED,
        )
        self.detection_text.grid(
            row=0,
            column=0,
            padx=12,
            pady=12,
            sticky="nsew",
        )
        self._set_detection_text(
            "Tespit motoru henüz çalıştırılmadı.\n\n"
            "Sonraki aşamada saldırı kuralları bu bölüme bağlanacak."
        )

    def select_file(self):
        file_path = filedialog.askopenfilename(
            parent=self,
            title="Analiz edilecek PCAP dosyasını seçin",
            filetypes=[
                ("PCAP dosyaları", "*.pcap *.pcapng"),
                ("Tüm dosyalar", "*.*"),
            ],
        )

        if not file_path:
            return

        self.selected_file = file_path
        path = Path(file_path)

        self.file_name_label.configure(text=path.name)
        self.file_path_label.configure(text=str(path))
        self.status_label.configure(
            text="Dosya hazır. Analizi başlatabilirsiniz.",
            text_color=self.SUCCESS,
        )
        self.analyze_button.configure(state="normal")

        self._reset_results()

    def start_analysis(self):
        if not self.selected_file:
            messagebox.showwarning(
                "Dosya seçilmedi",
                "Lütfen önce bir PCAP dosyası seçin.",
                parent=self,
            )
            return

        self.select_button.configure(state="disabled")
        self.analyze_button.configure(state="disabled")
        self.status_label.configure(
            text="PCAP analiz ediliyor...",
            text_color="#60A5FA",
        )
        self.progress.start()

        worker = threading.Thread(
            target=self._analysis_worker,
            daemon=True,
        )
        worker.start()

        self.after(100, self._poll_analysis_queue)

    def _analysis_worker(self):
        try:
            summary = read_pcap_summary(self.selected_file)
            self.analysis_queue.put(("success", summary))
        except Exception as error:
            self.analysis_queue.put(("error", error))

    def _poll_analysis_queue(self):
        try:
            result_type, result = self.analysis_queue.get_nowait()
        except Empty:
            self.after(100, self._poll_analysis_queue)
            return

        self.progress.stop()
        self.progress.set(0)
        self.select_button.configure(state="normal")
        self.analyze_button.configure(state="normal")

        if result_type == "success":
            self._display_summary(result)
        else:
            self._display_error(result)

    def _display_summary(self, summary):
        traffic_type = "802.11 / Wi-Fi"

        if summary["wifi_frames"] == 0 and summary["ipv4"] > 0:
            traffic_type = "Ethernet / IP"
        elif summary["wifi_frames"] == 0 and summary["ipv4"] == 0:
            traffic_type = "Bilinmiyor"

        self.stat_values["total_packets"].configure(
            text=f"{summary['total_packets']:,}".replace(",", ".")
        )
        self.stat_values["capture_duration"].configure(
            text=f"{summary['capture_duration']:.2f} sn"
        )
        self.stat_values["packets_per_second"].configure(
            text=f"{summary['packets_per_second']:.2f}"
        )
        self.stat_values["traffic_type"].configure(text=traffic_type)

        summary_text = (
            "ANALİZ DURUMU\n"
            "────────────────────────────────────────\n"
            "PCAP dosyası başarıyla okundu.\n\n"
            f"Dosya adı       : {summary['file_name']}\n"
            f"Dosya boyutu    : {summary['file_size_mb']} MB\n"
            f"Toplam paket    : {summary['total_packets']}\n"
            f"Yakalama süresi : {summary['capture_duration']} saniye\n"
            f"Paket yoğunluğu : {summary['packets_per_second']} paket/saniye\n"
            f"Trafik türü     : {traffic_type}\n\n"
            "Bu aşamada temel trafik yapısı çıkarılmıştır. "
            "Saldırı tespit motoru sonraki aşamada bu verilerle birlikte çalışacaktır."
        )
        self._set_summary_text(summary_text)

        protocols = [
            ("Wi-Fi / 802.11", summary["wifi_frames"]),
            ("Radiotap", summary["radiotap"]),
            ("EAPOL", summary["eapol"]),
            ("IPv4", summary["ipv4"]),
            ("TCP", summary["tcp"]),
            ("UDP", summary["udp"]),
            ("ICMP", summary["icmp"]),
            ("ARP", summary["arp"]),
        ]

        for item in self.protocol_table.get_children():
            self.protocol_table.delete(item)

        total = summary["total_packets"]

        for protocol, count in protocols:
            percentage = (count / total * 100) if total else 0

            self.protocol_table.insert(
                "",
                "end",
                values=(
                    protocol,
                    f"{count:,}".replace(",", "."),
                    f"%{percentage:.2f}",
                ),
            )

        self.status_label.configure(
            text="Analiz başarıyla tamamlandı.",
            text_color=self.SUCCESS,
        )

        self._set_detection_text(
            "TEMEL ANALİZ TAMAMLANDI\n\n"
            "Dosya başarıyla işlendi. Saldırı tespit motoru henüz eklenmedi.\n\n"
            "Bir sonraki aşamada sonuçlar burada saldırı türü, risk seviyesi, "
            "kaynak, hedef ve teknik kanıtlarla gösterilecek."
        )

    def _display_error(self, error):
        self.status_label.configure(
            text="Analiz sırasında hata oluştu.",
            text_color="#F87171",
        )

        if isinstance(error, PcapReadError):
            error_message = str(error)
        else:
            error_message = f"Beklenmeyen hata: {error}"

        messagebox.showerror(
            "Analiz hatası",
            error_message,
            parent=self,
        )

    def _reset_results(self):
        for value_label in self.stat_values.values():
            value_label.configure(text="—")

        for item in self.protocol_table.get_children():
            self.protocol_table.delete(item)

        self._set_summary_text(
            "Dosya seçildi.\n\n"
            "Analizi başlatmak için sol menüdeki “Analizi Başlat” düğmesine basın."
        )

        self._set_detection_text(
            "Seçilen dosya henüz analiz edilmedi."
        )

    def _set_summary_text(self, text):
        self.summary_box.configure(state="normal")
        self.summary_box.delete("1.0", "end")
        self.summary_box.insert("1.0", text)
        self.summary_box.configure(state="disabled")

    def _set_detection_text(self, text):
        self.detection_text.configure(state="normal")
        self.detection_text.delete("1.0", "end")
        self.detection_text.insert("1.0", text)
        self.detection_text.configure(state="disabled")


if __name__ == "__main__":
    app = PcapAnalyzerApp()
    app.mainloop()