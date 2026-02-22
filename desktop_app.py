import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
import asyncio
import json
import sys
import os
import queue
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.crawler_async import AsyncWebCrawler
from modules.scanner import VulnerabilityScanner
from core.ai_classifier import VulnerabilityClassifier

class DesktopApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HexStrike AI - فحص الثغرات")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # متغيرات
        self.scanning = False
        self.result_queue = queue.Queue()
        
        # إطار الإدخال
        input_frame = ttk.LabelFrame(root, text="إعدادات الفحص", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="الرابط:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.url_entry = ttk.Entry(input_frame, width=70)
        self.url_entry.grid(row=0, column=1, padx=5, pady=2)
        self.url_entry.insert(0, "http://testphp.vulnweb.com")
        
        ttk.Label(input_frame, text="عدد الصفحات:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.pages_entry = ttk.Entry(input_frame, width=10)
        self.pages_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        self.pages_entry.insert(0, "5")
        
        self.scan_button = ttk.Button(input_frame, text="بدء الفحص", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # شريط التقدم
        self.progress = ttk.Progressbar(root, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # منطقة عرض النتائج
        result_frame = ttk.LabelFrame(root, text="النتائج", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.WORD, width=100, height=25,
            font=("Consolas", 10)
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # إطار الأزرار السفلية
        button_frame = ttk.Frame(root)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.save_button = ttk.Button(button_frame, text="حفظ التقرير", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="مسح النتائج", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        # تحميل النموذج الذكي
        self.classifier = VulnerabilityClassifier()
        try:
            self.classifier.load_model()
            self.log_message("✓ تم تحميل النموذج الذكي بنجاح", "info")
        except:
            self.log_message("⚠ لم يتم العثور على نموذج ذكي، سيتم الفحص بدون تصنيف", "warning")
        
        # بدء معالجة قائمة الانتظار
        self.process_queue()
    
    def log_message(self, message, tag="info"):
        """إدراج رسالة في منطقة النتائج مع تنسيق"""
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)
    
    def start_scan(self):
        if self.scanning:
            return
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("خطأ", "الرجاء إدخال رابط")
            return
        
        try:
            max_pages = int(self.pages_entry.get().strip())
        except ValueError:
            messagebox.showerror("خطأ", "عدد الصفحات يجب أن يكون رقماً")
            return
        
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.progress.start()
        self.clear_results()
        self.log_message(f"🔍 بدء فحص {url} ...")
        
        # تشغيل الفحص في خيط منفصل
        threading.Thread(target=self.run_scan, args=(url, max_pages), daemon=True).start()
    
    def run_scan(self, url, max_pages):
        """تنفيذ الفحص (يعمل في خيط منفصل)"""
        try:
            # إعداد headers
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            # زحف
            async def crawl():
                crawler = AsyncWebCrawler(
                    url, max_pages=max_pages, headers=headers,
                    delay=1, max_concurrent=3
                )
                return await crawler.crawl()
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            crawl_results = loop.run_until_complete(crawl())
            loop.close()
            
            self.result_queue.put(("log", f"✓ تم العثور على {len(crawl_results['forms'])} نموذج."))
            
            if not crawl_results['forms']:
                self.result_queue.put(("log", "⚠ لا توجد نماذج للفحص."))
                self.result_queue.put(("done", None))
                return
            
            # فحص الثغرات
            scanner = VulnerabilityScanner(
                crawl_results['forms'], base_url=url,
                headers=headers, delay=0.5
            )
            vulns = scanner.scan_all()
            
            if vulns:
                self.result_queue.put(("log", f"⚠ تم العثور على {len(vulns)} ثغرة محتملة:"))
                
                # تصنيف ذكي
                for v in vulns:
                    try:
                        prob = self.classifier.predict(v['form'])
                        v['ai_probability'] = round(prob, 2)
                    except:
                        v['ai_probability'] = 'N/A'
                    
                    # عرض تفصيلي
                    self.result_queue.put(("vuln", v))
                
                # حفظ النتائج
                filename = scanner.save_results()
                self.result_queue.put(("log", f"📁 تم حفظ النتائج في {filename}"))
                self.result_queue.put(("enable_save", filename))
            else:
                self.result_queue.put(("log", "✅ لم يتم العثور على ثغرات."))
            
        except Exception as e:
            self.result_queue.put(("log", f"❌ خطأ: {str(e)}"))
        finally:
            self.result_queue.put(("done", None))
    
    def process_queue(self):
        """معالجة الرسائل من خيط الفحص"""
        try:
            while True:
                msg = self.result_queue.get_nowait()
                if msg[0] == "log":
                    self.log_message(msg[1])
                elif msg[0] == "vuln":
                    v = msg[1]
                    self.log_message(
                        f"  - {v['vulnerability']} في {v['action']} "
                        f"(الثقة: {v['confidence']}, احتمال AI: {v.get('ai_probability', 'N/A')})",
                        "vuln"
                    )
                elif msg[0] == "enable_save":
                    self.last_report = msg[1]
                    self.save_button.config(state=tk.NORMAL)
                elif msg[0] == "done":
                    self.scanning = False
                    self.progress.stop()
                    self.scan_button.config(state=tk.NORMAL)
                    self.log_message("✓ انتهى الفحص.")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
    
    def save_report(self):
        """حفظ التقرير الحالي إلى ملف نصي"""
        if hasattr(self, 'last_report'):
            try:
                with open(self.last_report, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # حفظ تقرير منسق
                report_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write("تقرير فحص الثغرات - HexStrike AI\n")
                    f.write("="*50 + "\n\n")
                    for v in data:
                        f.write(f"الثغرة: {v['vulnerability']}\n")
                        f.write(f"الرابط: {v['action']}\n")
                        f.write(f"الطريقة: {v['method']}\n")
                        f.write(f"الحمولة: {v.get('payload', 'N/A')}\n")
                        f.write(f"الثقة: {v['confidence']}\n")
                        f.write(f"احتمال AI: {v.get('ai_probability', 'N/A')}\n")
                        f.write("-"*30 + "\n")
                
                messagebox.showinfo("نجاح", f"تم حفظ التقرير في {report_file}")
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل حفظ التقرير: {str(e)}")
    
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = DesktopApp(root)
    root.mainloop()