import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.crawler import WebCrawler
from modules.scanner import VulnerabilityScanner
from core.ai_classifier import VulnerabilityClassifier

class SecurityChatbot:
    def __init__(self, root):
        self.root = root
        self.root.title("HexStrike AI - شات بوت أمني")
        self.root.geometry("700x500")
        
        # منطقة عرض المحادثة
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # إطار الإدخال
        input_frame = tk.Frame(root)
        input_frame.pack(padx=10, pady=5, fill=tk.X)
        
        self.input_field = tk.Entry(input_frame)
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input_field.bind("<Return>", self.send_message)
        
        self.send_button = tk.Button(input_frame, text="إرسال", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        
        # تحميل النموذج الذكي (اختياري)
        self.classifier = VulnerabilityClassifier()
        self.classifier.load_model()
        
        self.display_message("مرحباً بك في HexStrike AI!", "bot")
        self.display_message("اكتب 'help' لعرض الأوامر المتاحة.", "bot")
    
    def display_message(self, message, sender="user"):
        self.chat_area.config(state='normal')
        if sender == "user":
            self.chat_area.insert(tk.END, f"أنت: {message}\n", "user")
        else:
            self.chat_area.insert(tk.END, f"بوت: {message}\n", "bot")
        self.chat_area.see(tk.END)
        self.chat_area.config(state='disabled')
    
    def send_message(self, event=None):
        user_input = self.input_field.get().strip()
        if not user_input:
            return
        self.display_message(user_input, "user")
        self.input_field.delete(0, tk.END)
        
        # معالجة الأمر في خيط منفصل حتى لا تتجمد الواجهة
        threading.Thread(target=self.process_command, args=(user_input,), daemon=True).start()
    
    def process_command(self, command):
        if command.lower() == "help":
            self.display_message("الأوامر المتاحة:\n"
                                 "scan <url> [max_pages] - فحص موقع\n"
                                 "train - تدريب النموذج على البيانات الحالية\n"
                                 "clear - مسح الشاشة\n"
                                 "exit - إنهاء البرنامج", "bot")
        elif command.lower().startswith("scan"):
            parts = command.split()
            if len(parts) < 2:
                self.display_message("يرجى إدخال رابط. مثال: scan http://example.com", "bot")
                return
            url = parts[1]
            max_pages = 5
            if len(parts) > 2:
                try:
                    max_pages = int(parts[2])
                except:
                    pass
            self.display_message(f"جارٍ فحص {url} (الحد الأقصى للصفحات: {max_pages})...", "bot")
            try:
                # زحف
                crawler = WebCrawler(url, max_pages=max_pages, headers={'User-Agent': 'Mozilla/5.0'}, delay=2)
                results = crawler.crawl()
                self.display_message(f"تم العثور على {len(results['forms'])} نموذج.", "bot")
                
                # فحص
                scanner = VulnerabilityScanner(results['forms'], base_url=url, headers={'User-Agent': 'Mozilla/5.0'}, delay=1)
                vulns = scanner.scan_all()
                
                # تصنيف ذكي
                if vulns:
                    for v in vulns:
                        prob = self.classifier.predict(v['form'])
                        v['ai_probability'] = round(prob, 2)
                    self.display_message(f"تم العثور على {len(vulns)} ثغرة:", "bot")
                    for v in vulns:
                        self.display_message(f"- {v['vulnerability']} في {v['action']} (احتمال: {v.get('ai_probability', 'N/A')})", "bot")
                else:
                    self.display_message("لم يتم العثور على ثغرات.", "bot")
                
                # حفظ النتائج
                filename = scanner.save_results()
                self.display_message(f"تم حفظ النتائج في {filename}", "bot")
            except Exception as e:
                self.display_message(f"حدث خطأ: {str(e)}", "bot")
        elif command.lower() == "train":
            self.display_message("بدء تدريب النموذج...", "bot")
            try:
                from core.train_model import load_training_data, train_and_save
                X, y = load_training_data()
                if X:
                    train_and_save(X, y)
                    self.display_message("تم تدريب النموذج بنجاح!", "bot")
                else:
                    self.display_message("لا توجد بيانات تدريب. قم بجمع بيانات أولاً.", "bot")
            except Exception as e:
                self.display_message(f"خطأ في التدريب: {str(e)}", "bot")
        elif command.lower() == "clear":
            self.chat_area.config(state='normal')
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.config(state='disabled')
        elif command.lower() == "exit":
            self.root.quit()
        else:
            self.display_message("أمر غير معروف. اكتب 'help' للمساعدة.", "bot")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityChatbot(root)
    root.mainloop()