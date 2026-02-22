import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import random
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse
from modules.crawler import WebCrawler
from modules.scanner import VulnerabilityScanner

# قائمة بوكلاء مستخدمين عشوائيين لتجنب الحظر
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
]

# قائمة بمواقع حقيقية مع احترام شروط الخدمة
# ملاحظة: Threads يتبع سياسة ميتا، لذا يجب الحذر الشديد. سنضيفه مع تأخير كبير.
TEST_SITES = [
    # مواقع آمنة وتسمح بالزحف
    "https://www.wikipedia.org",
    "https://www.bbc.com",
    "https://www.github.com",
    "https://stackoverflow.com",
    "https://www.reddit.com",        # يسمح بالزحف بشرط احترام robots.txt
    "https://www.quora.com",          # قد يكون مقيداً
    
    # منصات اختبار مرخصة
    "https://pentesterlab.com",       # يتطلب تسجيل دخول لكن يمكن زحف الصفحات العامة
    "https://www.hackthebox.com",     # صفحات عامة
    
    # موقع Threads - تحذير: يتبع ميتا، قد يكون محظوراً. سنستخدمه بحذر شديد.
    "https://www.threads.net",
]

def can_fetch(url, user_agent='*'):
    """التحقق من robots.txt قبل الزحف"""
    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        rp = RobotFileParser()
        rp.set_url(f"{base_url}/robots.txt")
        rp.read()
        return rp.can_fetch(user_agent, url)
    except:
        # إذا تعذر الوصول إلى robots.txt، نفترض عدم السماح احتياطاً
        print(f"⚠️ تعذر الوصول إلى robots.txt لـ {url}، سيتم تخطي الموقع.")
        return False

def fetch_with_delay(url, delay=10):
    """تأخير قبل الزحف"""
    print(f"🕒 انتظار {delay} ثانية قبل زحف {url}...")
    time.sleep(delay)

def collect_data(output_file="data/training_data.json"):
    all_forms = []
    all_vulns = []
    
    for site in TEST_SITES:
        print(f"\n🌐 معالجة {site}...")
        
        # التحقق من robots.txt
        if not can_fetch(site):
            print(f"⛔ robots.txt يمنع زحف {site}، تخطي.")
            continue
        
        # تأخير قبل كل موقع
        fetch_with_delay(site, delay=random.randint(10, 15))
        
        try:
            # استخدام وكيل مستخدم عشوائي
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            
            # تعديل كلاس WebCrawler لقبول headers (سنفترض أنك عدلته مسبقاً)
            # إذا لم يكن الكلام يدعم headers، سنضطر لتعديله لاحقاً.
            # للتبسيط، سنستخدم الكلام الحالي مع إضافة headers عبر requests.get مباشرة.
            # سنقوم بتمرير headers إلى الدوال الداخلية.
            
            # زحف
            crawler = WebCrawler(site, max_pages=5)  # نبدأ بعدد قليل
            # نعدل خاصية headers في الكلام (إذا كانت موجودة)
            if hasattr(crawler, 'headers'):
                crawler.headers = headers
            results = crawler.crawl()
            forms = results['forms']
            
            if not forms:
                print(f"📭 لا توجد نماذج في {site}")
                continue
            
            # فحص
            scanner = VulnerabilityScanner(forms, base_url=site)
            # نعدل headers في الماسح أيضاً
            if hasattr(scanner, 'headers'):
                scanner.headers = headers
            vulns = scanner.scan_all()
            
            # حفظ النماذج
            for form in forms:
                is_vuln = any(v['form'] == form for v in vulns)
                all_forms.append({
                    'form': form,
                    'vulnerable': is_vuln,
                    'site': site
                })
            
            all_vulns.extend(vulns)
            print(f"✅ تم جمع {len(forms)} نموذج، {len(vulns)} ثغرة من {site}")
            
        except Exception as e:
            print(f"❌ خطأ في {site}: {e}")
    
    # حفظ النتائج
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({'forms': all_forms, 'vulns': all_vulns}, f, indent=4)
    
    print(f"\n📁 تم حفظ البيانات في {output_file}")
    print(f"📊 إجمالي النماذج: {len(all_forms)}، إجمالي الثغرات: {len(all_vulns)}")
    return output_file

if __name__ == "__main__":
    collect_data()