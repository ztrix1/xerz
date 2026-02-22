import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import urllib3
import time
import random

# إيقاف تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعداد التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebCrawler:
    """
    زاحف ويب بسيط يكتشف الروابط والنماذج في موقع معين.
    يدعم إضافة headers مخصصة وتأخير بين الطلبات لاحترام سياسات المواقع.
    """
    def __init__(self, base_url, max_pages=10, headers=None, delay=1):
        """
        :param base_url: الرابط الأساسي للزحف
        :param max_pages: أقصى عدد صفحات للزحف
        :param headers: قاموس يحتوي على headers مخصصة (مثل User-Agent)
        :param delay: عدد الثواني للتأخير بين الطلبات (افتراضي 1 ثانية)
        """
        self.base_url = base_url
        self.max_pages = max_pages
        self.headers = headers or {}
        self.delay = delay
        self.visited = set()
        self.to_visit = [base_url]
        self.results = {
            'links': [],
            'forms': []
        }

    def is_internal_link(self, link):
        """التحقق مما إذا كان الرابط داخلياً (نفس النطاق)"""
        parsed_base = urlparse(self.base_url)
        parsed_link = urlparse(link)
        return parsed_base.netloc == parsed_link.netloc

    def extract_links(self, soup, current_url):
        """استخراج جميع الروابط من الصفحة"""
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            if self.is_internal_link(full_url) and full_url not in self.visited:
                links.append(full_url)
                self.results['links'].append(full_url)
        return links

    def extract_forms(self, soup, current_url):
        """استخراج جميع نماذج HTML من الصفحة"""
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = []
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            form_data = {
                'action': urljoin(current_url, action) if action else current_url,
                'method': method,
                'inputs': inputs
            }
            forms.append(form_data)
            self.results['forms'].append(form_data)
        return forms

    def crawl(self):
        """بدء عملية الزحف مع مراعاة التأخير"""
        logger.info(f"بدء الزحف من {self.base_url} (بحد أقصى {self.max_pages} صفحات)")
        pages_crawled = 0

        while self.to_visit and pages_crawled < self.max_pages:
            current_url = self.to_visit.pop(0)
            if current_url in self.visited:
                continue

            try:
                # إضافة تأخير قبل الطلب (حتى لو كان أول طلب، نتركه اختيارياً)
                if pages_crawled > 0:  # لا تؤخر قبل أول طلب لتسريع البداية
                    sleep_time = self.delay + random.uniform(0, 1)  # إضافة توزيع عشوائي
                    logger.debug(f"الانتظار {sleep_time:.2f} ثانية قبل {current_url}")
                    time.sleep(sleep_time)

                response = requests.get(
                    current_url,
                    timeout=15,
                    verify=False,
                    headers=self.headers
                )

                if response.status_code != 200:
                    logger.warning(f"فشل في جلب {current_url} - الحالة: {response.status_code}")
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                self.visited.add(current_url)
                pages_crawled += 1
                logger.info(f"تم زحف {current_url} - الصفحة {pages_crawled}")

                # استخراج الروابط والنماذج
                new_links = self.extract_links(soup, current_url)
                self.extract_forms(soup, current_url)

                # إضافة الروابط الجديدة إلى قائمة الانتظار
                for link in new_links:
                    if link not in self.visited and link not in self.to_visit:
                        self.to_visit.append(link)

            except Exception as e:
                logger.error(f"خطأ أثناء معالجة {current_url}: {str(e)}")

        logger.info(f"انتهى الزحف. تمت زيارة {len(self.visited)} صفحة.")
        return self.results

# اختبار بسيط عند تشغيل الملف مباشرة
if __name__ == "__main__":
    # مثال مع headers مخصصة وتأخير 2 ثانية
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    crawler = WebCrawler("https://example.com", max_pages=5, headers=headers, delay=2)
    results = crawler.crawl()
    print("الروابط المكتشفة:", results['links'])
    print("النماذج المكتشفة:", results['forms'])