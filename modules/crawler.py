import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

# إعداد التسجيل (logging) لتتبع الأخطاء
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebCrawler:
    """
    زاحف ويب بسيط يكتشف الروابط والنماذج في موقع معين.
    """
    def __init__(self, base_url, max_pages=10):
        self.base_url = base_url
        self.max_pages = max_pages
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
        """بدء عملية الزحف"""
        logger.info(f"بدء الزحف من {self.base_url}")
        pages_crawled = 0

        while self.to_visit and pages_crawled < self.max_pages:
            current_url = self.to_visit.pop(0)
            if current_url in self.visited:
                continue

            try:
                response = requests.get(current_url, timeout=5)
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
                self.to_visit.extend([link for link in new_links if link not in self.visited and link not in self.to_visit])

            except Exception as e:
                logger.error(f"خطأ أثناء معالجة {current_url}: {str(e)}")

        logger.info(f"انتهى الزحف. تمت زيارة {len(self.visited)} صفحة.")
        return self.results

# اختبار بسيط عند تشغيل الملف مباشرة
if __name__ == "__main__":
    crawler = WebCrawler("https://example.com", max_pages=5)
    results = crawler.crawl()
    print("الروابط المكتشفة:", results['links'])
    print("النماذج المكتشفة:", results['forms'])