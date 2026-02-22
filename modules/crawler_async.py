import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import random
import time

logger = logging.getLogger(__name__)

class AsyncWebCrawler:
    def __init__(self, base_url, max_pages=10, headers=None, delay=1, max_concurrent=5):
        self.base_url = base_url
        self.max_pages = max_pages
        self.headers = headers or {}
        self.delay = delay
        self.max_concurrent = max_concurrent
        self.visited = set()
        self.to_visit = [base_url]
        self.results = {'links': [], 'forms': []}
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def fetch(self, session, url):
        async with self.semaphore:
            if self.delay > 0:
                await asyncio.sleep(self.delay + random.uniform(0, 0.5))
            try:
                async with session.get(url, timeout=10, ssl=False) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        logger.warning(f"فشل {url} - {response.status}")
                        return None
            except Exception as e:
                logger.error(f"خطأ في {url}: {e}")
                return None

    def extract_links_and_forms(self, html, current_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            full = urljoin(current_url, href)
            if self.is_internal_link(full) and full not in self.visited:
                links.append(full)
                self.results['links'].append(full)

        forms = []
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = []
            for inp in form.find_all('input'):
                name = inp.get('name')
                typ = inp.get('type', 'text')
                if name:
                    inputs.append({'name': name, 'type': typ})
            form_data = {
                'action': urljoin(current_url, action) if action else current_url,
                'method': method,
                'inputs': inputs
            }
            forms.append(form_data)
            self.results['forms'].append(form_data)
        return links

    def is_internal_link(self, link):
        parsed_base = urlparse(self.base_url)
        parsed_link = urlparse(link)
        return parsed_base.netloc == parsed_link.netloc

    async def crawl(self):
        logger.info(f"بدء الزحف غير المتزامن من {self.base_url}")
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, connector=connector) as session:
            tasks = []
            pages_crawled = 0
            while self.to_visit and pages_crawled < self.max_pages:
                current = self.to_visit.pop(0)
                if current in self.visited:
                    continue
                self.visited.add(current)
                pages_crawled += 1
                task = asyncio.create_task(self.process_page(session, current))
                tasks.append(task)
                if len(tasks) >= self.max_concurrent:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    tasks = list(pending)
            if tasks:
                await asyncio.wait(tasks)
        logger.info(f"انتهى الزحف. تمت زيارة {len(self.visited)} صفحة.")
        return self.results

    async def process_page(self, session, url):
        html = await self.fetch(session, url)
        if html:
            new_links = self.extract_links_and_forms(html, url)
            for link in new_links:
                if link not in self.visited and link not in self.to_visit:
                    self.to_visit.append(link)