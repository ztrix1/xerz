from flask import Flask, render_template, request, jsonify
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.crawler_async import AsyncWebCrawler
from modules.scanner import VulnerabilityScanner
from core.ai_classifier import VulnerabilityClassifier
import asyncio

app = Flask(__name__)
classifier = VulnerabilityClassifier()
classifier.load_model()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    max_pages = int(data.get('max_pages', 5))
    
    # تشغيل الزحف غير المتزامن في حلقة asyncio جديدة
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    crawler = AsyncWebCrawler(url, max_pages=max_pages, headers={'User-Agent': 'Mozilla/5.0'}, delay=1, max_concurrent=3)
    results = loop.run_until_complete(crawler.crawl())
    loop.close()
    
    scanner = VulnerabilityScanner(results['forms'], base_url=url, headers={'User-Agent': 'Mozilla/5.0'}, delay=0.5)
    vulns = scanner.scan_all()
    for v in vulns:
        prob = classifier.predict(v['form'])
        v['ai_probability'] = round(prob, 2)
    
    filename = scanner.save_results()
    return jsonify({'vulns': vulns, 'filename': filename, 'forms_count': len(results['forms'])})

if __name__ == '__main__':
    app.run(debug=True)