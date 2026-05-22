import asyncio
import json
import re
import hashlib
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Any
from aiohttp import web
from aiohttp.web import Request, Response
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RequestHistoryStorage:
    def __init__(self, ttl_seconds: int = 60):
        self._history: Dict[str, List[float]] = defaultdict(list)
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    async def add_request(self, client_ip: str):
        async with self._lock:
            current_time = time.time()
            self._history[client_ip] = [
                t for t in self._history[client_ip]
                if current_time - t < self._ttl
            ]
            self._history[client_ip].append(current_time)

    async def get_request_count(self, client_ip: str) -> int:
        async with self._lock:
            current_time = time.time()
            return len([
                t for t in self._history[client_ip]
                if current_time - t < self._ttl
            ])

    async def cleanup_old_entries(self):
        while True:
            await asyncio.sleep(60)
            async with self._lock:
                current_time = time.time()
                for ip in list(self._history.keys()):
                    self._history[ip] = [
                        t for t in self._history[ip]
                        if current_time - t < self._ttl
                    ]
                    if not self._history[ip]:
                        del self._history[ip]

request_storage = RequestHistoryStorage()

HEADLESS_PATTERNS = [
    'HeadlessChrome', 'PhantomJS', 'Selenium', 'Puppeteer',
    'Playwright', 'Headless', 'HeadlessBrowser', 'Cypress'
]

BOT_USER_AGENTS = [
    'python-requests', 'python-urllib', 'Java', 'curl', 'wget',
    'Go-http-client', 'Apache-HttpClient', 'okhttp', 'bot', 'spider',
    'crawler', 'scraper', 'scrapy', 'httpx', 'aiohttp', 'axios',
    'node-fetch', 'got', 'urllib3'
]

ANTIDETECT_BROWSERS = {
    'indigo': ['Indigo', 'IndigoBrowser'],
    'multilogin': ['Multilogin', 'MLBrowser'],
    'gologin': ['GoLogin', 'Gologin'],
    'octobrowser': ['OctoBrowser', 'Octo', 'OctoBrowser'],
    'kameleo': ['Kameleo', 'KameleoBrowser'],
    'adspower': ['AdsPower', 'ADSPower'],
    'lalicat': ['Lalicat', 'LaliBrowser'],
    'vmlogin': ['VMLogin', 'VMBrowser'],
}

class AntibotAnalyzer:
    async def analyze_bot_behavior(
            self,
            headers: Dict,
            body: Optional[Any],
            client_ip: str,
            request_path: str,
            method: str
    ) -> Dict:
        scores = {
            'is_bot': 0,
            'is_headless': 0,
            'is_antidetect': 0,
            'is_human_like': 0
        }
        reasons = []
        user_agent = headers.get('user-agent', '')

        await self._analyze_user_agent(user_agent, scores, reasons)
        await self._analyze_headers(headers, scores, reasons)
        await self._analyze_behavioral(headers, body, method, scores, reasons)
        await self._analyze_body_content(body, scores, reasons)

        request_count = await request_storage.get_request_count(client_ip)
        if request_count > 30:
            scores['is_bot'] += 2
            reasons.append(f'High request frequency: {request_count} requests/minute')

        total_bot_score = scores['is_bot'] + scores['is_headless'] + scores['is_antidetect']

        if total_bot_score >= 5:
            verdict = 'BOT'
            confidence = min(95, 60 + total_bot_score * 5)
        elif scores['is_antidetect'] >= 3:
            verdict = 'ANTIDETECT_BROWSER'
            confidence = 80
        elif total_bot_score >= 2:
            verdict = 'SUSPICIOUS'
            confidence = 50 + total_bot_score * 10
        else:
            verdict = 'REAL_BROWSER'
            confidence = min(95, 70 + scores['is_human_like'] * 10)

        return {
            'verdict': verdict,
            'confidence': confidence,
            'scores': scores,
            'reasons': reasons,
            'bot_score': total_bot_score,
            'request_count_last_minute': request_count
        }

    async def _analyze_user_agent(self, user_agent: str, scores: Dict, reasons: List):
        if not user_agent:
            scores['is_bot'] += 3
            reasons.append('Missing User-Agent')
            return

        ua_lower = user_agent.lower()

        for bot in BOT_USER_AGENTS:
            if bot.lower() in ua_lower:
                scores['is_bot'] += 3
                reasons.append(f'Known bot signature: {bot}')
                break

        for pattern in HEADLESS_PATTERNS:
            if pattern.lower() in ua_lower:
                scores['is_headless'] += 9
                reasons.append(f'Headless pattern: {pattern}')
                break

        for browser_name, patterns in ANTIDETECT_BROWSERS.items():
            for pattern in patterns:
                if pattern.lower() in ua_lower:
                    scores['is_antidetect'] += 3
                    reasons.append(f'Anti-detect browser: {browser_name}')
                    break

        if await self._is_suspicious_ua(user_agent):
            scores['is_bot'] += 2
            reasons.append('Suspicious User-Agent format')

    async def _analyze_headers(self, headers: Dict, scores: Dict, reasons: List):
        sec_ch_ua = headers.get('sec-ch-ua', '')
        sec_ch_ua_mobile = headers.get('sec-ch-ua-mobile', '')
        sec_ch_ua_platform = headers.get('sec-ch-ua-platform', '')

        if not sec_ch_ua and not sec_ch_ua_mobile and not sec_ch_ua_platform:
            scores['is_bot'] += 2
            reasons.append('Missing modern browser hints (Sec-Ch-Ua)')

        accept_lang = headers.get('accept-language', '')
        if not accept_lang:
            scores['is_bot'] += 1
            reasons.append('Missing Accept-Language header')

        accept_encoding = headers.get('accept-encoding', '')
        if not accept_encoding:
            scores['is_bot'] += 1
            reasons.append('Missing Accept-Encoding header')

    async def _analyze_behavioral(self, headers: Dict, body: Optional[Any], method: str, scores: Dict, reasons: List):
        if method == 'POST':
            referer = headers.get('referer', '')
            if not referer:
                scores['is_bot'] += 1
                reasons.append('POST request without Referer')

        if await self._looks_like_human_behavior(headers):
            scores['is_human_like'] += 3
            reasons.append('Human-like behavior detected')

    async def _analyze_body_content(self, body: Optional[Any], scores: Dict, reasons: List):
        if body and isinstance(body, str):
            body_str = str(body).lower()
            automation_patterns = ['selenium', 'puppeteer', 'playwright', 'webdriver']
            for pattern in automation_patterns:
                if pattern in body_str:
                    scores['is_bot'] += 2
                    reasons.append(f'Automation keyword: {pattern}')
                    break

    async def _is_suspicious_ua(self, user_agent: str) -> bool:
        if len(user_agent) < 20:
            return True

        if not re.search(r'Mozilla|Mobile|AppleWebKit|Windows|Mac|Linux|Android|iPhone', user_agent, re.I):
            return True

        if not re.search(r'\d+\.\d+', user_agent):
            return True

        return False

    async def _looks_like_human_behavior(self, headers: Dict) -> bool:
        human_indicators = 0

        accept = headers.get('accept', '')
        if 'text/html' in accept and 'image/' in accept:
            human_indicators += 1

        if headers.get('cache-control') or headers.get('if-modified-since'):
            human_indicators += 1

        if headers.get('cookie') and len(headers.get('cookie', '')) > 20:
            human_indicators += 1

        if headers.get('referer') or headers.get('origin'):
            human_indicators += 1

        return human_indicators >= 3

    async def extract_browser_fingerprint(self, headers: Dict) -> Dict:
        fingerprint_data = {
            'user_agent': headers.get('user-agent', ''),
            'accept': headers.get('accept', ''),
            'accept_language': headers.get('accept-language', ''),
            'accept_encoding': headers.get('accept-encoding', ''),
            'sec_ch_ua': headers.get('sec-ch-ua', ''),
            'sec_ch_ua_platform': headers.get('sec-ch-ua-platform', ''),
            'sec_ch_ua_mobile': headers.get('sec-ch-ua-mobile', ''),
            'dnt': headers.get('dnt', ''),
            'connection': headers.get('connection', ''),
        }

        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]

        return {
            'hash': fingerprint_hash,
            'data': fingerprint_data
        }

analyzer = AntibotAnalyzer()

def parse_user_agent(user_agent: str) -> Dict:
    ua = user_agent or ''

    is_mobile = bool(re.search(r'Mobile|Android|iPhone|iPad|iPod|BlackBerry|Opera Mini|IEMobile', ua, re.I))
    is_tablet = bool(re.search(r'iPad|Android(?!.*Mobile)', ua, re.I))
    is_desktop = not is_mobile and not is_tablet

    browser = 'Unknown'
    browser_version = 'Unknown'

    if 'Chrome' in ua and 'Edg' not in ua and 'OPR' not in ua:
        browser = 'Chrome'
        match = re.search(r'Chrome/(\d+\.\d+)', ua)
        if match:
            browser_version = match.group(1)
    elif 'Firefox' in ua:
        browser = 'Firefox'
        match = re.search(r'Firefox/(\d+\.\d+)', ua)
        if match:
            browser_version = match.group(1)
    elif 'Safari' in ua and 'Chrome' not in ua:
        browser = 'Safari'
        match = re.search(r'Version/(\d+\.\d+)', ua)
        if match:
            browser_version = match.group(1)

    os_name = 'Unknown'
    if 'Windows NT 10.0' in ua:
        os_name = 'Windows 10'
    elif 'Mac OS X' in ua:
        os_name = 'macOS'
    elif 'Linux' in ua:
        os_name = 'Linux'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_name = 'iOS'

    device = 'Mobile' if is_mobile else ('Tablet' if is_tablet else 'Desktop')

    return {
        'browser': browser,
        'browser_version': browser_version,
        'os': os_name,
        'device': device,
        'is_mobile': is_mobile,
        'is_tablet': is_tablet,
        'is_desktop': is_desktop
    }

async def universal_handler(request: Request) -> Response:
    if request.method == 'OPTIONS':
        return web.Response(
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Max-Age': '3600'
            }
        )

    try:
        body = None
        json_body = None

        if request.can_read_body and request.content_length:
            body = await request.text()
            if body and request.content_type == 'application/json':
                try:
                    json_body = json.loads(body)
                except:
                    pass

        parsed_url = urlparse(str(request.url))
        query_params = parse_qs(parsed_url.query)
        query_params_simple = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

        client_ip = request.headers.get('X-Forwarded-For')
        if client_ip:
            client_ip = client_ip.split(',')[0].strip()
        else:
            client_ip = request.remote

        await request_storage.add_request(client_ip)

        bot_analysis = await analyzer.analyze_bot_behavior(
            request.headers, body, client_ip, parsed_url.path, request.method
        )

        fingerprint = await analyzer.extract_browser_fingerprint(request.headers)
        user_agent_string = request.headers.get('user-agent', '')
        user_agent_data = parse_user_agent(user_agent_string)

        response_data = {
            'request': {
                'method': request.method,
                'url': str(request.url),
                'path': parsed_url.path,
                'query_params': query_params_simple,
                'body': json_body if json_body else body,
                'timestamp': datetime.now().isoformat()
            },
            'client': {
                'ip': client_ip,
                'user_agent': user_agent_string,
                'user_agent_parsed': user_agent_data,
                'fingerprint': fingerprint,
                'languages': request.headers.get('accept-language', '').split(','),
                'platform': request.headers.get('sec-ch-ua-platform'),
            },
            'bot_detection': bot_analysis,
            'headers': dict(request.headers),
        }

        colors = {
            'REAL_BROWSER': '\033[92m',
            'SUSPICIOUS': '\033[93m',
            'BOT': '\033[91m',
            'ANTIDETECT_BROWSER': '\033[95m'
        }
        reset = '\033[0m'
        color = colors.get(bot_analysis['verdict'], '\033[94m')

        print(f'\n{"=" * 80}')
        print(f'{color}{bot_analysis["verdict"]}{reset} [{request.method}] {parsed_url.path}')
        print(f'Confidence: {bot_analysis["confidence"]}%')
        print(f'Bot Score: {bot_analysis["bot_score"]}')
        print(f'Requests/min: {bot_analysis["request_count_last_minute"]}')
        if bot_analysis["reasons"]:
            print(f'Reasons: {", ".join(bot_analysis["reasons"][:3])}')
        print(f'Fingerprint: {fingerprint["hash"]}')
        print(f'{"=" * 80}\n')

        return web.json_response(
            {
                'status': 'success',
                'verdict': bot_analysis['verdict'],
                'confidence': f"{bot_analysis['confidence']}%",
                'blocked': bot_analysis['verdict'] in ['BOT', 'ANTIDETECT_BROWSER'],
                'fingerprint': fingerprint['hash'],
                'analysis': bot_analysis
            },
            headers={
                'X-Bot-Detected': bot_analysis['verdict'],
                'X-Bot-Confidence': str(bot_analysis['confidence']),
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                'Access-Control-Allow-Headers': '*'
            }
        )

    except Exception as e:
        logger.error(f'Error: {e}', exc_info=True)
        return web.json_response(
            {'error': str(e)},
            status=500,
            headers={'Access-Control-Allow-Origin': '*'}
        )

async def health_check(request: Request) -> Response:
    return web.json_response({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_requests': len(request.app.get('active_requests', {}))
    })

async def cleanup_background_tasks(app: web.Application):
    cleanup_task = asyncio.create_task(request_storage.cleanup_old_entries())
    app['cleanup_task'] = cleanup_task
    yield
    cleanup_task.cancel()
    await cleanup_task

async def main():
    app = web.Application()

    app.router.add_route('*', '/', universal_handler)
    app.router.add_route('*', '/{path:.*}', universal_handler)
    app.router.add_get('/health', health_check)

    app.cleanup_ctx.append(cleanup_background_tasks)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()

    print('=' * 60)
    print('SERVER STARTED')
    print('=' * 60)
    print(f'Address: http://localhost:8000')


    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        print('\nStopping server...')
        await runner.cleanup()
        print('Server stopped')

if __name__ == '__main__':
    asyncio.run(main())