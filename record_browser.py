#!/usr/bin/env python3
"""Record scoped requests during manual browser use. Does not auto-click or replay."""
import argparse
import time
from pathlib import Path
from recon81.core import MAX_BODY, Inventory, Scope, get_header, normalize_record


def record_request(request, response, include_text=False):
    headers = request.headers
    rh = response.headers if response else []
    body = None
    if response:
        mime = get_header(rh, 'content-type').split(';')[0].lower()
        length = get_header(rh, 'content-length')
        structured = mime in ('application/json', 'application/xml', 'text/xml', 'application/x-www-form-urlencoded') or mime.endswith(('+json', '+xml'))
        # Read bounded declared bodies only. Browser APIs provide complete buffers.
        if (structured or include_text) and length.isdigit() and int(length) <= MAX_BODY:
            try:
                body = response.body()
            except Exception:
                body = None
    return normalize_record(request.url, request.method, headers, request.post_data_buffer or b'', {'status': response.status, 'headers': rh, 'body': body} if response else None, source='playwright', include_text=include_text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--scope', action='append', required=True)
    parser.add_argument('--db', type=Path, default=Path('reports/request_inventory.sqlite3'))
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--include-text', action='store_true')
    args = parser.parse_args()
    scope = Scope(args.scope)
    if not scope.allows(args.url):
        parser.error('Initial URL must match scope')
    if not 1 <= args.seconds <= 3600:
        parser.error('--seconds must be between 1 and 3600')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        parser.error('Install playwright and its Chromium browser first (see README)')
    count = failed = 0
    with Inventory(args.db) as inventory, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        context = browser.new_context(service_workers='block')
        pending = set()
        def request_seen(request):
            if scope.allows(request.url):
                pending.add(request)
        def finish(request, response=None):
            nonlocal count, failed
            if request not in pending:
                return
            pending.remove(request)
            try:
                inventory.add(record_request(request, response, args.include_text))
                count += 1
            except Exception:
                failed += 1  # Never print raw URL or exception data.
        context.on('request', request_seen)
        context.on('requestfinished', lambda request: finish(request, request.response()))
        context.on('requestfailed', lambda request: finish(request))
        page = context.new_page()
        try:
            page.goto(args.url, wait_until='domcontentloaded', timeout=30000)
        except Exception:
            print('Initial navigation did not complete. You may continue in the browser.')
        print('Use the browser manually for ' + str(args.seconds) + ' seconds. Press Ctrl+C to stop. No automated submission or replay.')
        deadline = time.monotonic() + args.seconds
        try:
            while time.monotonic() < deadline and context.pages:
                context.pages[0].wait_for_timeout(250)
        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        finally:
            # Unfinished requests are preserved with a missing response.
            for request in list(pending):
                finish(request)
            context.close()
            browser.close()
    print('Saved records: ' + str(count) + '; failed records: ' + str(failed))


if __name__ == '__main__':
    main()
