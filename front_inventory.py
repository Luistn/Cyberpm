"""Extract same-host script references from HTML without executing code."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


class Scripts(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.scripts = set()

    def handle_starttag(self, tag, attrs):
        if tag != 'script':
            return
        attrs = dict(attrs)
        if not attrs.get('src'):
            return
        url = urljoin(self.base, attrs['src'])
        try:
            source, target = urlparse(self.base), urlparse(url)
            if (target.scheme in ('http', 'https') and target.hostname == source.hostname
                    and target.port == source.port and not target.username and not target.password):
                self.scripts.add(url)
        except ValueError:
            pass


def extract(base, html):
    parser = Scripts(base)
    parser.feed(html)
    return sorted(parser.scripts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('html')
    args = parser.parse_args()
    for url in extract(args.base, Path(args.html).read_text(encoding='utf-8', errors='replace')):
        print(url)


if __name__ == '__main__':
    main()
