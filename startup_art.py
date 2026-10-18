"""ASCII identity for local startup and concise Telegram notifications."""
import argparse
import html
import json
import os
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parent


def ascii_art():
    try: return (ROOT/'assets'/'startup_ascii.txt').read_text(encoding='utf-8').rstrip('\n')
    except OSError: return 'C Y B E R P M'


def telegram_start_text(target, mode):
    version=(ROOT/'VERSION').read_text(encoding='utf-8').strip()
    return f'<b>Cyberpm v{html.escape(version)}</b>\nAuditoria iniciada\nAlvo: {html.escape(target[:253])}\nModo: {html.escape(mode[:32])}'


def send_telegram_start(token, chat, target, mode):
    if not token or not chat: return False
    body=urlencode({'chat_id':chat,'text':telegram_start_text(target,mode),'parse_mode':'HTML','disable_web_page_preview':'true'}).encode('utf-8')
    request=Request(f'https://api.telegram.org/bot{token}/sendMessage',data=body,method='POST')
    try:
        with urlopen(request,timeout=12) as response:
            result=json.load(response)
        return bool(result.get('ok'))
    except Exception:
        # Transport exception messages can contain the bot token.
        return False


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--telegram-start',action='store_true')
    parser.add_argument('--target',default='')
    parser.add_argument('--mode',default='completo')
    args=parser.parse_args()
    if args.telegram_start:
        ok=send_telegram_start(os.environ.get('TELEGRAM_TOKEN',''),os.environ.get('TELEGRAM_CHAT',''),args.target,args.mode)
        print('[TG] Início enviado.' if ok else '[AVISO] Telegram: início não enviado; verifique configuração e conexão.')
    else:
        print(ascii_art())
        print('Cyberpm v'+(ROOT/'VERSION').read_text().strip())
