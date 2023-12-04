import os
import time
import asyncio
import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'
ATTACKER_URL = os.environ.get('ATTACKER_URL') or "http://localhost:6666"

async def main():
    async with async_playwright() as p:
        # Get id_token from attacker server
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{ATTACKER_URL}/data/id_token")
            creds = res.json()
            id_token = creds['id_token']
        
        # Sign in(attacker, attacker's browser)
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Install virtual authenticator
        cdpSession = await context.new_cdp_session(page)
        await cdpSession.send('WebAuthn.enable')
        await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
            'options': {
                'protocol': 'ctap2',
                'transport': 'internal',
                'automaticPresenceSimulation': True,
                'hasResidentKey': True,
                'hasUserVerification': True,
                'isUserVerified': True,
            }
        })

        await page.goto(f"{RP_URL}/callback#id_token={id_token}")
        await page.click('#loginButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign in result (attacker): ", result)
        assert("Sign in failed." in result)

if __name__ == "__main__":
    asyncio.run(main())