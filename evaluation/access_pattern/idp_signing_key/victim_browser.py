import os
import time
import asyncio
import httpx
import jwt
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'
ATTACKER_URL = os.environ.get('ATTACKER_URL') or "http://localhost:6666"

# Read private key
private_key_file = os.path.join(os.getcwd(), 'keys', 'private_key.pem')
with open(private_key_file, 'r') as file:
    private_key = file.read()
kid = '1b4cae83f17f2a89c4a775a1f88f6aed9e04196fe0e3fb78b4b9cc47a6c0dcf1'

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
        # Generate id_token
        payload = {
            'iss': 'http://localhost:4445',
            'sub': 'hoge',
            'aud': 'client'
        }
        id_token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": kid})
        print("id_token: ", id_token)

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
                'isUserVerified': False,
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
        # assert("Sign up succeeded." in result)
        
        # Sign in(attacker, attacker's browser)
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