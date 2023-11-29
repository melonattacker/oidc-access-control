import os
import time
import asyncio
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'

def get_random_name(n):
   randlst = [random.choice(string.ascii_letters + string.digits) for i in range(n)]
   return ''.join(randlst)

# theft victim's credential
victim_username = 'hoge'
victim_password = 'hoge'

async def sso_flow(page):
    await page.goto(f"{RP_URL}/login")

    await page.locator('input[name="userId"]').fill(f'{victim_username}')
    await page.locator('input[name="password"]').fill(f'{victim_password}')
    try:
        # Click login button
        await page.locator('button[type="submit"]').click(timeout=1000)

        # Click yes button on consent page
        await page.locator('input[name="yes"]').click(timeout=1000) 
    except PlaywrightTimeoutError as e:
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

        # Sign in(attacker, attacker browser)
        page = await sso_flow(page)
        await page.click('#loginButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        assert("Sign in failed." in result)

if __name__ == "__main__":
    asyncio.run(main())