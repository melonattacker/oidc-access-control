import os
import time
import asyncio
import random
import string
import csv
import tempfile
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'

save_to_csv_flag = os.environ.get('SAVE_TO_CSV', 'False').lower() in ['true', '1']

# victim credentials
victim_username = 'hoge'
victim_password = 'hoge'

def save_to_csv(response_times, filename):
    directory = os.path.dirname(filename)
    if not os.path.exists(directory):
        os.makedirs(directory)

    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Request Number", "Response Time"])  # CSV header
        
        for i, response_time in enumerate(response_times, 1):
            writer.writerow([i, response_time])

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
        # Create tmp file
        temp_file = tempfile.NamedTemporaryFile(prefix="tmp", dir="/tmp/hogehoge", delete=False)
        print("Temporary file name:", temp_file.name)

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

        # store response times
        response_times_sign_in = []

        # Sign in(victim, victim's browser)
        for i in range(100):
            start_time = time.time() # start time

            page = await sso_flow(page)
            await page.click('#loginButton')
            await page.wait_for_selector('p#content:text("Sign in succeeded.")')

            end_time = time.time()  # End time
            response_time = end_time - start_time  # Calculate the difference
            response_times_sign_in.append(response_time)
            print(f"Response time for sign in {i}: {response_time:.2f} seconds")

            time.sleep(0.5)

        # show average response time
        average_response_time_sign_in = sum(response_times_sign_in) / len(response_times_sign_in)
        print(f"Average response time for sign in: {average_response_time_sign_in:.2f} seconds")

        # save response times to csv
        if save_to_csv_flag:
            save_to_csv(response_times_sign_in, "./data/performance/response_time/proposed/response_times_signin.csv")
       
        await browser.close()

        temp_file.close()
        os.unlink(temp_file.name)

if __name__ == "__main__":
    asyncio.run(main())