import os
import time
import asyncio
import random
import string
import csv
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

RP_URL = os.environ.get('RP_URL') or 'http://localhost:4444'

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
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Sign up(victim, victim's browser)
        page = await sso_flow(page)
        await page.click('#normalRegisterButton')
        time.sleep(3) # wait 3 seconds

        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        result = soup.find('p', id='content')
        print("sign up result (victim): ", result)
        assert("Sign up succeeded." in result)

        # store response times
        response_times_sign_in = []
        response_times_after_sign_in = []

        # Sign in(victim, victim's browser)
        for i in range(100):
            start_time = time.time() # start time

            page = await sso_flow(page)
            await page.click('#normalLoginButton')
            await page.wait_for_selector('p#content:text("Sign in succeeded.")')

            end_time = time.time()  # End time
            response_time = end_time - start_time  # Calculate the difference
            response_times_sign_in.append(response_time)
            print(f"Response time for sign in {i}: {response_time:.2f} seconds")

            time.sleep(0.5)

        # After sigin in(victim, victim's browser)
        for i in range(100):
            start_time = time.time() # start time

            await page.click('#normalAfterLoginRequestButton')
            await page.wait_for_selector('p#content:text("After sigin in request succeeded.")')

            end_time = time.time()  # End time
            response_time = end_time - start_time  # Calculate the difference
            response_times_after_sign_in.append(response_time)
            print(f"Response time for after sign in {i}: {response_time:.2f} seconds")

            time.sleep(0.5)
        
        # show average response time
        average_response_time_sign_in = sum(response_times_sign_in) / len(response_times_sign_in)
        average_response_time_after_sign_in = sum(response_times_after_sign_in) / len(response_times_after_sign_in)
        print(f"Average response time for sign in: {average_response_time_sign_in:.2f} seconds")
        print(f"Average response time for after sign in: {average_response_time_after_sign_in:.2f} seconds")

        # save response times to csv
        save_to_csv(response_times_sign_in, filename="./data/performance/baseline/response_times_sign_in.csv")
        save_to_csv(response_times_after_sign_in, filename="./data/performance/baseline/response_times_after_sign_in.csv")
       
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())