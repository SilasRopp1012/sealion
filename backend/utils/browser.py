import asyncio
# The correct import is the 'Stealth' class
from playwright_stealth import Stealth
from playwright.async_api import async_playwright

async def fetch_rendered_html(url: str) -> str:
    """
    Uses a stealthy headless browser to fetch the fully rendered HTML content
    of a URL, avoiding common bot detection.
    """
    html = ""
    try:
        # Corrected: Instantiate Stealth() before calling use_async
        async with Stealth().use_async(async_playwright()) as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            
            await page.goto(url, wait_until='networkidle', timeout=15000)
            # An extra wait just in case networkidle isn't enough for some SPAs
            await page.wait_for_timeout(2000) 
            html = await page.content()
            await browser.close()
    except Exception as e:
        print(f"Error fetching rendered HTML for {url}: {str(e)}")
        # Return an empty string if there's an error so scanners can fail gracefully
        return ""
    return html 