import httpx
from bs4 import BeautifulSoup
import asyncio

async def test_dvwa_login_and_post():
    """
    A simple, self-contained script to test the DVWA login and post flow.
    """
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    BASE_URL = "http://localhost/"
    LOGIN_URL = "http://localhost/login.php"
    TARGET_URL = "http://localhost/vulnerabilities/xss_s/"
    
    # Use a stateful client to handle cookies automatically
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
        print("--- Step 1: GET Login Page to get session and CSRF token ---")
        try:
            login_page_res = await client.get(LOGIN_URL)
            soup = BeautifulSoup(login_page_res.text, 'html5lib')
            user_token = soup.find('input', {'name': 'user_token'}).get('value')
            print(f"SUCCESS: Got user_token: {user_token}")
            print(f"Client cookies after GET: {client.cookies}")
        except Exception as e:
            print(f"FAIL: Could not get login page or token. Error: {e}")
            return

        print("\n--- Step 2: POST to Login Page with credentials ---")
        login_payload = {
            "username": "admin",
            "password": "password",
            "user_token": user_token,
            "Login": "Login",
        }
        try:
            login_post_res = await client.post(LOGIN_URL, data=login_payload, headers={"Referer": LOGIN_URL})
            if "index.php" in str(login_post_res.url):
                print("SUCCESS: Login successful, redirected to index.php")
                print(f"Client cookies after POST: {client.cookies}")
            else:
                print(f"FAIL: Login failed. Final URL: {login_post_res.url}")
                return
        except Exception as e:
            print(f"FAIL: Could not post to login page. Error: {e}")
            return

        print("\n--- Step 3: GET the Stored XSS page to get a fresh CSRF token ---")
        try:
            target_page_res = await client.get(TARGET_URL)
            soup = BeautifulSoup(target_page_res.text, 'html5lib')
            user_token = soup.find('input', {'name': 'user_token'}).get('value')
            print(f"SUCCESS: Got new user_token for XSS page: {user_token}")
        except Exception as e:
            print(f"FAIL: Could not get target page. Error: {e}")
            return

        print("\n--- Step 4: POST payload to Stored XSS page ---")
        xss_payload = {
            "txtName": "SealionTest",
            "mtxMessage": "This is a test from the Sealion scanner.",
            "btnSign": "Sign Guestbook",
            "user_token": user_token,
        }
        try:
            post_res = await client.post(TARGET_URL, data=xss_payload, headers={"Referer": TARGET_URL})
            print(f"SUCCESS: Posted to guestbook. Status code: {post_res.status_code}")
        except Exception as e:
            print(f"FAIL: Could not post to guestbook. Error: {e}")
            return
            
        print("\n--- Step 5: GET final page and check for reflection ---")
        try:
            final_res = await client.get(TARGET_URL)
            if "SealionTest" in final_res.text:
                print("\n✅✅✅ SUCCESS: Payload was successfully stored and reflected on the page!")
            else:
                print("\n❌❌❌ FAIL: Payload was not found on the final page.")
                # print(final_res.text) # Uncomment for full HTML debug
        except Exception as e:
            print(f"FAIL: Could not get final page. Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_dvwa_login_and_post()) 