import time
from playwright.sync_api import sync_playwright

def test_password_decrypt(page):
    print("Navigating to login...")
    page.goto("http://localhost:8080/login")

    print("Filling login form...")
    page.fill("input[name='username']", "admin")
    page.fill("input[name='password']", "admin123")

    print("Clicking login...")
    page.click("button:has-text('Login')")

    print("Waiting for dashboard...")
    page.wait_for_url("http://localhost:8080/dashboard", timeout=5000)

    print("Clicking Add Password...")
    page.click("button:has-text('Add Password')")
    page.wait_for_selector("#add-password-modal", state="visible")

    print("Filling password details...")
    page.fill("#add-site", "TestSite")
    page.fill("#add-username", "testuser")
    page.fill("#add-password", "secret123")

    print("Submitting password...")
    page.click("#add-password-modal button[type='submit']")

    print("Waiting for password card...")
    page.wait_for_selector(".password-card", state="visible")

    print("Clicking Show...")
    page.click("button:has-text('Show')")

    print("Waiting for revealed password...")
    page.wait_for_selector("span:text('secret123')", state="visible")

    print("Taking screenshot...")
    page.screenshot(path="verification/decrypt_verified.png")
    print("Done.")

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            test_password_decrypt(page)
        except Exception as e:
            print(f"Error: {e}")
            page.screenshot(path="verification/error.png")
        finally:
            browser.close()
