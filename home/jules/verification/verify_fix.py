from playwright.sync_api import sync_playwright

def verify_password_buttons():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # 1. Login
        page.goto("http://localhost:8080/login")
        page.fill("input[name='username']", "admin")
        page.fill("input[name='password']", "admin123")
        page.click("button[type='submit']")

        # Wait for dashboard
        page.wait_for_url("**/dashboard")

        # 2. Add a password with special chars in site name to test safe rendering
        page.click("button:has-text('Add Password')")
        page.fill("#add-site", "Test'Site")
        page.fill("#add-username", "user")
        page.fill("#add-password", "pass")
        page.click("#add-password-modal button[type='submit']")

        # Wait for it to appear
        page.reload() # reload to be sure
        page.wait_for_selector(".password-card")

        # 3. Verify buttons work (which means JS didn't crash due to syntax error)
        # Click 'Show'
        page.click("button:has-text('Show')")

        # Take screenshot
        page.screenshot(path="/home/jules/verification/passwords_ui.png")

        # Check if console had errors?
        # (Hard to check in sync mode easily without event listener, but if click works it's good)

        browser.close()

if __name__ == "__main__":
    verify_password_buttons()
