from playwright.sync_api import sync_playwright

def verify_ux_changes():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Navigate to dashboard (requires login, so we'll start with login)
        page.goto("http://localhost:8080/login")

        # Login
        page.fill("input[name='username']", "admin")
        page.fill("input[name='password']", "admin123")
        page.click("button[type='submit']")

        # Wait for dashboard to load
        page.wait_for_selector(".dashboard-container")

        # 1. Verify Focus State on Export CSV button
        # Force focus on the Export CSV link
        export_btn = page.get_by_role("link", name="Export CSV")
        export_btn.focus()

        # Take screenshot of the focus state
        page.screenshot(path=".jules/verification/focus_state.png")

        # 2. Verify Attributes of Export CSV link
        rel = export_btn.get_attribute("rel")
        target = export_btn.get_attribute("target")
        aria_label = export_btn.get_attribute("aria-label")

        print(f"Rel: {rel}")
        print(f"Target: {target}")
        print(f"Aria-Label: {aria_label}")

        if rel != "noopener noreferrer":
            print("FAILED: rel attribute is incorrect")
        if target != "_blank":
            print("FAILED: target attribute is incorrect")
        if "Opens in new window" not in aria_label and "S'ouvre dans une nouvelle fenêtre" not in aria_label:
             print("FAILED: aria-label missing 'Opens in new window'")

        browser.close()

if __name__ == "__main__":
    verify_ux_changes()
