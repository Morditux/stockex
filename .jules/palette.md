# Palette's Journal - UX & Accessibility Learnings

## 2025-02-18 - Modal Accessibility
**Learning:** The custom modal system used for alerts and confirmations was lacking basic accessibility features like focus trapping and keyboard dismissal (Escape key). This creates a "keyboard trap" where users might not know how to exit or where focus is lost.
**Action:** Always ensure custom modals manage focus:
1. Save `document.activeElement` on open.
2. Focus the primary action or first interactive element in the modal.
3. Trap focus within the modal (or at least listen for Escape).
4. Restore focus to the saved element on close.
