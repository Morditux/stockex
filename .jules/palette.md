## 2024-05-22 - [Contextual Buttons in Lists]
**Learning:** In lists of items (like password cards), repeating action buttons like "Show", "Copy", "Delete" without context is a major screen reader trap.
**Action:** Always add `aria-label` that includes the item's name/context (e.g., "Show password for Google"). We used `{{T "Show"}} {{T "Password"}} - {{.Site}}` to compose this from existing strings.

## 2024-05-22 - [Template Key Sensitivity]
**Learning:** The i18n function `T` is sensitive to leading spaces in keys (e.g. `{{T " EnterUsername"}}` != `EnterUsername`).
**Action:** Be precise with template keys and lint/grep for leading/trailing spaces in calls to `T`.
