## 🎉 TEESimulator 4.0 — a new foundation

Ever since TEESimulator began, the community has watched me pour real effort into closing pre-existing detection points, release after release. But as AI-driven conformance scanners multiply and quick "harness fix" commits go viral, it has grown exhausting to fold in a stream of unproven, poorly-explained external patches — innovation stalled, and code quality slipped noticeably. 😮‍💨

So here is **TEESimulator 4.0**. 🚀 Instead of faking a hardware backend, it runs AOSP's own KeyMint reference implementation — the very trusted application that normally lives *inside* the TEE — **in-process**. This single change sweeps away countless detection points at once and, for the first time, brings first-class permanent key storage. 🔐

## ✨ Highlights

- **🧠 Reference KeyMint TA, in-process.** Attestations come straight from AOSP's `kmr-ta`, not hand-rolled certificates — so every emitted record matches a real device field-for-field.
- **🎛️ Profiles and a WebUI.** Bundle a keybox, operation mode, patch/OS levels, and device identity into a named profile, assign it to your apps, and edit it all from the manager's WebUI — no text editor, no reboot.
- **📱 Android 10 → 17.** Both the legacy `keystore` daemon (Android 10/11) and `keystore2` / KeyMint (Android 12+) are intercepted, and every key is attested at — and reports — its real security level and the version its OS release uses.
- **🩹 Patch mode by default.** The real hardware still generates the key; only its attestation is re-signed under your keybox, keeping the genuine hardware-backed blob and its true contents.

## 💬 Feedback

To get started, drop a keybox at `/data/adb/teesim/keybox.xml`, then assign your apps to a profile in the WebUI. 🗝️

Please open an issue for any device-support or compatibility problems — it helps enormously. 🙏 This release has been tested on **Android 17 (Pixel 6)** and **Android 10 (the Android emulator)**.
