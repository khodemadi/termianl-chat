# LAN Terminal Chat — hotfix 0.3.0

این hotfix بر اساس سورس فعلی `khodemadi/termianl-chat` ساخته شده است.

## اضافه شده

- RTL/BiDi rendering برای پیام‌های فارسی/عربی/عبری در chat.
- رمزنگاری محتوای chat و فایل‌ها با X25519 + XChaCha20-Poly1305.
- کلید عمومی در discovery رد و بدل می‌شود و payloadها روی TCP رمز می‌شوند.
- دستور `/files`.
- file picker داخل همان TUI.
- انتخاب پوشه با Enter و انتخاب فایل با Enter.
- ارسال فایل به صورت chunkهای رمزنگاری‌شده.
- ذخیره فایل دریافتی در:
  `~/Downloads/LAN-Terminal-Chat/`
- جلوگیری از overwrite با نام‌هایی مثل `file (1).pdf`.

## تست

دو دستگاه را روی یک LAN اجرا کنید:

```bash
cargo run --release -- Ali
cargo run --release -- Reza
```

بعد در chat:

```text
سلام علی
```

برای ارسال فایل:

```text
/files
```

سپس با `↑/↓` حرکت کنید، با `Enter` وارد پوشه شوید و روی فایل `Enter` بزنید.

## محدودیت امنیتی این hotfix

محتوای chat و file با AEAD رمز و authenticate می‌شود، اما این نسخه **احراز هویت هویت peer / ضد MITM** ندارد؛ کلیدهای عمومی فعلاً از discovery می‌آیند. برای نسخه production باید یک لایه identity/authentication یا Noise Protocol اضافه شود.

## محدودیت RTL

این hotfix از Unicode BiDi برای reorder کردن متن استفاده می‌کند. شکل‌دهی حروف (Arabic shaping) را به terminal/font واگذار می‌کند؛ این همان رویکردی است که terminalهای مدرن با shaping داخلی می‌توانند از آن استفاده کنند. اگر terminal شما joining حروف فارسی را انجام ندهد، مرحله بعدی باید shaping presentation-form یا renderer داخلی باشد.

## توجه

این محیط به Rust/Cargo دسترسی نداشت، بنابراین این hotfix اینجا با `cargo check` اجرا نشده است. قبل از استفاده واقعی:

```bash
cargo check
cargo run --release -- Ali
```


## Input box fix

The message input is now a larger 7-row panel and wraps long text visually. It automatically scrolls vertically to keep the latest part of a long Persian/LTR message visible instead of letting it disappear past the bottom edge. Enter still sends the message.
