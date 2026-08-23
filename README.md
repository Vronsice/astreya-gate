# Astreya Gate

Центр управления приватностью для Windows: локальный прокси-мост, гибкая маршрутизация по доменам и приложениям, защита от утечки реального IP.

Форк [Clod-Helper-v1](https://github.com/iimperium-dev/Clod-Helper-v1) (MIT), переработанный **vronsice**.

## Что умеет

- **Мост** `gate-bridge.exe` (Rust): слушает `127.0.0.1:8889` без auth, инжектит авторизацию и форвардит в купленный HTTP-прокси. Пул до 5 upstream'ов с failover.
- **Маршрутизация по доменам**: закрепите anthropic.com за платным прокси, а весь остальной трафик (opencode, git, npm, Telegram) пустите через дешёвый локальный/VPN-прокси — новая опция «Прокси по умолчанию».
- **Приложения**: Claude Code, Claude Desktop, ChatGPT/Codex, VS Code, Telegram, AyuGram — ярлыки «(proxy)», env-переменные, killswitch-покрытие.
- **Браузеры (PAC)**: выбранные сайты через мост, остальные напрямую с реальным IP. Без прав администратора.
- **Killswitch** через Windows Firewall: заблокированный процесс физически не может выйти наружу мимо моста — единственная жёсткая гарантия приватности.
- **Надёжность**: супервизор внутри моста + задача Планировщика + watchdog в GUI — упавший мост оживает за ~5 секунд.
- **Гид**: подробные объяснения как всё работает, рецепты настройки и чек-лист «не спалиться» — прямо в приложении.

## Форматы прокси

Понимаются все популярные форматы: `ip:port:user:pass`, `user:pass@host:port`, `http://user:pass@host:port` — вставляйте как есть.

## Для разработчиков

Стек: **Tauri 2 + React 19 + Tailwind 4**. Backend на Rust, фронт на TypeScript.

```powershell
npm install          # зависимости
npm run tauri dev    # dev-режим (hot reload)
npm run tauri build  # NSIS-установщик → src-tauri/target/release/bundle/nsis/
```

Пересборка моста отдельно:

```powershell
npm run bridge:build   # gate-bridge.exe → src-tauri/resources/
```

### Структура

```
src/                    React frontend (pages/, wizard/, components/, lib/)
src-tauri/              Rust backend
  src/proxy.rs          парсинг + проверка прокси (вкл. ip:port:user:pass)
  src/browser.rs        PAC-файл для браузеров + системный прокси (HKCU)
  src/env_proxy.rs      глобальные User-scope HTTP(S)_PROXY
  src/firewall.rs       killswitch (elevated PowerShell)
  src/tasks.rs          задача Планировщика + rules-файл моста
  resources/gate-bridge.exe  бандлится в установщик
bridge/                 исходники моста (tokio, без внешних зависимостей)
```

### Настройки

`%APPDATA%\Astreya Gate\settings.json` — пул прокси, назначения сервисов, дефолтный upstream, правила PAC. Чужие env-переменные и настройки системного прокси сохраняются при включении и возвращаются при выключении.

## Лицензия

MIT — см. [LICENSE](LICENSE).
