"""Run the bundled research workbench in a local WebView2 window."""

from __future__ import annotations

import ctypes
import os
import threading
from pathlib import Path

from server import DEFAULT_PORT, HOST, serve


APP_TITLE = "RK Research Workbench"
PORT = DEFAULT_PORT
URL = f"http://{HOST}:{PORT}/"


def local_data_directory() -> Path:
    """Return the per-user directory for persistent desktop web data."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base = Path(local_app_data)
    else:
        base = Path.home() / "AppData" / "Local"
    path = base / "RK-Research-Workbench"
    path.mkdir(parents=True, exist_ok=True)
    return path


def show_error(message: str) -> None:
    """Show an error even in the windowed, console-free executable."""
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(None, message, APP_TITLE, 0x10)
    else:
        print(f"{APP_TITLE}: {message}")


def main() -> None:
    try:
        import webview
    except ImportError:
        show_error(
            "The desktop window runtime is missing. Rebuild the executable using "
            "build.ps1 or install the desktop requirements."
        )
        return

    server = None
    try:
        server = serve(PORT)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10048 or getattr(exc, "errno", None) in (48, 98, 10048):
            show_error(
                f"The RK Research Workbench could not start because localhost port {PORT} is already in use.\n\n"
                "Close another workbench instance or stop the local server using this port, "
                "then launch the workbench again."
            )
            return
        show_error(f"The RK Research Workbench could not start its local interface.\n\n{exc}")
        return

    try:
        threading.Thread(target=server.serve_forever, name="keydeck-local-server", daemon=True).start()
        data_directory = local_data_directory()
        webview_data_directory = data_directory / "WebView2"
        webview_data_directory.mkdir(parents=True, exist_ok=True)
        webview.create_window(
            APP_TITLE,
            URL,
            width=1440,
            height=940,
            min_size=(1024, 680),
            background_color="#f4f5f2",
        )
        webview.start(
            gui="edgechromium",
            private_mode=False,
            storage_path=str(webview_data_directory),
            debug=False,
        )
    except Exception as exc:
        show_error(
            "The RK Research Workbench could not open its desktop window. Make sure Microsoft Edge WebView2 "
            f"Runtime is installed, then try again.\n\nDetails: {exc}"
        )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
