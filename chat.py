"""Encrypted chat room TUI on top of Supabase.

Run:  python chat.py            (reads SUPABASE_URL / SUPABASE_ANON_KEY from .env)
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime

from dotenv import load_dotenv
from rich.markup import escape
from supabase import AsyncClient, acreate_client
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, RichLog

from crypto import DecryptionError, RoomCipher, derive_key

TABLE = "messages"
HISTORY_LIMIT = 100


# ---------------------------------------------------------------- login screen
class LoginScreen(Screen):
    CSS = """
    LoginScreen { align: center middle; }
    #box { width: 60; height: auto; border: round $accent; padding: 1 2; }
    #box Input { margin-bottom: 1; }
    #error { color: $error; height: auto; }
    """

    def __init__(self, error: str = "", username: str = "", room: str = "lobby"):
        super().__init__()
        self._error, self._username, self._room = error, username, room

    def compose(self) -> ComposeResult:
        with Vertical(id="box"):
            yield Label("[b]Join encrypted chat[/b]\n")
            yield Input(self._username, placeholder="Your name", id="username")
            yield Input(self._room, placeholder="Room", id="room")
            yield Input(placeholder="Shared passphrase", password=True, id="passphrase")
            yield Label(self._error, id="error")
            yield Button("Join", variant="primary", id="join")

    @on(Input.Submitted)
    @on(Button.Pressed, "#join")
    def submit(self) -> None:
        username = self.query_one("#username", Input).value.strip()
        room = self.query_one("#room", Input).value.strip()
        passphrase = self.query_one("#passphrase", Input).value
        if not (username and room and passphrase):
            self.query_one("#error", Label).update("All fields are required.")
            return
        if len(passphrase) < 8:
            self.query_one("#error", Label).update("Use a passphrase of at least 8 characters.")
            return
        self.dismiss((username[:32], room[:64], passphrase))


# ----------------------------------------------------------------- chat screen
class ChatScreen(Screen):
    BINDINGS = [("ctrl+q", "app.quit", "Quit"), ("ctrl+l", "clear", "Clear")]
    CSS = """
    #log { height: 1fr; border: round $primary; }
    #msg { dock: bottom; }
    """

    def __init__(self, client: AsyncClient, cipher: RoomCipher, username: str):
        super().__init__()
        self.client, self.cipher, self.username = client, cipher, username
        self.seen_ids: set[int] = set()
        self.channel = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log", wrap=True, markup=True)
        yield Input(placeholder="Type a message and press Enter", id="msg")
        yield Footer()

    def on_mount(self) -> None:
        self.app.sub_title = f"#{self.cipher.room} as {self.username}"
        self.query_one("#msg", Input).focus()
        self.start()

    def action_clear(self) -> None:
        self.query_one(RichLog).clear()

    # -- rendering
    def show_row(self, row: dict) -> bool:
        """Decrypt and print one DB row. Returns True if it decrypted."""
        if row["id"] in self.seen_ids:
            return True
        self.seen_ids.add(row["id"])
        ts = datetime.fromisoformat(row["created_at"]).astimezone().strftime("%H:%M")
        name = escape(row["username"])
        log = self.query_one(RichLog)
        try:
            text = self.cipher.decrypt(row["username"], row["nonce"], row["ciphertext"])
        except DecryptionError:
            log.write(f"[dim]{ts}[/] [b]{name}[/]: [red i]<cannot decrypt: different passphrase?>[/]")
            return False
        colour = "green" if row["username"] == self.username else "cyan"
        log.write(f"[dim]{ts}[/] [b {colour}]{name}[/]: {escape(text)}")
        return True

    def system(self, text: str) -> None:
        self.query_one(RichLog).write(f"[yellow]* {text}[/]")

    # -- realtime + history
    @work(exclusive=True)
    async def start(self) -> None:
        room = self.cipher.room

        def on_insert(payload: dict) -> None:
            # Runs on the same asyncio loop as Textual, so touching widgets is safe.
            record = payload["data"].get("record")
            if record and self.is_attached:
                self.show_row(record)

        def on_status(status, err) -> None:
            if err:
                self.system(f"realtime: {status} {err}")

        # Subscribe first, then load history, so nothing is missed in between.
        self.channel = self.client.channel(f"room:{room}")
        self.channel.on_postgres_changes(
            "INSERT", schema="public", table=TABLE, filter=f"room=eq.{room}", callback=on_insert
        )
        await self.channel.subscribe(on_status)

        res = (
            await self.client.table(TABLE)
            .select("*")
            .eq("room", room)
            .order("created_at", desc=True)
            .limit(HISTORY_LIMIT)
            .execute()
        )
        rows = list(reversed(res.data))
        ok = [self.show_row(r) for r in rows]
        if rows and not any(ok):
            # Every existing message failed -> almost certainly a typo in the passphrase.
            await self.client.remove_channel(self.channel)
            self.app.call_later(self.app.relogin, "None of the room's messages decrypt. Wrong passphrase?",
                                self.username, room)
            return
        self.system(f"joined #{room} ({len(rows)} earlier messages). Messages are end-to-end encrypted.")

    @on(Input.Submitted, "#msg")
    async def send(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        nonce, ct = self.cipher.encrypt(self.username, text)
        try:
            await self.client.table(TABLE).insert(
                {"room": self.cipher.room, "username": self.username, "nonce": nonce, "ciphertext": ct}
            ).execute()
        except Exception as exc:  # network / RLS / check-constraint errors
            self.system(f"send failed: {exc}")


# ------------------------------------------------------------------------ app
class ChatApp(App):
    TITLE = "Supabase Encrypted Chat"

    def __init__(self, url: str, key: str):
        super().__init__()
        self.url, self.key = url, key
        self.client: AsyncClient | None = None

    async def on_mount(self) -> None:
        self.client = await acreate_client(self.url, self.key)
        self.relogin()

    def relogin(self, error: str = "", username: str = "", room: str = "lobby") -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(LoginScreen(error, username, room), self.on_login)

    @work
    async def on_login(self, result: tuple[str, str, str]) -> None:
        username, room, passphrase = result
        self.notify("Deriving key...", timeout=2)
        # Argon2 is CPU-heavy; keep the UI responsive.
        key = await asyncio.to_thread(derive_key, passphrase, room)
        await self.push_screen(ChatScreen(self.client, RoomCipher(key, room), username))

    async def on_unmount(self) -> None:
        if self.client:
            try:
                await self.client.remove_all_channels()
            except Exception:
                pass


def main() -> None:
    load_dotenv()
    url, key = os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_ANON_KEY")
    if not url or not key:
        raise SystemExit("Set SUPABASE_URL and SUPABASE_ANON_KEY (see .env.example).")
    ChatApp(url, key).run()


if __name__ == "__main__":
    main()
