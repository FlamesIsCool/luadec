from __future__ import annotations

import logging

import discord
import httpx
from discord import app_commands
from discord.ext import commands

from config import load_bot_settings


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("luadec-bot")

ALLOWED_EXTENSIONS = {".lua", ".luau", ".txt"}
EMBED_COLOR = discord.Color.from_rgb(255, 255, 255)

bot_settings = load_bot_settings()


def decode_attachment_payload(payload: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("The uploaded file could not be decoded as text.")


def extension_is_allowed(file_name: str) -> bool:
    lowered = file_name.lower()
    return any(lowered.endswith(ext) for ext in ALLOWED_EXTENSIONS)


class LuaDecBot(commands.Bot):
    def __init__(self) -> None:
        super().__init__(command_prefix="!", intents=discord.Intents.none())

    async def setup_hook(self) -> None:
        synced = await self.tree.sync()
        logger.info("Synced %s global commands", len(synced))

    async def on_ready(self) -> None:
        if self.user:
            logger.info("Logged in as %s (%s)", self.user, self.user.id)


bot = LuaDecBot()


@bot.tree.command(name="protect", description="Upload a Lua file and get back the loader snippet.")
@app_commands.describe(
    script_file="Upload the Lua file you want to protect.",
    script_key="The key users must set in script_key before the loader runs.",
)
async def protect(interaction: discord.Interaction, script_file: discord.Attachment, script_key: str) -> None:
    await interaction.response.defer(thinking=True, ephemeral=True)

    if not script_file.filename or not extension_is_allowed(script_file.filename):
        await interaction.followup.send("Upload a `.lua`, `.luau`, or `.txt` file.", ephemeral=True)
        return

    if not script_key.strip():
        await interaction.followup.send("Enter a non-empty script key.", ephemeral=True)
        return

    try:
        payload = await script_file.read()
        script_source = decode_attachment_payload(payload)
        if not script_source.strip():
            raise ValueError("The uploaded file is empty.")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{bot_settings.server_base_url}/api/upload",
                headers={"X-API-Key": bot_settings.server_upload_api_key},
                json={
                    "script": script_source,
                    "script_key": script_key.strip(),
                    "script_name": script_file.filename,
                    "owner_id": str(interaction.user.id),
                    "owner_name": str(interaction.user),
                },
            )

        response.raise_for_status()
        data = response.json()
        loader = str(data.get("loader", "")).strip()
        if not loader:
            raise ValueError("Server returned an empty loader.")
    except Exception as exc:
        logger.exception("Protect command failed")
        await interaction.followup.send(f"Upload failed.\n`{exc}`", ephemeral=True)
        return

    embed = discord.Embed(
        title="Loader",
        description=f"```lua\n{loader}\n```",
        color=EMBED_COLOR,
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


def main() -> None:
    bot.run(bot_settings.discord_token, log_handler=None)


if __name__ == "__main__":
    main()
