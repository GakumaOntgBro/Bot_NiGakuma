# --- START OF FILE bot_worker.py ---

import os
import sys
import io
import time
import random
import re
import json
from datetime import datetime
import logging
import requests
import signal
import threading
import html
from telegram import Bot, User, InputMediaPhoto
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Updater, CommandHandler, CallbackQueryHandler, MessageHandler,
    Filters, CallbackContext
)
from telegram.error import TelegramError, BadRequest
from telegram.constants import PARSEMODE_HTML

# --- Logging Configuration ---
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Bot Configuration ---
BOT_VERSION = "GAKUMA_BOT_v3.8_STABLE"
TOKEN = "7607247495:AAHxmuG9tV_8o5DDm0LhtEGxRHc2WUw8HXw"
ADMIN_ID = 5163892491
PANEL_API_URL = os.environ.get("PANEL_API_URL", "http://127.0.0.1:2004")
INTERNAL_API_SECRET = "a-super-secret-key-for-internal-api-calls"

PUBLIC_FEEDBACK_CHANNEL_ID = -1002898093709
PUBLIC_FEEDBACK_CHANNEL_LINK = "https://t.me/kupalkabagakuma"

OWNER_USERNAME = "KenshiKupal"
REPORT_GENERATOR = "Kenze03"
DEFAULT_LINES_TO_SEND, LIFETIME_LINES_TO_SEND, PRIVATE_LINES_TO_SEND = 300, 500, 1000
INFO_GEN_COOLDOWN = 30 * 60

ADMIN_DATABASE_FOLDER = 'admin_database'
POINT_COSTS = {'1d': 100, '2d': 150, '3d': 200, 'private': 100}
FEEDBACK_POINTS = 2

# --- UI Styling & Constants ---
INFO_ICON, SUCCESS_ICON, ERROR_ICON, WARN_ICON = "ℹ️", "✅", "❌", "⚠️"
LOCK_ICON, ROCKET_ICON, KEY_ICON, USER_ICON, FEEDBACK_LOG_ICON = "🔐", "🚀", "🔑", "👤", "📜"
HELP_ICON, BACK_ICON, FOLDER_ICON, CONVERT_ICON, FEEDBACK_ICON = "❓", "🔙", "📁", "🎁", "🗣️"
SEPARATOR = "----------------------------------------"

PUBLIC_DATABASE_FOLDERS = ['database', 'database1', 'database2', 'database3', 'database4', 'database5', 'database6']
KEYWORDS_CATEGORIES = {
    "🪖 Garena": { "💀 100000": "100000.connect.garena.com", "💀 100054": "100054.connect.garena.com", "💀 100055": "100055.connect.garena.com", "💀 100056": "100056.connect.garena.com", "💀 100063": "100063.connect.garena.com", "💀 100066": "100066.connect.garena.com", "💀 100070": "100070.connect.garena.com", "💀 100071": "100071.connect.garena.com", "💀 100072": "100072.connect.garena.com", "💀 100075": "100075.connect.garena.com", "💀 100080": "100080.connect.garena.com", "💀 100081": "100081.connect.garena.com", "💀 100082": "100082.connect.garena.com", "💀 100084": "100084.connect.garena.com", "💀 100088": "100088.connect.garena.com", "💀 100089": "100089.connect.garena.com", "💀 100090": "100090.connect.garena.com", "💀 100091": "100091.connect.garena.com", "💀 100093": "100093.connect.garena.com", "💀 Activision": "codm.activision.com", "💀 AuthGop": "authgop.garena.com", "💀 CODM (SSO)": "sso.garena.com", "💀 CODM Account": "garena.com", "💀 Call of Duty": "100082.connect.garena.com", "💀 CodmLEG": "callofdutyleague.com", "💀 Garena Account": "account.garena.com", "💀 GasLite": "com.garena.gaslite", "💀 Normal CODM": "profile.callofduty.com", },
    "🛡️ Mobile Legends": { "⚔️🏆 Hidden MLBB Site": "play.mobilelegends.com", "⚔️🏆 MLBB Premium": "m.mobilelegends.com", "⚔️🏆 MLBB Site": "mtacc.mobilelegends.com", "⚔️🏆 Real MLBB Site": "mobilelegends.com", },
    "🌐 Social Media": { "🎧 Discord": "discord.com", "📘 Facebook": "facebook.com", "📱 Instagram": "instagram.com", "🎵 TikTok": "tiktok.com" }, "🎬 Cinema & Music": { "🎬 Bilibili": "bilibili.com", "🎬 CrunchyRoll": "crunchyroll.com", "🎬 Netflix": "netflix.com", "🎧 Spotify": "spotify.com", "🎬 YouTube": "youtube.com" },
    "🎮 Online Games": { "🔫 BLOODSTRIKE": "bloodstrike.com", "🔥 Free Fire": "ff.garena.com", "🎮 L.O.L": "leagueoflegends.com", "🏘️ Minecraft": "minecraft.net", "🔫 PUBG": "accounts.pubg.com", "🎯 Riot Games": "auth.riotgames.com", "🕹️ Roblox": "roblox.com" },
    "🛍️ Shopping & Other": { "🛍️ AliExpress": "aliexpress.com", "🛍️ Amazon": "amazon.com", "🛍️ Codashop": "codashop.com", "📩 Google": "google.com", "📩 Outlook": "outlook.com", "📩 Paypal": "paypal.com", "📩 Yahoo": "yahoo.com" },
    "💎 CRYPTO": { "💎 BINANCE": "binance.com", "💎 BITGET": "bitget.com", "💎 COINBASE": "coinbase.com", "💎 OKX": "okx.com", "💎 TRUSTWALLET": "trustwallet.com" },
    "🏦 Banking": { "🏦 BDO": "bdo.com.ph", "🏦 BPI": "bpi.com.ph", "🏦 Chinabank": "chinabank.ph", "🏦 Landbank": "landbank.com", "🏦 Metrobank": "metrobank.com.ph", "🏦 PNB": "pnb.com.ph", "🏦 RCBC": "rcbc.com", "🏦 Security Bank": "securitybank.com", "🏦 UnionBank": "unionbankph.com" },
    "🏦 Global Banking": { "🏦 Bank of America": "bankofamerica.com", "🏦 Chase": "chase.com", "🏦 Citi": "citibank.com", "🏦 HSBC": "hsbc.com", "🏦 Standard Chartered": "sc.com", "🏦 Wells Fargo": "wellsfargo.com" }
}
ALL_DOMAINS = {v: k for category in KEYWORDS_CATEGORIES.values() for k, v in category.items()}

media_group_cache = {}; media_group_lock = threading.Lock()

def api_request(endpoint, method='get', data=None):
    try:
        headers = {'X-Internal-Secret': INTERNAL_API_SECRET}
        response = requests.request(method, f"{PANEL_API_URL}{endpoint}", json=data, timeout=30, headers=headers)
        response.raise_for_status(); return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API Error to {endpoint}: {e}"); return {"success": False, "message": "Could not connect to the main server."}

def log_user_activity(user_id: int):
    """Sends a fire-and-forget request to the panel to log user activity."""
    def _log():
        try:
            api_request('/api/bot/log_traffic', 'post', {'telegram_user_id': user_id})
        except Exception:
            pass # Fail silently as this is not a critical function
    threading.Thread(target=_log).start()

def admin_api_generate_request(folder, service_file, quantity):
    try:
        headers = {'X-Internal-Secret': INTERNAL_API_SECRET}
        form_data = {'folder': folder, 'service_file': service_file, 'quantity': quantity}
        response = requests.post(f"{PANEL_API_URL}/api/admin/generate", data=form_data, timeout=60, headers=headers)
        response.raise_for_status()
        return {"success": True, "lines": response.text}
    except requests.exceptions.RequestException as e:
        logger.error(f"API Error to /api/admin/generate: {e}")
        try:
            message = response.json().get("error", f"Admin generation failed. Status: {response.status_code}")
        except (ValueError, json.JSONDecodeError):
            message = f"Admin generation failed. Status: {response.status_code}. Response: {response.text[:100]}"
        return {"success": False, "message": message}

def check_access(user_id):
    if user_id == ADMIN_ID: return {"has_access": True, "is_lifetime": True, "is_admin": True, "is_from_points": False, "points": 9999}
    return api_request("/api/bot/check_access", 'post', {"telegram_user_id": user_id})

def delete_message(context: CallbackContext, chat_id: int, message_id: int):
    try: context.bot.delete_message(chat_id, message_id)
    except (TelegramError, BadRequest): pass

def format_to_user_pass(line: str) -> str:
    parts = line.strip().split(':'); return f"{parts[-2]}:{parts[-1]}" if len(parts) >= 2 else line.strip()

def styled_message(title: str, body_lines: list, footer_text: str):
    title_line = f"--- {title} ---"
    body = "\n".join(body_lines)
    return f"<b>{html.escape(title_line)}</b>\n\n{body}\n\n{SEPARATOR}\n{footer_text}"

def send_or_edit(update: Update, context: CallbackContext, text: str, reply_markup: InlineKeyboardMarkup = None, parse_mode=PARSEMODE_HTML):
    try:
        query = update.callback_query
        if query:
            if query.message.text is None:
                try: context.bot.delete_message(query.message.chat_id, query.message.message_id)
                except (TelegramError, BadRequest): pass
                context.bot.send_message(query.message.chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
                query.answer()
                return

            if query.message.text == text and query.message.reply_markup == reply_markup:
                try: query.answer()
                except BadRequest: pass
                return
            query.edit_message_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
        else:
            update.message.reply_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            logger.error(f"Failed to send/edit message: {e}\nParse Mode: {parse_mode}\nText was: {text}")
            if query:
                 try: query.answer("An error occurred.", show_alert=True)
                 except BadRequest: pass
        elif query:
            try: query.answer()
            except BadRequest: pass

def handle_no_access(update: Update, context: CallbackContext):
    if update.callback_query: update.callback_query.answer()
    title = f"{LOCK_ICON} ACCESS DENIED"
    body = ["Premium Access Required.", "Please redeem a key to use this feature."]
    text = styled_message(title, body, f"G Λ K U M Λ Bot")
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def start(update: Update, context: CallbackContext):
    user = update.effective_user
    log_user_activity(user.id)
    access = check_access(user.id)
    
    status_text = ""
    if access.get("is_admin"): status_text = "👑 Status: Admin"
    elif access.get("is_lifetime"): status_text = "🌟 Status: Lifetime"
    elif access.get("has_access"): status_text = f"{SUCCESS_ICON} Status: Active / Aktibo"
    elif access.get("reason") == 'expired': status_text = f"{ERROR_ICON} Status: Expired / Nag-expire na"
    else: status_text = f"{WARN_ICON} Status: No Key / Walang Key"
    
    points_line = f"💎 Points / Puntos: {access.get('points', 0)}"
    body = [f"Welcome, {html.escape(user.first_name)}!", "", status_text, points_line, "", "Select an option to begin."]
    text = styled_message("G Λ K U M Λ - MAIN MENU", body, BOT_VERSION)
    
    kbd = []
    if access.get("has_access"):
        kbd.append([InlineKeyboardButton(f"{ROCKET_ICON} Generate Accounts", callback_data="generate_menu")])
        if not access.get("is_from_points"):
            kbd.append([InlineKeyboardButton(f"{INFO_ICON} Get With Info", callback_data="info_warning")])
            kbd.append([InlineKeyboardButton(f"{LOCK_ICON} Private Txt", callback_data="private_start")])
        kbd.append([InlineKeyboardButton(f"{USER_ICON} My Info", callback_data="show_user_info"), InlineKeyboardButton(f"{HELP_ICON} Help", callback_data="show_help")])
        kbd.append([InlineKeyboardButton(f"{CONVERT_ICON} Convert Points", callback_data="convert_points_menu")])
        kbd.append([InlineKeyboardButton(f"{FEEDBACK_ICON} Submit Feedback", callback_data="feedback_start"), InlineKeyboardButton(f"{FEEDBACK_LOG_ICON} View Feedbacks", callback_data="view_feedback_menu")])
        kbd.append([InlineKeyboardButton(f"{KEY_ICON} Redeem Key", callback_data="redeem_prompt")])
    else:
        kbd.append([InlineKeyboardButton(f"{KEY_ICON} Redeem Key / Mag-redeem", callback_data="redeem_prompt")])
        kbd.append([InlineKeyboardButton(f"{HELP_ICON} Help / Tulong", callback_data="show_help")])
        if access.get("has_access") or access.get("reason") == 'expired':
            kbd.append([InlineKeyboardButton(f"{CONVERT_ICON} Convert Points", callback_data="convert_points_menu")])
            kbd.append([InlineKeyboardButton(f"{FEEDBACK_ICON} Submit Feedback", callback_data="feedback_start")])

    if user.id == ADMIN_ID:
        if not any("Admin Generate" in btn.text for row in kbd for btn in row):
            kbd.insert(0, [InlineKeyboardButton("👑 Admin Generate", callback_data="admin_browse_/")])
        if not any("Go to Web Panel" in btn.text for row in kbd for btn in row):
            kbd.append([InlineKeyboardButton("🌐 Go to Web Panel", url=PANEL_API_URL)])
    
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def redeem_prompt(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    context.user_data['next_message'] = 'redeem_key'
    title = f"{KEY_ICON} REDEEM KEY"
    body = ["Please send your subscription key now."]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back to Main Menu", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def handle_text_input(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    next_action = context.user_data.get('next_message', None)
    if not next_action: return
    user, text_input = update.effective_user, update.message.text.strip()
    
    if next_action == 'redeem_key':
        context.user_data.pop('next_message', None)
        res = api_request("/api/bot/redeem_key", 'post', {"key": text_input, "telegram_user_id": user.id, "telegram_username": user.username})
        message_from_api = res.get('message', 'An unknown error occurred.')
        tl_message = message_from_api.replace("Success! Your new expiry is:", "Tagumpay! Ang iyong bagong expiry ay:").replace("Invalid Key", "Di-wastong Key").replace("Key already used by user", "Ang key ay ginamit na ng user")
        icon = SUCCESS_ICON if res.get('success') else ERROR_ICON
        title = f"{icon} KEY REDEMPTION"
        body = [html.escape(message_from_api), html.escape(tl_message)]
        text = styled_message(title, body, BOT_VERSION)
        send_or_edit(update, context, text)
        if res.get('success'): start(update, context)
        
    elif next_action == 'private_key':
        context.user_data.pop('next_message', None)
        res = api_request('/api/bot/redeem_private_key', 'post', {'key': text_input, 'telegram_user_id': user.id})
        if res.get('success'):
            context.user_data['has_private_access'] = True
            private_category_menu(update, context)
        else:
            message = res.get('message', 'An error occurred.')
            tl_message = message.replace("Invalid Private Access Key.", "Di-wasto ang Private Access Key.").replace("This key has already been used.", "Ang key na ito ay nagamit na.")
            title = f"{ERROR_ICON} PRIVATE ACCESS"
            body = [html.escape(message), html.escape(tl_message)]
            text = styled_message(title, body, BOT_VERSION)
            send_or_edit(update, context, text)

    elif next_action == 'admin_gen_quantity':
        if update.effective_user.id != ADMIN_ID: return
        try:
            quantity = int(text_input)
            if not (1 <= quantity <= 5000): raise ValueError("Quantity must be between 1 and 5000.")
        except (ValueError, TypeError):
            update.message.reply_text("❌ Invalid input. Please send a number between 1 and 5000.")
            return

        file_path = context.user_data.pop('admin_gen_file_path', None)
        context.user_data.pop('next_message', None)
        
        if not file_path:
            update.message.reply_text("❌ An error occurred. File selection was lost. Please start over.")
            return start(update, context)

        msg = update.message.reply_text("⏳ Generating for you, admin...")
        res = admin_api_generate_request(folder=ADMIN_DATABASE_FOLDER, service_file=file_path, quantity=quantity)
        delete_message(context, msg.chat_id, msg.message_id)

        if res.get("success"):
            lines_content = res.get("lines", "")
            if not lines_content.strip():
                update.message.reply_text(f"✅ Generation complete, but the result was empty. The source file might be empty or has issues.")
                return

            file_stream = io.BytesIO(lines_content.encode('utf-8'))
            clean_display_name = ''.join(e for e in os.path.basename(file_path) if e.isalnum())
            file_stream.name = f"ADMIN_GEN_{clean_display_name}_{datetime.now().strftime('%y%m%d')}.txt"
            
            caption = (f"<b>👑 Admin Generation Complete</b>\n\n"
                       f"<b>Source:</b> <code>{html.escape(file_path)}</code>\n"
                       f"<b>Quantity Requested:</b> <code>{quantity}</code>")
            
            context.bot.send_document(
                chat_id=update.effective_user.id, document=file_stream, caption=caption,
                parse_mode=PARSEMODE_HTML, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")]])
            )
        else:
            error_message = res.get('message', 'An unknown error occurred during generation.')
            update.message.reply_text(f"❌ Generation Failed:\n\n{html.escape(error_message)}")


def show_user_info(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query, user_id = update.callback_query, update.effective_user.id
    query.answer()
    res = check_access(user_id)
    points_balance = res.get('points', 0)
    
    body = [f"User ID: <code>{user_id}</code>", f"Username: @{query.from_user.username or 'N/A'}"]
    if res.get("has_access"):
        expiry_date_str = "Never (Lifetime)"
        if res.get('expires_at') and res.get('expires_at') != "Lifetime":
            try: expiry_date_str = datetime.fromisoformat(res['expires_at'].replace("Z", "+00:00")).strftime('%Y-%m-%d %H:%M UTC')
            except: expiry_date_str = res.get('expires_at', 'N/A')
        key_type = "From Points" if res.get('is_from_points') else res.get('key_type', 'N/A').title()
        
        body.extend([
            f"Status: ✅ Active",
            f"Key Type: {html.escape(key_type)}",
            f"Expires: {html.escape(expiry_date_str)}",
            f"💎 Points: {points_balance}"
        ])
    else:
        reason = res.get('reason', 'Inactive').title()
        body.extend([
            f"Status: ❌ {reason}",
            f"💎 Points: {points_balance}",
            "",
            html.escape(res.get('message', 'Please redeem a key.'))
        ])
            
    text = styled_message(f"{USER_ICON} YOUR INFO", body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def show_help(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    body = [
        "Welcome to GAKUMA BOT!", "",
        "<b>1. Generate Accounts:</b>", "The main feature. Get fresh lists of accounts.", "",
        "<b>2. Get With Info:</b>", "Provides unchecked accounts with full details (cooldown applies).", "",
        "<b>3. Private Txt:</b>", "Access special databases using a one-time private key.", "",
        "<b>4. Submit Feedback:</b>", f"Earn {FEEDBACK_POINTS} points for each valid feedback.", "",
        f"Owner: @{OWNER_USERNAME}"
    ]
    text = styled_message(f"{HELP_ICON} HELP & SUPPORT", body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def feedback_start(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not PUBLIC_FEEDBACK_CHANNEL_ID:
        if update.callback_query:
            update.callback_query.answer("Feedback system is not configured by the admin.", show_alert=True)
        else:
            update.message.reply_text("Feedback system is not configured by the admin.")
        return
    if update.callback_query: update.callback_query.answer()
    context.user_data['next_message'] = 'feedback_photo'
    title = f"{FEEDBACK_ICON} SUBMIT FEEDBACK"
    body = ["Please send a photo (or multiple photos) with your message as the caption.", f"You will earn {FEEDBACK_POINTS} points and your feedback will be posted publicly."]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def process_and_post_feedback(context: CallbackContext, user: User, file_id: str, caption: str):
    api_res = api_request('/api/bot/submit_feedback', 'post', {
        'telegram_user_id': user.id,
        'telegram_username': user.username,
        'caption': caption,
        'file_id': file_id
    })

    if not api_res or not api_res.get('success'):
        context.bot.send_message(chat_id=user.id, text="There was a server error submitting your feedback. Please try again later.")
        return

    new_balance = api_res.get('new_balance', 'N/A')
    title = f"{SUCCESS_ICON} FEEDBACK RECEIVED"
    body = [f"Thank you! You've been awarded {FEEDBACK_POINTS} points.", f"New balance: {new_balance}"]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")]]
    context.bot.send_message(chat_id=user.id, text=text, reply_markup=InlineKeyboardMarkup(kbd), parse_mode=PARSEMODE_HTML)

    try:
        username = user.username or f"User_{user.id}"
        public_caption = f"<b>Feedback from @{html.escape(username)}:</b>\n\n{html.escape(caption)}"
        context.bot.send_photo(chat_id=PUBLIC_FEEDBACK_CHANNEL_ID, photo=file_id, caption=public_caption, parse_mode=PARSEMODE_HTML)
        logger.info(f"Successfully posted feedback from {user.id} to public channel {PUBLIC_FEEDBACK_CHANNEL_ID}.")
    except Exception as e:
        logger.error(f"Failed to post feedback to public channel: {e}")
        context.bot.send_message(chat_id=ADMIN_ID, text=f"⚠️ Failed to auto-post feedback from @{username} to the public channel. Please check bot permissions.\nError: {e}")

def process_media_group(context: CallbackContext):
    job_context = context.job.context
    media_group_id, user = job_context['media_group_id'], job_context['user']
    with media_group_lock:
        if media_group_id not in media_group_cache: return
        media_items = media_group_cache.pop(media_group_id)
    caption_text = next((item['caption'] for item in media_items if item['caption']), "No caption provided.")
    first_file_id = media_items[0]['file_id']
    process_and_post_feedback(context, user, first_file_id, caption_text)

def handle_photo_input(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if context.user_data.get('next_message') != 'feedback_photo': return
    user, message = update.effective_user, update.message
    delete_message(context, user.id, message.message_id)
    if not message.media_group_id:
        context.user_data.pop('next_message', None)
        file_id = message.photo[-1].file_id
        caption = message.caption or "No caption provided."
        process_and_post_feedback(context, user, file_id, caption)
        return
    with media_group_lock:
        if message.media_group_id not in media_group_cache: media_group_cache[message.media_group_id] = []
        media_group_cache[message.media_group_id].append({'file_id': message.photo[-1].file_id, 'caption': message.caption})
        for job in context.job_queue.get_jobs_by_name(str(message.media_group_id)): job.schedule_removal()
    context.job_queue.run_once(process_media_group, when=2, context={'media_group_id': message.media_group_id, 'user': user}, name=str(message.media_group_id))
    context.user_data.pop('next_message', None)

def view_feedback_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    title = f"{FEEDBACK_LOG_ICON} VIEW FEEDBACKS"
    body = ["Choose an option to view feedbacks."]
    kbd = [[InlineKeyboardButton("📜 My Submissions", callback_data="my_submissions")]]
    if PUBLIC_FEEDBACK_CHANNEL_LINK:
        kbd.append([InlineKeyboardButton("🌐 Public Channel", url=PUBLIC_FEEDBACK_CHANNEL_LINK)])
    else:
        kbd.append([InlineKeyboardButton("🌐 Public Channel (Not Set)", callback_data="noop_feedback_link")])
    kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")])
    text = styled_message(title, body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def my_submissions_handler(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    user_id = update.effective_user.id
    send_or_edit(update, context, styled_message("LOADING...", ["Fetching your feedback history..."], BOT_VERSION))
    res = api_request('/api/bot/get_my_feedback', 'post', {'telegram_user_id': user_id})
    if not res or not res.get('success'):
        send_or_edit(update, context, styled_message(f"{ERROR_ICON} ERROR", ["Could not fetch your feedback."], BOT_VERSION))
        return
    feedbacks = res.get('feedbacks', [])
    if not feedbacks:
        send_or_edit(update, context, styled_message("NO FEEDBACK", ["You have not submitted any feedback yet."], BOT_VERSION), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="view_feedback_menu")]]))
        return
    delete_message(context, query.message.chat_id, query.message.message_id)
    context.bot.send_message(chat_id=user_id, text=f"--- Your Last {len(feedbacks)} Feedbacks ---")
    for fb in feedbacks:
        try:
            ts = datetime.fromisoformat(fb['timestamp']).strftime('%Y-%m-%d %H:%M')
            caption = f"<b>Submitted:</b> {ts}\n\n{html.escape(fb['caption'] or '')}"
            context.bot.send_photo(chat_id=user_id, photo=fb['file_id'], caption=caption, parse_mode=PARSEMODE_HTML)
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error sending stored feedback photo to user {user_id}: {e}")
            context.bot.send_message(chat_id=user_id, text=f"Error loading one of your feedbacks.")
    context.bot.send_message(chat_id=user_id, text="--- End of History ---", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"{BACK_ICON} Back to Feedback Menu", callback_data="view_feedback_menu")]]))

def convert_points_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    res = check_access(update.effective_user.id)
    points = res.get('points', 0)
    title = f"{CONVERT_ICON} CONVERT POINTS"
    body = [f"Your current balance: {points} points", "Select an option to convert your points."]
    kbd = []
    duration_map = {'1d': '1 Day Key', '2d': '2 Days Key', '3d': '3 Days Key', 'private': 'Private Txt Access'}
    for key_type, cost in POINT_COSTS.items():
        button_text = f"{duration_map.get(key_type, key_type)} - {cost} Points"
        if points >= cost:
            kbd.append([InlineKeyboardButton(f"✅ {button_text}", callback_data=f"perform_conversion_{key_type}")])
        else:
            kbd.append([InlineKeyboardButton(f"❌ {button_text}", callback_data="noop")])
    kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")])
    text = styled_message(title, body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def handle_point_conversion(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer()
    conversion_type = query.data.replace("perform_conversion_", "", 1)
    send_or_edit(update, context, styled_message("⏳ PROCESSING...", ["Please wait..."], BOT_VERSION))
    res = api_request('/api/bot/convert_points', 'post', {'telegram_user_id': update.effective_user.id, 'conversion_type': conversion_type})
    if res and res.get('success'):
        if conversion_type == 'private':
            title, body = f"{SUCCESS_ICON} SUCCESS", ["Conversion successful!", f"Your Private Access Key is: <code>{html.escape(res.get('key_string'))}</code>", "Use it in the 'Private Txt' section."]
            kbd = [[InlineKeyboardButton(f"{LOCK_ICON} Go to Private Txt", callback_data="private_start")], [InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")]]
        else:
            title, body = f"{SUCCESS_ICON} SUCCESS", ["Conversion successful!", f"Your new {res.get('duration_str')} key is: <code>{html.escape(res.get('key_string'))}</code>", "Please redeem this key to activate it."]
            kbd = [[InlineKeyboardButton(f"{KEY_ICON} Redeem Now", callback_data="redeem_prompt")], [InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")]]
    else:
        title, body = f"{ERROR_ICON} FAILED", ["Conversion failed.", html.escape(res.get('message', 'An unknown error occurred.'))]
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="convert_points_menu")]]
    text = styled_message(title, body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def noop_callback(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer("This option is unavailable or you have insufficient points.", show_alert=True)

def noop_feedback_link_callback(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    query = update.callback_query; query.answer("The admin has not set the public feedback channel link.", show_alert=True)

def info_warning(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer()
    title = f"{WARN_ICON} DISCLAIMER"
    body = ["Accounts in this section are unchecked and might be invalid.", "Proceed at your own risk.", "You can generate one account every 30 minutes."]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{SUCCESS_ICON} I Understand", callback_data="info_country_select")], [InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def check_cooldown(update: Update, context: CallbackContext):
    if update.effective_user.id != ADMIN_ID:
        last_gen_time = context.user_data.get('last_info_gen_time', 0)
        if time.time() - last_gen_time < INFO_GEN_COOLDOWN:
            remaining = INFO_GEN_COOLDOWN - (time.time() - last_gen_time); mins, secs = divmod(remaining, 60)
            title = "⏳ COOLDOWN ACTIVE"
            body = [f"Please wait {int(mins)}m {int(secs)}s."]
            text = styled_message(title, body, BOT_VERSION)
            kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return True
    return False

def info_menu_country_select(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer()
    if check_cooldown(update, context): return
    send_or_edit(update, context, styled_message("LOADING...", ["Fetching available countries..."], BOT_VERSION))
    res = api_request('/api/bot/list_info_files')
    if not res.get('success') or not res.get('files'):
        text = styled_message(f"{ERROR_ICON} NO FILES", ["No 'With Info' files are available."], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    context.user_data['info_files'] = res.get('files', [])
    countries = sorted(list(set(path.split('/')[0] for path in context.user_data['info_files'] if '/' in path)))
    if not countries:
        text = styled_message(f"{ERROR_ICON} NOT ORGANIZED", ["Could not find country folders."], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    buttons = [InlineKeyboardButton(f"🏴 {cc}", callback_data=f"infostatus_{cc}") for cc in countries]
    kbd = [buttons[i:i+3] for i in range(0, len(buttons), 3)]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="info_warning")])
    text = styled_message(f"{INFO_ICON} GET WITH INFO - Step 1", ["Select a Country"], BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def info_menu_status_select(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer(); selected_country = query.data.split('_', 1)[1]
    context.user_data['selected_country'] = selected_country
    all_info_files = context.user_data.get('info_files', [])
    statuses = sorted(list(set(p.split('/')[1] for p in all_info_files if p.startswith(f"{selected_country}/") and len(p.split('/')) > 1)))
    if not statuses:
        text = styled_message(f"{ERROR_ICON} NOT ORGANIZED", ["No status categories found for this country."], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="info_country_select")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    buttons = [InlineKeyboardButton(f"{FOLDER_ICON} {status.title()}", callback_data=f"infolevel_{status}") for status in statuses]
    kbd = [buttons[i:i+2] for i in range(0, len(buttons), 2)]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="info_country_select")])
    body = [f"Country: {selected_country}", "Select Status"]
    text = styled_message(f"{INFO_ICON} GET WITH INFO - Step 2", body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def info_menu_level_select(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer(); selected_status = query.data.split('_', 1)[1]; selected_country = context.user_data.get('selected_country')
    if not selected_country: return start(update, context)
    access_info = check_access(update.effective_user.id); is_lifetime = access_info.get('is_lifetime', False)
    all_info_files = context.user_data.get('info_files', [])
    eligible_files = [path for path in all_info_files if path.startswith(f"{selected_country}/{selected_status}/")]
    buttons = []
    for path in sorted(eligible_files):
        base_filename = os.path.basename(path); level = None
        level_single_match = re.search(r'[Ll][Vv][Ll]_(\d+)', base_filename, re.IGNORECASE)
        level_range_match = re.search(r'[Ll][Ee][Vv][Ee][Ll]_(\d+)-\d+', base_filename, re.IGNORECASE)
        if level_single_match: level = int(level_single_match.group(1))
        elif level_range_match: level = int(level_range_match.group(1))
        if level is not None and not is_lifetime and level >= 200: continue
        icon = SUCCESS_ICON if 'clean' in selected_status.lower() else ERROR_ICON
        button_text = f"{icon} {base_filename.replace('.txt', '').replace('_', ' ')}"
        buttons.append(InlineKeyboardButton(button_text, callback_data=f"infogen_{path}"))
    if not buttons:
        title = f"{INFO_ICON} NO ACCOUNTS"
        body = ["No account types are available for your subscription level in this category."]
        text = styled_message(title, body, BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data=f"infostatus_{selected_country}")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    kbd = [buttons[i:i+1] for i in range(len(buttons))]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data=f"infostatus_{selected_country}")])
    body = [f"Country: {selected_country}", f"Status: {selected_status}", "Select an available type"]
    text = styled_message(f"{INFO_ICON} GET WITH INFO - Step 3", body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def generate_info_account(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query, user = update.callback_query, update.effective_user
    query.answer()
    if check_cooldown(update, context): return
    service_filename = query.data.replace("infogen_", "", 1)
    send_or_edit(update, context, styled_message("PROCESSING...", [f"Requesting info for: {service_filename}"], BOT_VERSION))
    res = api_request('/api/bot/get_info_line', 'post', {'service_name': service_filename, 'telegram_user_id': user.id, 'telegram_username': user.username})
    if res.get('success') and res.get('line'):
        if user.id != ADMIN_ID: context.user_data['last_info_gen_time'] = time.time()
        final_message = f"<code>{html.escape(res['line'])}</code>\n\n<i>Report generated by @{OWNER_USERNAME}</i>"
        kbd = [[InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")], [InlineKeyboardButton("🔄 Get Info Again", callback_data="info_warning")]]
        send_or_edit(update, context, final_message, InlineKeyboardMarkup(kbd), parse_mode=PARSEMODE_HTML)
    else:
        message = res.get('message', 'Failed to retrieve data.')
        text = styled_message(f"{ERROR_ICON} FAILED", [message], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="info_country_select")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def generate_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer()
    buttons = [InlineKeyboardButton(f"{FOLDER_ICON} {folder.replace('database', 'DB ').title()}", callback_data=f"db_{folder}") for folder in PUBLIC_DATABASE_FOLDERS]
    kbd = [buttons[i:i+2] for i in range(0, len(buttons), 2)]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")])
    text = styled_message(f"{ROCKET_ICON} GENERATE ACCOUNTS - Step 1", ["Select a Database Source"], BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def show_categories_for_db(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer(); db_folder = query.data.split('_', 1)[1]
    context.user_data['selected_db_folder'] = db_folder
    buttons = [InlineKeyboardButton(c, callback_data=f"category_{c}") for c in KEYWORDS_CATEGORIES.keys()]
    kbd = [buttons[i:i+2] for i in range(0, len(buttons), 2)]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="generate_menu")])
    body = [f"DB Source: {db_folder}", "Select a category."]
    text = styled_message(f"{ROCKET_ICON} GENERATE ACCOUNTS - Step 2", body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def category_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer(); category_name = query.data.split('_', 1)[1]
    db_folder = context.user_data.get('selected_db_folder')
    if not db_folder: return start(update, context)
    send_or_edit(update, context, styled_message(category_name, ["Loading stock..."], BOT_VERSION))
    services = KEYWORDS_CATEGORIES.get(category_name, {})
    stock_requests = [{"service_name": f"{kw}.txt", "database_folder": db_folder} for kw in services.values()]
    res = api_request('/api/bot/get_stock_batch', 'post', {'requests': stock_requests})
    buttons = []
    if res and res.get('success'):
        stocks = res.get('stocks', {})
        for display_name, keyword in services.items():
            stock = stocks.get(f"{db_folder}:{keyword}.txt", 'ERR')
            buttons.append(InlineKeyboardButton(f"{display_name} ({stock})", callback_data=f"generate_{keyword}"))
    kbd = [buttons[i:i+2] for i in range(0, len(buttons), 2)]
    kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data=f"db_{db_folder}")])
    body = [f"DB Source: {db_folder}", "Select a service (Stock shown):"]
    text = styled_message(category_name, body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def private_start(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer()
    if query.from_user.id == ADMIN_ID or context.user_data.get('has_private_access'):
        return private_category_menu(update, context)
    context.user_data['next_message'] = 'private_key'
    title = f"{LOCK_ICON} PRIVATE ACCESS"
    body = ["This is for one-time use.", "Please send your Private Access Key."]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def private_category_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    send_or_edit(update, context, styled_message("LOADING...", ["Fetching private categories..."], BOT_VERSION))
    res = api_request('/api/bot/list_private_files')
    if not res.get('success') or not res.get('files'):
        text = styled_message(f"{ERROR_ICON} NO FILES", ["No private files are available."], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    context.user_data['private_files'] = res.get('files', [])
    categories = sorted(list(set(path.split('/')[0] for path in context.user_data['private_files'] if '/' in path)))
    if not categories:
        text = styled_message(f"{ERROR_ICON} NOT ORGANIZED", ["Private files are not in categories."], BOT_VERSION)
        kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]; send_or_edit(update, context, text, InlineKeyboardMarkup(kbd)); return
    buttons = [InlineKeyboardButton(f"{FOLDER_ICON} {category}", callback_data=f"private_cat_{category}") for category in categories]
    kbd = [buttons[i:i+2] for i in range(0, len(buttons), 2)]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")])
    text = styled_message(f"{LOCK_ICON} PRIVATE GENERATION - Step 1", ["Select a Category"], BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def private_service_menu(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query = update.callback_query; query.answer(); selected_category = query.data.split('private_cat_')[1]
    send_or_edit(update, context, styled_message(selected_category, ["Loading stock..."], BOT_VERSION))
    all_private_files = context.user_data.get('private_files', [])
    category_files = [path for path in all_private_files if path.startswith(f"{selected_category}/")]
    stock_requests = [{"service_name": path, "is_private": True} for path in sorted(category_files)]
    res = api_request('/api/bot/get_stock_batch', 'post', {'requests': stock_requests})
    buttons = []
    if res and res.get('success'):
        stocks = res.get('stocks', {})
        for path in sorted(category_files):
            stock = stocks.get(f"private:{path}", 'ERR')
            service_name_base = os.path.basename(path).replace('.txt', '')
            buttons.append(InlineKeyboardButton(f"{LOCK_ICON} {service_name_base} ({stock})", callback_data=f"generate_{path}_private"))
    kbd = [buttons[i:i+1] for i in range(len(buttons))]; kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="private_start")])
    body = [f"Category: {selected_category}", "Select a service:"]
    text = styled_message(f"{LOCK_ICON} PRIVATE GENERATION - Step 2", body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def generate_accounts(update: Update, context: CallbackContext):
    log_user_activity(update.effective_user.id)
    if not check_access(update.effective_user.id).get("has_access"): return handle_no_access(update, context)
    query, user_id = update.callback_query, update.effective_user.id
    query.answer()
    access_info = check_access(user_id)
    callback_data = query.data.replace("generate_", "", 1)
    is_private = callback_data.endswith("_private")
    lines_to_gen = PRIVATE_LINES_TO_SEND if is_private else (LIFETIME_LINES_TO_SEND if access_info.get('is_lifetime') else DEFAULT_LINES_TO_SEND)
    
    db_folder_api = None
    if is_private:
        service_path = callback_data.removesuffix("_private")
        full_filename_to_generate, display_name = service_path, os.path.basename(service_path).replace('.txt', '')
    else:
        service_name_base = callback_data
        db_folder_api = context.user_data.get('selected_db_folder')
        if not db_folder_api: return start(update, context)
        full_filename_to_generate = f"{service_name_base}.txt"
        display_name = ALL_DOMAINS.get(service_name_base, service_name_base.replace('.com','').title())

    if is_private and user_id != ADMIN_ID and not context.user_data.get('has_private_access'):
        send_or_edit(update, context, styled_message(f"{ERROR_ICON} KEY REQUIRED", ["You need a valid Private Access Key first."], BOT_VERSION), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="private_start")]]))
        return
        
    send_or_edit(update, context, styled_message("🔥 GENERATING...", [f"Requesting {display_name}...", "Please wait..."], BOT_VERSION))
    res = api_request("/api/bot/get_service_lines_batch", 'post', {"service_name": full_filename_to_generate, "lines_to_generate": lines_to_gen, "is_private": is_private, "telegram_user_id": user_id, "database_folder": db_folder_api})
    
    if not res.get("success") or not res.get("lines"):
        error_message = res.get('message', 'Unknown error') if res.get('message') else "No accounts were found for this service."
        send_or_edit(update, context, styled_message(f"{ERROR_ICON} FAILED", [error_message], BOT_VERSION), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]))
        return
        
    if is_private and user_id != ADMIN_ID: context.user_data['has_private_access'] = False
    
    lines = res["lines"].splitlines()
    processed_lines = [format_to_user_pass(line) for line in lines]
    file_header = (f"╔═════════ G Λ K U M Λ ═════════╗\n\n    ✅ Service: {display_name}\n    🔢 Accounts: {len(processed_lines)}\n    📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n    🗣️ Credits: @{OWNER_USERNAME}\n\n╚══════════════════════════════════╝\n\n" + ("-" * 50) + "\n")
    file_footer = "\n" + ("-" * 50) + f"\n\n{BOT_VERSION.replace('_', ' ')}"
    file_content = file_header + "\n".join(processed_lines) + file_footer
    file_stream = io.BytesIO(file_content.encode('utf-8'))
    clean_display_name = ''.join(e for e in display_name if e.isalnum())
    file_stream.name = f"GAKUMA_{clean_display_name}_{datetime.now().strftime('%y%m%d')}.txt"
    delete_message(context, query.message.chat_id, query.message.message_id)
    caption = f"<b>✅ DELIVERY / PAGHATID</b>\n\nService / Serbisyo: <code>{html.escape(display_name)}</code>\nAccounts / Mga Account: <code>{len(processed_lines)}</code>\n\n{SEPARATOR}\nThank you for using G Λ K U M Λ!"
    kbd = [[InlineKeyboardButton("🏠 Main Menu", callback_data="back_to_main")], [InlineKeyboardButton("🔄 Generate Again", callback_data=query.data)]]
    context.bot.send_document(chat_id=query.message.chat_id, document=file_stream, caption=caption, parse_mode=PARSEMODE_HTML, reply_markup=InlineKeyboardMarkup(kbd))

# --- Admin Generation Handlers ---
def admin_gen_browse(update: Update, context: CallbackContext):
    if update.effective_user.id != ADMIN_ID: return
    log_user_activity(update.effective_user.id)
    query = update.callback_query
    query.answer()

    browse_path = query.data.replace("admin_browse_", "")
    if browse_path == "/": browse_path = "" 

    send_or_edit(update, context, styled_message("LOADING...", [f"Browsing: admin_database/{browse_path}..."], BOT_VERSION))
    
    res = api_request('/api/admin/list_files', method='post', data={'folder': ADMIN_DATABASE_FOLDER})
    if not res.get('success'):
        send_or_edit(update, context, styled_message("❌ ERROR", ["Could not fetch file list from the panel."], BOT_VERSION), 
                     reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data="back_to_main")]]))
        return

    all_files_with_counts = res.get('files', [])
    
    items_in_path = {} 
    for file_info in all_files_with_counts:
        file_path = file_info['path']
        count = file_info['count']
        
        if file_path.startswith(browse_path):
            sub_path = file_path[len(browse_path):].strip('/')
            if not sub_path: continue
            
            item_name = sub_path.split('/')[0]
            if '/' in sub_path:
                dir_path = os.path.join(browse_path, item_name).replace("\\", "/") + "/"
                if item_name not in items_in_path:
                    items_in_path[item_name] = {'type': 'folder', 'path': dir_path}
            else:
                if item_name not in items_in_path:
                    items_in_path[item_name] = {'type': 'file', 'path': file_path, 'count': count}

    buttons = []
    sorted_items = sorted(items_in_path.items(), key=lambda x: (x[1]['type'], x[0]))

    for name, data in sorted_items:
        if data['type'] == 'folder':
            buttons.append(InlineKeyboardButton(f"📁 {name}", callback_data=f"admin_browse_{data['path']}"))
        else:
            buttons.append(InlineKeyboardButton(f"📄 {name} ({data['count']})", callback_data=f"admin_file_{data['path']}"))

    kbd = [buttons[i:i+1] for i in range(len(buttons))]
    
    if browse_path:
        parent_path = os.path.dirname(browse_path.strip('/')).replace("\\", "/")
        parent_path = "/" if not parent_path else parent_path + "/"
        kbd.append([InlineKeyboardButton(f"{BACK_ICON} Back", callback_data=f"admin_browse_{parent_path}")])
    else:
        kbd.append([InlineKeyboardButton(f"{BACK_ICON} Main Menu", callback_data="back_to_main")])

    title = "👑 ADMIN BROWSER"
    body = [f"Current Path: <code>admin_database/{html.escape(browse_path)}</code>"]
    if not buttons:
        body.append("\nThis folder is empty.")

    text = styled_message(title, body, BOT_VERSION)
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def admin_gen_file_select(update: Update, context: CallbackContext):
    if update.effective_user.id != ADMIN_ID: return
    log_user_activity(update.effective_user.id)
    query = update.callback_query
    query.answer()
    file_path = query.data.split('admin_file_')[1]
    context.user_data['admin_gen_file_path'] = file_path
    context.user_data['next_message'] = 'admin_gen_quantity'
    
    parent_path = os.path.dirname(file_path).replace("\\", "/")
    parent_path = "/" if not parent_path else parent_path + "/"
    
    title = "👑 ADMIN GENERATE - Final Step"
    body = [f"File: <code>{html.escape(os.path.basename(file_path))}</code>", "\nPlease send the number of accounts you want to generate (e.g., 50)."]
    text = styled_message(title, body, BOT_VERSION)
    kbd = [[InlineKeyboardButton(f"{BACK_ICON} Back", callback_data=f"admin_browse_{parent_path}")]]
    send_or_edit(update, context, text, InlineKeyboardMarkup(kbd))

def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    def shutdown_handler(signum, frame):
        logger.info("Shutdown signal received. Bot is stopping.")
        time.sleep(1); updater.stop(); logger.info("Bot has been stopped."); sys.exit(0)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.photo & ~Filters.command, handle_photo_input))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_text_input))

    dp.add_handler(CallbackQueryHandler(start, pattern=r"^back_to_main$"))
    dp.add_handler(CallbackQueryHandler(redeem_prompt, pattern=r"^redeem_prompt$"))
    dp.add_handler(CallbackQueryHandler(show_user_info, pattern=r"^show_user_info$"))
    dp.add_handler(CallbackQueryHandler(show_help, pattern=r"^show_help$"))
    dp.add_handler(CallbackQueryHandler(noop_callback, pattern=r"^noop$"))
    dp.add_handler(CallbackQueryHandler(noop_feedback_link_callback, pattern=r"^noop_feedback_link$"))
    dp.add_handler(CallbackQueryHandler(convert_points_menu, pattern=r"^convert_points_menu$"))
    dp.add_handler(CallbackQueryHandler(handle_point_conversion, pattern=r"^perform_conversion_")) 

    dp.add_handler(CallbackQueryHandler(feedback_start, pattern=r"^feedback_start$"))
    dp.add_handler(CallbackQueryHandler(view_feedback_menu, pattern=r"^view_feedback_menu$"))
    dp.add_handler(CallbackQueryHandler(my_submissions_handler, pattern=r"^my_submissions$"))

    dp.add_handler(CallbackQueryHandler(generate_menu, pattern=r"^generate_menu$"))
    dp.add_handler(CallbackQueryHandler(private_start, pattern=r"^private_start$"))
    dp.add_handler(CallbackQueryHandler(show_categories_for_db, pattern=r"^db_"))
    dp.add_handler(CallbackQueryHandler(category_menu, pattern=r"^category_"))
    dp.add_handler(CallbackQueryHandler(private_service_menu, pattern=r"^private_cat_"))
    dp.add_handler(CallbackQueryHandler(generate_accounts, pattern=r"^generate_"))
    
    dp.add_handler(CallbackQueryHandler(info_warning, pattern=r"^info_warning$"))
    dp.add_handler(CallbackQueryHandler(info_menu_country_select, pattern=r"^info_country_select$"))
    dp.add_handler(CallbackQueryHandler(info_menu_status_select, pattern=r"^infostatus_"))
    dp.add_handler(CallbackQueryHandler(info_menu_level_select, pattern=r"^infolevel_"))
    dp.add_handler(CallbackQueryHandler(generate_info_account, pattern=r"^infogen_"))

    # New Admin Generation Handlers
    dp.add_handler(CallbackQueryHandler(admin_gen_browse, pattern=r"^admin_browse_"))
    dp.add_handler(CallbackQueryHandler(admin_gen_file_select, pattern=r"^admin_file_"))

    logger.info(f"🔥 {BOT_VERSION} IS LAUNCHING! 🔥")
    updater.start_polling()
    logger.info("Bot is online.")
    updater.idle()

if __name__ == "__main__":
    main()

# --- END OF FILE bot_worker.py ---