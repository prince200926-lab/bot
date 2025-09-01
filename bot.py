import discord
from discord.ext import commands
import asyncio
import random
import sqlite3
from datetime import datetime, timedelta
from typing import Tuple, Dict, List # Added for type hints in games class

# --- Configuration (from config.py) ---
"""
Configuration for the Discord gambling bot
"""
# Bot configuration
BOT_PREFIX = "!"
INITIAL_BALANCE = 1000
MIN_BET = 10
MAX_BET = 5000

# Cooldown times (in seconds)
GAMBLING_COOLDOWN = 3   # 3 seconds between gambling commands

# Game multipliers and odds
COIN_FLIP_MULTIPLIER = 1.1
DICE_WIN_MULTIPLIER = 1.25  # For rolling 6
SLOTS_MULTIPLIERS = {
    "jackpot": 1.5,     # Three 7s
    "triple": 1.3,       # Three of any other symbol
    "double": 1.2        # Two matching symbols
}

# Slots symbols and their weights (higher weight = more common)
SLOTS_SYMBOLS = {
    "🍒": 12,
    "🍋": 12,
    "🍊": 12,
    "🍇": 12,
    "💎": 18,
    "7️⃣": 3
}

# Database file
DATABASE_FILE = "gambling_bot.db"


# --- Database Operations (from database.py) ---
"""
Database operations for the Discord gambling bot
"""
class Database:
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Users table for economy data
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER,
                guild_id INTEGER,
                balance INTEGER DEFAULT {INITIAL_BALANCE},
                total_winnings INTEGER DEFAULT 0,
                total_losses INTEGER DEFAULT 0,
                games_played INTEGER DEFAULT 0,
                PRIMARY KEY (user_id, guild_id)
            )
        ''')
        
        # Cooldowns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cooldowns (
                user_id INTEGER,
                guild_id INTEGER,
                command TEXT,
                expires_at TEXT,
                PRIMARY KEY (user_id, guild_id, command)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def get_user_balance(self, user_id: int, guild_id: int) -> int:
        """Get user's current balance"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT balance FROM users WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0]
        else:
            # Create new user with initial balance
            await self.create_user(user_id, guild_id)
            return INITIAL_BALANCE
    
    async def create_user(self, user_id: int, guild_id: int):
        """Create a new user in the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''INSERT OR IGNORE INTO users (user_id, guild_id, balance) 
               VALUES (?, ?, ?)''',
            (user_id, guild_id, INITIAL_BALANCE)
        )
        
        conn.commit()
        conn.close()
    
    async def update_balance(self, user_id: int, guild_id: int, new_balance: int):
        """Update user's balance"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''UPDATE users SET balance = ? 
               WHERE user_id = ? AND guild_id = ?''',
            (new_balance, user_id, guild_id)
        )
        
        conn.commit()
        conn.close()
    
    async def add_to_balance(self, user_id: int, guild_id: int, amount: int):
        """Add amount to user's balance"""
        current_balance = await self.get_user_balance(user_id, guild_id)
        new_balance = current_balance + amount
        await self.update_balance(user_id, guild_id, new_balance)
        return new_balance
    
    async def subtract_from_balance(self, user_id: int, guild_id: int, amount: int) -> bool:
        """Subtract amount from user's balance, return False if insufficient funds"""
        current_balance = await self.get_user_balance(user_id, guild_id)
        
        if current_balance >= amount:
            new_balance = current_balance - amount
            await self.update_balance(user_id, guild_id, new_balance)
            return True
        return False
    
    async def update_stats(self, user_id: int, guild_id: int, winnings: int = 0, losses: int = 0):
        """Update user's gambling statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''UPDATE users SET 
               total_winnings = total_winnings + ?,
               total_losses = total_losses + ?,
               games_played = games_played + 1
               WHERE user_id = ? AND guild_id = ?''',
            (winnings, losses, user_id, guild_id)
        )
        
        conn.commit()
        conn.close()
    
    async def get_leaderboard(self, guild_id: int, limit: int = 10):
        """Get top users by balance for a guild"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''SELECT user_id, balance FROM users 
               WHERE guild_id = ? 
               ORDER BY balance DESC 
               LIMIT ?''',
            (guild_id, limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    async def get_user_stats(self, user_id: int, guild_id: int):
        """Get user's complete statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            '''SELECT balance, total_winnings, total_losses, games_played 
               FROM users WHERE user_id = ? AND guild_id = ?''',
            (user_id, guild_id)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'balance': result[0],
                'total_winnings': result[1],
                'total_losses': result[2],
                'games_played': result[3]
            }
        return None
    
    

# --- Gambling Games Implementation (from games.py) ---
"""
Gambling games implementation for the Discord bot
"""
class GamblingGames:
    
    @staticmethod
    def coin_flip(bet_amount: int, user_choice: str) -> Tuple[bool, int, str]:
        """
        Coin flip game
        Returns: (won, payout, result_message)
        """
        choices = ['heads', 'tails']
        result = random.choice(choices)
        
        user_choice = user_choice.lower()
        if user_choice not in choices:
            return False, 0, "Invalid choice! Use 'heads' or 'tails'"
        
        won = user_choice == result
        payout = int(bet_amount * COIN_FLIP_MULTIPLIER) if won else 0
        
        result_message = f"🪙 The coin landed on **{result}**! "
        if won:
            result_message += f"You won **{payout}** coins! 🎉"
        else:
            result_message += f"You lost **{bet_amount}** coins! 💸"
        
        return won, payout, result_message
    
    @staticmethod
    def dice_roll(bet_amount: int, target_number: int = 6) -> Tuple[bool, int, str]:
        """
        Dice roll game - win by rolling a 6, or specify target
        Returns: (won, payout, result_message)
        """
        if target_number is None: # Ensure target_number is not None if default is used
            target_number = 6
        
        if target_number < 1 or target_number > 6:
            return False, 0, "Invalid target! Choose a number between 1 and 6"
        
        roll = random.randint(1, 6)
        won = roll == target_number
        
        # Adjust payout based on target difficulty
        if target_number == 6:
            payout = int(bet_amount * DICE_WIN_MULTIPLIER) if won else 0
        else:
            # Standard 1/6 chance, so 6x multiplier for fair odds
            payout = int(bet_amount * 1.25) if won else 0 # Using the same multiplier as default for simplicity
        
        result_message = f"🎲 You rolled a **{roll}**! "
        if won:
            result_message += f"You hit your target of **{target_number}** and won **{payout}** coins! 🎉"
        else:
            result_message += f"You needed **{target_number}** but lost **{bet_amount}** coins! 💸"
        
        return won, payout, result_message
    
    @staticmethod
    def _get_weighted_symbol() -> str:
        """Get a random symbol based on weights"""
        symbols = list(SLOTS_SYMBOLS.keys())
        weights = list(SLOTS_SYMBOLS.values())
        return random.choices(symbols, weights=weights, k=1)[0]
    
    @staticmethod
    def slots(bet_amount: int) -> Tuple[bool, int, str]:
        """
        Slot machine game
        Returns: (won, payout, result_message)
        """
        # Generate three symbols
        symbols = [
            GamblingGames._get_weighted_symbol(),
            GamblingGames._get_weighted_symbol(),
            GamblingGames._get_weighted_symbol()
        ]
        
        result_message = f"🎰 **{symbols[0]} | {symbols[1]} | {symbols[2]}**\n\n"
        
        # Check for wins
        won = False
        payout = 0
        
        # Check for jackpot (three 7s)
        if symbols[0] == symbols[1] == symbols[2] == "7️⃣":
            won = True
            payout = int(bet_amount * SLOTS_MULTIPLIERS["jackpot"])
            result_message += f"🔥 **JACKPOT!** 🔥 You won **{payout}** coins!"
        
        # Check for triple (three of any symbol)
        elif symbols[0] == symbols[1] == symbols[2]:
            won = True
            payout = int(bet_amount * SLOTS_MULTIPLIERS["triple"])
            result_message += f"🎉 **TRIPLE {symbols[0]}!** You won **{payout}** coins!"
        
        # Check for double (any two matching)
        elif symbols[0] == symbols[1] or symbols[1] == symbols[2] or symbols[0] == symbols[2]:
            won = True
            payout = int(bet_amount * SLOTS_MULTIPLIERS["double"])
            result_message += f"✨ **DOUBLE MATCH!** You won **{payout}** coins!"
        
        # No win
        else:
            result_message += f"💸 No match! You lost **{bet_amount}** coins!"
        
        return won, payout, result_message
    
    @staticmethod
    def get_game_help() -> str:
        """Return help text for all games"""
        help_text = """
🎮 **Available Gambling Games:**

**🪙 Coin Flip** - `!flip <amount> <heads/tails>`
• Win multiplier: 1.1x
• 50% chance to win

**🎲 Dice Roll** - `!dice <amount> [target_number]`
• Default target: 6 (1.25x multiplier)
• Custom target: 1.25x multiplier (for any target 1-6)
• 1/6 chance to win

**🎰 Slots** - `!slots <amount>`
• Triple 7s (Jackpot): 1.5x multiplier
• Triple any symbol: 1.3x multiplier
• Double match: 1.2x multiplier
• Various win chances based on symbol rarity

**💰 Economy Commands:**
• `!balance` - Check your balance
• `!leaderboard` - View top players
• `!stats` - View your statistics
        """
        return help_text.strip()


# --- Economy System (from economy.py) ---
"""
Economy system for the Discord gambling bot
"""
class Economy:
    def __init__(self, db: Database):
        self.db = db
    
    async def check_valid_bet(self, user_id: int, guild_id: int, bet_amount: int) -> tuple[bool, str]:
        """
        Validate if a bet is valid
        Returns: (is_valid, error_message)
        """
        # Check bet amount limits
        if bet_amount < MIN_BET:
            return False, f"Minimum bet is **{MIN_BET}** coins!"
        
        if bet_amount > MAX_BET:
            return False, f"Maximum bet is **{MAX_BET}** coins!"
        
        # Check if user has sufficient balance
        balance = await self.db.get_user_balance(user_id, guild_id)
        if balance < bet_amount:
            return False, f"Insufficient funds! You have **{balance}** coins but need **{bet_amount}**!"
        
        return True, ""
    
    async def process_game_result(self, user_id: int, guild_id: int, bet_amount: int, 
                                won: bool, payout: int) -> None:
        """Process the result of a gambling game"""
        if won:
            # Add winnings to balance
            new_balance = await self.db.add_to_balance(user_id, guild_id, payout - bet_amount)
            await self.db.update_stats(user_id, guild_id, winnings=payout - bet_amount)
        else:
            # Subtract bet from balance
            await self.db.subtract_from_balance(user_id, guild_id, bet_amount)
            await self.db.update_stats(user_id, guild_id, losses=bet_amount)
    
    async def get_balance_embed(self, user: discord.User, guild_id: int) -> discord.Embed:
        """Create an embed showing user's balance"""
        balance = await self.db.get_user_balance(user.id, guild_id)
        
        embed = discord.Embed(
            title="💰 Balance",
            description=f"**{user.display_name}** has **{balance}** coins",
            color=0x00ff00
        )
        embed.set_thumbnail(url=user.avatar.url if user.avatar else user.default_avatar.url)
        
        return embed
    
    async def get_stats_embed(self, user: discord.User, guild_id: int) -> discord.Embed:
        """Create an embed showing user's statistics"""
        stats = await self.db.get_user_stats(user.id, guild_id)
        
        if not stats:
            embed = discord.Embed(
                title="📊 Statistics",
                description=f"No statistics found for **{user.display_name}**",
                color=0xff0000
            )
            return embed
        
        net_profit = stats['total_winnings'] - stats['total_losses']
        win_rate = 0
        if stats['games_played'] > 0:
            # Calculate win rate based on games where winnings > 0
            win_rate = (stats['total_winnings'] / (stats['total_winnings'] + stats['total_losses']) * 100) if (stats['total_winnings'] + stats['total_losses']) > 0 else 0
        
        embed = discord.Embed(
            title="📊 Gambling Statistics",
            color=0x00ff00 if net_profit >= 0 else 0xff0000
        )
        
        embed.add_field(name="💰 Current Balance", value=f"{stats['balance']} coins", inline=True)
        embed.add_field(name="🎮 Games Played", value=stats['games_played'], inline=True)
        embed.add_field(name="📈 Net Profit", value=f"{net_profit:+} coins", inline=True)
        embed.add_field(name="💸 Total Losses", value=f"{stats['total_losses']} coins", inline=True)
        embed.add_field(name="💎 Total Winnings", value=f"{stats['total_winnings']} coins", inline=True)
        embed.add_field(name="🎯 Success Rate", value=f"{win_rate:.1f}%", inline=True)
        
        embed.set_thumbnail(url=user.avatar.url if user.avatar else user.default_avatar.url)
        embed.set_footer(text=f"Statistics for {user.display_name}")
        
        return embed
    
    async def get_leaderboard_embed(self, guild: discord.Guild, bot_instance) -> discord.Embed: # Renamed 'bot' to 'bot_instance' to avoid conflict
        """Create an embed showing the server leaderboard"""
        leaderboard = await self.db.get_leaderboard(guild.id, 10)
        
        embed = discord.Embed(
            title=f"🏆 {guild.name} Leaderboard",
            description="Top 10 richest players",
            color=0xffd700
        )
        
        if not leaderboard:
            embed.add_field(name="No Data", value="No players found!", inline=False)
            return embed
        
        leaderboard_text = ""
        for i, (user_id, balance) in enumerate(leaderboard, 1):
            try:
                user = await bot_instance.fetch_user(user_id) # Use bot_instance here
                username = user.display_name
            except:
                username = f"Unknown User ({user_id})"
            
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
            leaderboard_text += f"{medal} **{username}** - {balance} coins\n"
        
        embed.add_field(name="Rankings", value=leaderboard_text, inline=False)
        embed.set_footer(text=f"Leaderboard for {guild.name}")
        
        return embed
    
    def format_number(self, number: int) -> str:
        """Format large numbers with commas"""
        return f"{number:,}"


# --- Main Bot Logic (from main.py) ---

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=BOT_PREFIX, intents=intents, help_command=None)

# Initialize components
db = Database()
games = GamblingGames()
economy = Economy(db)

@bot.event
async def on_ready():
    """Bot startup event"""
    print(f'{bot.user} has connected to Discord!')
    print(f'Bot is ready and serving {len(bot.guilds)} guilds')
    
    # Set bot status
    activity = discord.Game(name=f"{BOT_PREFIX}help | Virtual Casino")
    await bot.change_presence(activity=activity)

@bot.event
async def on_guild_join(guild):
    """Event when bot joins a new guild"""
    print(f'Joined new guild: {guild.name} (ID: {guild.id})')

@bot.event
async def on_command_error(ctx, error):
    """Global error handler"""
    if isinstance(error, commands.CommandOnCooldown):
        embed = discord.Embed(
            title="⏰ Cooldown Active",
            description=f"Please wait {error.retry_after:.1f} seconds before using this command again.",
            color=0xff0000
        )
        await ctx.send(embed=embed)
    elif isinstance(error, commands.MissingRequiredArgument):
        embed = discord.Embed(
            title="❌ Missing Arguments",
            description=f"Please provide all required arguments. Use `{BOT_PREFIX}help` for command usage.",
            color=0xff0000
        )
        await ctx.send(embed=embed)
    elif isinstance(error, commands.BadArgument):
        embed = discord.Embed(
            title="❌ Invalid Arguments",
            description="Please check your arguments and try again.",
            color=0xff0000
        )
        await ctx.send(embed=embed)
    else:
        print(f"Unhandled error: {error}")

# Utility function for cooldown checking (kept as a global function for simplicity, could be a method of a Cogs class)
async def check_and_set_cooldown(ctx, command_name: str, cooldown_seconds: int) -> bool:
    """Check if user is on cooldown and set new cooldown if not"""
    remaining = await db.check_cooldown(ctx.author.id, ctx.guild.id, command_name)
    
    if remaining > 0:
        embed = discord.Embed(
            title="⏰ Cooldown Active",
            description=f"Please wait {remaining:.1f} seconds before using `{command_name}` again.",
            color=0xff0000
        )
        await ctx.send(embed=embed)
        return False
    
    await db.set_cooldown(ctx.author.id, ctx.guild.id, command_name, cooldown_seconds)
    return True

# Economy Commands
@bot.command(name='balance', aliases=['bal', 'money'])
async def balance(ctx, user: discord.User | None = None):
    """Check your or another user's balance"""
    target_user = user or ctx.author
    embed = await economy.get_balance_embed(target_user, ctx.guild.id)
    await ctx.send(embed=embed)

@bot.command(name='stats', aliases=['statistics'])
async def stats(ctx, user: discord.User | None = None):
    """View gambling statistics"""
    target_user = user or ctx.author
    embed = await economy.get_stats_embed(target_user, ctx.guild.id)
    await ctx.send(embed=embed)

@bot.command(name='leaderboard', aliases=['top', 'rich'])
async def leaderboard(ctx):
    """View the server leaderboard"""
    embed = await economy.get_leaderboard_embed(ctx.guild, bot) # Pass 'bot' instance
    await ctx.send(embed=embed)

# Gambling Commands
@bot.command(name='flip', aliases=['coinflip', 'coin'])
@commands.cooldown(1, GAMBLING_COOLDOWN, commands.BucketType.user)
async def coin_flip(ctx, amount: int, choice: str):
    """
    Flip a coin and bet on the outcome
    Usage: !flip <amount> <heads/tails>
    """
    # Validate bet
    is_valid, error_msg = await economy.check_valid_bet(ctx.author.id, ctx.guild.id, amount)
    if not is_valid:
        embed = discord.Embed(title="❌ Invalid Bet", description=error_msg, color=0xff0000)
        await ctx.send(embed=embed)
        return
    
    # Play the game
    won, payout, result_message = games.coin_flip(amount, choice)
    
    # Process the result
    await economy.process_game_result(ctx.author.id, ctx.guild.id, amount, won, payout)
    
    # Send result
    embed = discord.Embed(
        title="🪙 Coin Flip Result",
        description=result_message,
        color=0x00ff00 if won else 0xff0000
    )
    
    new_balance = await db.get_user_balance(ctx.author.id, ctx.guild.id)
    embed.add_field(name="💰 New Balance", value=f"{new_balance} coins", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='dice', aliases=['roll'])
@commands.cooldown(1, GAMBLING_COOLDOWN, commands.BucketType.user)
async def dice_roll(ctx, amount: int, target: int = 6):
    """
    Roll a dice and bet on the outcome
    Usage: !dice <amount> [target_number]
    """
    # Validate bet
    is_valid, error_msg = await economy.check_valid_bet(ctx.author.id, ctx.guild.id, amount)
    if not is_valid:
        embed = discord.Embed(title="❌ Invalid Bet", description=error_msg, color=0xff0000)
        await ctx.send(embed=embed)
        return
    
    # Play the game
    won, payout, result_message = games.dice_roll(amount, target)
    
    # Process the result
    await economy.process_game_result(ctx.author.id, ctx.guild.id, amount, won, payout)
    
    # Send result
    embed = discord.Embed(
        title="🎲 Dice Roll Result",
        description=result_message,
        color=0x00ff00 if won else 0xff0000
    )
    
    new_balance = await db.get_user_balance(ctx.author.id, ctx.guild.id)
    embed.add_field(name="💰 New Balance", value=f"{new_balance} coins", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='slots', aliases=['slot', 'spin'])
@commands.cooldown(1, GAMBLING_COOLDOWN, commands.BucketType.user)
async def slots(ctx, amount: int):
    """
    Play the slot machine
    Usage: !slots <amount>
    """
    # Validate bet
    is_valid, error_msg = await economy.check_valid_bet(ctx.author.id, ctx.guild.id, amount)
    if not is_valid:
        embed = discord.Embed(title="❌ Invalid Bet", description=error_msg, color=0xff0000)
        await ctx.send(embed=embed)
        return
    
    # Play the game
    won, payout, result_message = games.slots(amount)
    
    # Process the result
    await economy.process_game_result(ctx.author.id, ctx.guild.id, amount, won, payout)
    
    # Send result
    embed = discord.Embed(
        title="🎰 Slot Machine Result",
        description=result_message,
        color=0x00ff00 if won else 0xff0000
    )
    
    new_balance = await db.get_user_balance(ctx.author.id, ctx.guild.id)
    embed.add_field(name="💰 New Balance", value=f"{new_balance} coins", inline=False)
    
    await ctx.send(embed=embed)

# Help and Information Commands
@bot.command(name='help', aliases=['commands'])
async def help_command(ctx):
    """Show all available commands"""
    embed = discord.Embed(
        title="🎰 Casino Bot Commands",
        description="Here are all available commands organized by category:",
        color=0x0099ff
    )
    
    # Gambling Games
    embed.add_field(
        name="🎮 Gambling Games",
        value=f"`{BOT_PREFIX}flip <amount> <heads/tails>` - Coin flip (1.1x win)\n"
              f"`{BOT_PREFIX}dice <amount> [target]` - Dice roll 1.25x\n"
              f"`{BOT_PREFIX}slots <amount>` - Slot machine jackpot 1.5x ,triple 1.3 , double 1.2",
        inline=False
    )
    
    # Economy Commands
    embed.add_field(
        name="💰 Economy",
        value=f"`{BOT_PREFIX}balance [user]` - Check balance\n"
              f"`{BOT_PREFIX}stats [user]` - View gambling statistics\n"
              f"`{BOT_PREFIX}leaderboard` - View top players",
        inline=False
    )
    
    # Information Commands
    embed.add_field(
        name="ℹ️ Information",
        value=f"`{BOT_PREFIX}games` - Detailed game rules\n"
              f"`{BOT_PREFIX}info` - Bot information\n"
              f"`{BOT_PREFIX}help` - This command list",
        inline=False
    )
    
    # Admin Commands (if user has permissions)
    if ctx.author.guild_permissions.administrator:
        embed.add_field(
            name="⚙️ Admin Commands",
            value=f"`{BOT_PREFIX}give <user> <amount>` - Give coins to user\n"
                  f"`{BOT_PREFIX}reset <user>` - Reset user's balance",
            inline=False
        )
    
    embed.set_footer(text=f"Bet limits: {MIN_BET}-{MAX_BET} coins | Cooldown: {GAMBLING_COOLDOWN}s between games")
    
    await ctx.send(embed=embed)

@bot.command(name='games', aliases=['gamelist'])
async def game_list(ctx):
    """Show all available games and their rules"""
    help_text = games.get_game_help()
    
    embed = discord.Embed(
        title="🎮 Casino Games & Commands",
        description=help_text,
        color=0x0099ff
    )
    embed.set_footer(text=f"Minimum bet: {MIN_BET} | Maximum bet: {MAX_BET}")
    
    await ctx.send(embed=embed)

@bot.command(name='info', aliases=['about'])
async def bot_info(ctx):
    """Show bot information"""
    embed = discord.Embed(
        title="🎰 Virtual Casino Bot",
        description="A Discord bot for virtual gambling and economy management",
        color=0x0099ff
    )
    
    embed.add_field(
        name="📊 Features",
        value="• Virtual currency system\n• Coin flip, dice, and slots games\n• Server leaderboards\n• Detailed statistics",
        inline=False
    )
    
    embed.add_field(
        name="🛡️ Security",
        value="• Server-specific economies\n• Anti-spam cooldowns\n• Bet limits for responsible gaming",
        inline=False
    )
    
    embed.add_field(
        name="💡 Commands",
        value=f"Use `{BOT_PREFIX}games` to see all available games\nUse `{BOT_PREFIX}help` for command list",
        inline=False
    )
    
    embed.set_footer(text="Made with discord.py | Virtual gambling only!")
    
    await ctx.send(embed=embed)

# Admin Commands (Optional)
@bot.command(name='give', hidden=True)
@commands.has_permissions(administrator=True)
async def give_money(ctx, user: discord.User, amount: int):
    """Give money to a user (Admin only)"""
    if amount <= 0:
        await ctx.send("❌ Amount must be positive!")
        return
    
    new_balance = await db.add_to_balance(user.id, ctx.guild.id, amount)
    
    embed = discord.Embed(
        title="💰 Money Given",
        description=f"Given **{amount}** coins to **{user.display_name}**\nTheir new balance: **{new_balance}** coins",
        color=0x00ff00
    )
    await ctx.send(embed=embed)

@bot.command(name='reset', hidden=True)
@commands.has_permissions(administrator=True)
async def reset_user(ctx, user: discord.User):
    """Reset a user's balance and stats (Admin only)"""
    await db.update_balance(user.id, ctx.guild.id, INITIAL_BALANCE)  # Reset to initial balance
    
    embed = discord.Embed(
        title="🔄 User Reset",
        description=f"Reset **{user.display_name}**'s balance to {INITIAL_BALANCE} coins",
        color=0x00ff00
    )
    await ctx.send(embed=embed)

# Error handlers for specific commands
@give_money.error
async def give_money_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
            title="❌ Permission Denied",
            description="You need administrator permissions to use this command.",
            color=0xff0000
        )
        await ctx.send(embed=embed)

@reset_user.error
async def reset_user_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
            title="❌ Permission Denied",
            description="You need administrator permissions to use this command.",
            color=0xff0000
        )
        await ctx.send(embed=embed)

# Run the bot
# IMPORTANT: Replace "YOUR_BOT_TOKEN_HERE" with your actual Discord bot token.
# The token provided in the original context is likely a placeholder or expired.
bot.run("")
