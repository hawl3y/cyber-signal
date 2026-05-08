"""
Curated threat-actor knowledge base.

Each entry maps a canonical actor name to:
  - aliases:    other names the group goes by (CTI vendors disagree, so we
                list every common variant)
  - actor_type: one of cybercriminal / nation_state / hacktivist
                (must match ALLOWED_ACTOR_TYPES from the prior AI prompt
                contract so downstream consumers don't break)

Maintenance:
  - Adding a group: append a new entry. Use the most commonly used canonical
    name in current reporting; put alternates in aliases.
  - Renaming a group (e.g. ransomware brand rebrand): keep the old name as
    an alias so historical articles still match.
  - Aliases are matched case-insensitively against article text with word
    boundaries, so they need to be the exact phrase used in news copy.

Coverage targets (in priority order):
  1. Active ransomware-as-a-service operators (~25 groups account for most
     incident reporting)
  2. Major state-sponsored APT groups tracked by major CTI vendors
  3. High-profile hacktivist groups
  4. Notable past groups (Conti, REvil, etc.) — kept because their old
     incidents and rebrands still surface
"""

THREAT_ACTORS = {
    # ---------- Ransomware / cybercrime ----------
    "LockBit": {
        "aliases": ["LockBit 3.0", "LockBit Black", "LockBit 2.0", "LockBit Red", "LockBit Green"],
        "actor_type": "cybercriminal",
    },
    "ALPHV": {
        "aliases": ["BlackCat", "ALPHV/BlackCat", "ALPHV BlackCat", "AlphV"],
        "actor_type": "cybercriminal",
    },
    "Cl0p": {
        "aliases": ["Clop", "Cl0p ransomware", "TA505"],
        "actor_type": "cybercriminal",
    },
    "Akira": {
        "aliases": ["Akira ransomware"],
        "actor_type": "cybercriminal",
    },
    "Black Basta": {
        "aliases": ["BlackBasta"],
        "actor_type": "cybercriminal",
    },
    "RansomHub": {
        "aliases": ["Ransom Hub"],
        "actor_type": "cybercriminal",
    },
    "Play": {
        "aliases": ["Play ransomware", "PlayCrypt"],
        "actor_type": "cybercriminal",
    },
    "Royal": {
        "aliases": ["Royal ransomware"],
        "actor_type": "cybercriminal",
    },
    "Hunters International": {
        "aliases": ["Hunters Intl"],
        "actor_type": "cybercriminal",
    },
    "Medusa": {
        "aliases": ["Medusa ransomware", "MedusaLocker"],
        "actor_type": "cybercriminal",
    },
    "Qilin": {
        "aliases": ["Agenda ransomware", "Agenda"],
        "actor_type": "cybercriminal",
    },
    "Rhysida": {
        "aliases": ["Rhysida ransomware"],
        "actor_type": "cybercriminal",
    },
    "INC Ransom": {
        "aliases": ["INC ransomware"],
        "actor_type": "cybercriminal",
    },
    "8Base": {
        "aliases": ["8base"],
        "actor_type": "cybercriminal",
    },
    "BianLian": {
        "aliases": ["Bian Lian"],
        "actor_type": "cybercriminal",
    },
    "Trigona": {
        "aliases": ["Trigona ransomware"],
        "actor_type": "cybercriminal",
    },
    "Snatch": {
        "aliases": ["Snatch ransomware"],
        "actor_type": "cybercriminal",
    },
    "Vice Society": {
        "aliases": ["ViceSociety"],
        "actor_type": "cybercriminal",
    },
    "Money Message": {
        "aliases": ["MoneyMessage"],
        "actor_type": "cybercriminal",
    },
    "DragonForce": {
        "aliases": ["Dragon Force", "DragonForce ransomware"],
        "actor_type": "cybercriminal",
    },
    "FOG": {
        "aliases": ["FOG ransomware"],
        "actor_type": "cybercriminal",
    },
    "Brain Cipher": {
        "aliases": ["BrainCipher"],
        "actor_type": "cybercriminal",
    },
    "ShinyHunters": {
        "aliases": ["Shiny Hunters"],
        "actor_type": "cybercriminal",
    },
    "Scattered Spider": {
        "aliases": ["UNC3944", "Scatter Swine", "Muddled Libra", "Roasted 0ktapus", "0ktapus"],
        "actor_type": "cybercriminal",
    },
    "Lapsus$": {
        "aliases": ["LAPSUS$", "Lapsus", "DEV-0537"],
        "actor_type": "cybercriminal",
    },
    "FIN7": {
        "aliases": ["Carbon Spider", "Carbanak"],
        "actor_type": "cybercriminal",
    },
    "FIN8": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "TA505": {
        "aliases": ["Hive0065"],
        "actor_type": "cybercriminal",
    },
    "Evil Corp": {
        "aliases": ["EvilCorp", "Indrik Spider", "TA505"],
        "actor_type": "cybercriminal",
    },

    # Notable past ransomware groups (kept so historical articles match)
    "Conti": {
        "aliases": ["Conti ransomware"],
        "actor_type": "cybercriminal",
    },
    "REvil": {
        "aliases": ["Sodinokibi", "Sodin"],
        "actor_type": "cybercriminal",
    },
    "DarkSide": {
        "aliases": ["Dark Side"],
        "actor_type": "cybercriminal",
    },
    "Maze": {
        "aliases": ["Maze ransomware"],
        "actor_type": "cybercriminal",
    },
    "Hive": {
        "aliases": ["Hive ransomware"],
        "actor_type": "cybercriminal",
    },
    "Ryuk": {
        "aliases": ["Ryuk ransomware"],
        "actor_type": "cybercriminal",
    },
    "BlackByte": {
        "aliases": ["Black Byte"],
        "actor_type": "cybercriminal",
    },
    "BlackSuit": {
        "aliases": ["Black Suit"],
        "actor_type": "cybercriminal",
    },

    # ---------- State-sponsored / nation-state ----------
    "Lazarus Group": {
        "aliases": ["Lazarus", "APT38", "Hidden Cobra", "ZINC", "Diamond Sleet", "TraderTraitor"],
        "actor_type": "nation_state",
    },
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard", "Pawn Storm"],
        "actor_type": "nation_state",
    },
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "BlueBravo"],
        "actor_type": "nation_state",
    },
    "APT41": {
        "aliases": ["Barium", "Wicked Panda", "Brass Typhoon", "Double Dragon"],
        "actor_type": "nation_state",
    },
    "APT40": {
        "aliases": ["Leviathan", "Kryptonite Panda", "Bronze Mohawk", "GADOLINIUM"],
        "actor_type": "nation_state",
    },
    "APT10": {
        "aliases": ["Stone Panda", "MenuPass", "Cicada", "POTASSIUM"],
        "actor_type": "nation_state",
    },
    "APT33": {
        "aliases": ["Refined Kitten", "Elfin", "Peach Sandstorm", "HOLMIUM"],
        "actor_type": "nation_state",
    },
    "APT34": {
        "aliases": ["OilRig", "Helix Kitten", "Hazel Sandstorm", "EUROPIUM"],
        "actor_type": "nation_state",
    },
    "APT35": {
        "aliases": ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "Ajax Security Team"],
        "actor_type": "nation_state",
    },
    "Volt Typhoon": {
        "aliases": ["Vanguard Panda", "Bronze Silhouette", "Voltzite"],
        "actor_type": "nation_state",
    },
    "Salt Typhoon": {
        "aliases": ["GhostEmperor", "FamousSparrow", "Earth Estries"],
        "actor_type": "nation_state",
    },
    "Flax Typhoon": {
        "aliases": ["RedJuliett", "Ethereal Panda"],
        "actor_type": "nation_state",
    },
    "MuddyWater": {
        "aliases": ["Mango Sandstorm", "Static Kitten", "Mercury", "Seedworm", "TEMP.Zagros"],
        "actor_type": "nation_state",
    },
    "Kimsuky": {
        "aliases": ["Velvet Chollima", "Black Banshee", "Emerald Sleet", "THALLIUM"],
        "actor_type": "nation_state",
    },
    "Andariel": {
        "aliases": ["Onyx Sleet", "PLUTONIUM", "Stonefly"],
        "actor_type": "nation_state",
    },
    "Sandworm": {
        "aliases": ["Voodoo Bear", "BlackEnergy", "Iron Viking", "Seashell Blizzard", "FROZENBARENTS"],
        "actor_type": "nation_state",
    },
    "Turla": {
        "aliases": ["Snake", "Venomous Bear", "Secret Blizzard", "Uroburos", "Krypton"],
        "actor_type": "nation_state",
    },
    "Gamaredon": {
        "aliases": ["Aqua Blizzard", "Primitive Bear", "Armageddon", "Trident Ursa"],
        "actor_type": "nation_state",
    },
    "Equation Group": {
        "aliases": ["Equation"],
        "actor_type": "nation_state",
    },
    "Mustang Panda": {
        "aliases": ["TA416", "RedDelta", "Bronze President"],
        "actor_type": "nation_state",
    },
    "Earth Lusca": {
        "aliases": ["Aquatic Panda", "RedHotel", "TAG-22"],
        "actor_type": "nation_state",
    },
    "BlackTech": {
        "aliases": ["Palmerworm", "Circuit Panda"],
        "actor_type": "nation_state",
    },
    "Storm-0539": {
        "aliases": ["Atlas Lion"],
        "actor_type": "nation_state",
    },

    # ---------- Hacktivist ----------
    "Anonymous": {
        "aliases": ["Anonymous Sudan"],
        "actor_type": "hacktivist",
    },
    "Killnet": {
        "aliases": ["KillNet"],
        "actor_type": "hacktivist",
    },
    "NoName057": {
        "aliases": ["NoName057(16)", "NoName"],
        "actor_type": "hacktivist",
    },
    "Cyber Av3ngers": {
        "aliases": ["CyberAvengers", "CyberAv3ngers"],
        "actor_type": "hacktivist",
    },
    "Handala": {
        "aliases": ["Handala Hack"],
        "actor_type": "hacktivist",
    },
    "IT Army of Ukraine": {
        "aliases": ["IT Army"],
        "actor_type": "hacktivist",
    },
    "GhostSec": {
        "aliases": ["Ghost Security"],
        "actor_type": "hacktivist",
    },
    "Predatory Sparrow": {
        "aliases": ["Gonjeshke Darande"],
        "actor_type": "hacktivist",
    },
    "SiegedSec": {
        "aliases": ["Sieged Sec"],
        "actor_type": "hacktivist",
    },
}
