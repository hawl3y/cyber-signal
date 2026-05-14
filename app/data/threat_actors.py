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

Coverage:
  - All 178 MITRE ATT&CK enterprise groups (nation-state + criminal APTs)
  - ~340 ransomware and extortion operators from ransomware.live
  - Hacktivist groups active in current reporting

Maintenance:
  Run scripts/update_threat_actors.py periodically to pull new groups from
  MITRE ATT&CK and ransomware.live and generate additions to paste here.
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
    "RansomHouse": {
        "aliases": ["Ransom House"],
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
    # ---------- Supply-chain / cybercrime ----------
    "TeamPCP": {
        "aliases": ["Team PCP", "PCP threat group"],
        "actor_type": "cybercriminal",
    },
    "Nitrogen": {
        "aliases": ["Nitrogen ransomware"],
        "actor_type": "cybercriminal",
    },

    # ---------- Added from MITRE ATT&CK ----------
    "admin@338": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Agrius": {
        "aliases": ["Pink Sandstorm", "AMERICIUM", "Agonizing Serpens", "BlackShadow"],
        "actor_type": "nation_state",
    },
    "Aoqin Dragon": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "APT-C-23": {
        "aliases": ["Mantis", "Arid Viper", "Desert Falcon", "TAG-63", "Grey Karkadann", "Big Bang APT", "Two-tailed Scorpion"],
        "actor_type": "nation_state",
    },
    "APT-C-36": {
        "aliases": ["Blind Eagle"],
        "actor_type": "nation_state",
    },
    "APT1": {
        "aliases": ["Comment Crew", "Comment Group", "Comment Panda"],
        "actor_type": "nation_state",
    },
    "APT12": {
        "aliases": ["IXESHE", "DynCalc", "Numbered Panda", "DNSCALC"],
        "actor_type": "nation_state",
    },
    "APT16": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "APT17": {
        "aliases": ["Deputy Dog"],
        "actor_type": "nation_state",
    },
    "APT18": {
        "aliases": ["TG-0416", "Dynamite Panda", "Threat Group-0416"],
        "actor_type": "nation_state",
    },
    "APT19": {
        "aliases": ["Codoso", "C0d0so0", "Codoso Team", "Sunshop Group"],
        "actor_type": "nation_state",
    },
    "APT3": {
        "aliases": ["Gothic Panda", "Pirpi", "UPS Team", "Buckeye", "Threat Group-0110", "TG-0110"],
        "actor_type": "nation_state",
    },
    "APT30": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "APT32": {
        "aliases": ["SeaLotus", "OceanLotus", "APT-C-00", "Canvas Cyclone", "BISMUTH"],
        "actor_type": "nation_state",
    },
    "APT37": {
        "aliases": ["InkySquid", "ScarCruft", "Reaper", "Group123", "TEMP.Reaper", "Ricochet Chollima"],
        "actor_type": "nation_state",
    },
    "APT39": {
        "aliases": ["ITG07", "Chafer", "Remix Kitten"],
        "actor_type": "nation_state",
    },
    "APT5": {
        "aliases": ["Mulberry Typhoon", "MANGANESE", "BRONZE FLEETWOOD", "Keyhole Panda", "UNC2630"],
        "actor_type": "nation_state",
    },
    "Axiom": {
        "aliases": ["Group 72"],
        "actor_type": "nation_state",
    },
    "BackdoorDiplomacy": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "BITTER": {
        "aliases": ["T-APT-17"],
        "actor_type": "nation_state",
    },
    "BlackOasis": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Blue Mockingbird": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Bouncing Golf": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "BRONZE BUTLER": {
        "aliases": ["REDBALDKNIGHT", "Tick"],
        "actor_type": "nation_state",
    },
    "Chimera": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Cinnamon Tempest": {
        "aliases": ["DEV-0401", "Emperor Dragonfly", "BRONZE STARLIGHT"],
        "actor_type": "nation_state",
    },
    "Cleaver": {
        "aliases": ["Threat Group 2889", "TG-2889"],
        "actor_type": "nation_state",
    },
    "Cobalt Group": {
        "aliases": ["GOLD KINGSWOOD", "Cobalt Gang", "Cobalt Spider"],
        "actor_type": "nation_state",
    },
    "Confucius": {
        "aliases": ["Confucius APT"],
        "actor_type": "nation_state",
    },
    "CopyKittens": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "CostaRicto": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "CURIUM": {
        "aliases": ["Crimson Sandstorm", "TA456", "Tortoise Shell", "Yellow Liderc"],
        "actor_type": "nation_state",
    },
    "Daggerfly": {
        "aliases": ["Evasive Panda", "BRONZE HIGHLAND"],
        "actor_type": "nation_state",
    },
    "Dark Caracal": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Darkhotel": {
        "aliases": ["DUBNIUM", "Zigzag Hail"],
        "actor_type": "nation_state",
    },
    "DarkHydrus": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "DarkVishnya": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Deep Panda": {
        "aliases": ["Shell Crew", "WebMasters", "KungFu Kittens", "PinkPanther", "Black Vine"],
        "actor_type": "nation_state",
    },
    "Dragonfly": {
        "aliases": ["TEMP.Isotope", "DYMALLOY", "Berserk Bear", "TG-4192", "Crouching Yeti", "IRON LIBERTY", "Energetic Bear", "Ghost Blizzard", "BROMINE"],
        "actor_type": "nation_state",
    },
    "Dragonfly 2.0": {
        "aliases": ["IRON LIBERTY", "DYMALLOY", "Berserk Bear"],
        "actor_type": "nation_state",
    },
    "DragonOK": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Dust Storm": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Elderwood": {
        "aliases": ["Elderwood Gang", "Beijing Group", "Sneaky Panda"],
        "actor_type": "nation_state",
    },
    "Ember Bear": {
        "aliases": ["UNC2589", "Bleeding Bear", "DEV-0586", "Cadet Blizzard", "Frozenvista", "UAC-0056"],
        "actor_type": "nation_state",
    },
    "Evilnum": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "EXOTIC LILY": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Ferocious Kitten": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "FIN10": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "FIN13": {
        "aliases": ["Elephant Beetle"],
        "actor_type": "nation_state",
    },
    "FIN4": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "FIN5": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "FIN6": {
        "aliases": ["Magecart Group 6", "ITG08", "Skeleton Spider", "TAAL", "Camouflage Tempest"],
        "actor_type": "nation_state",
    },
    "Fox Kitten": {
        "aliases": ["UNC757", "Parisite", "Pioneer Kitten", "RUBIDIUM", "Lemon Sandstorm"],
        "actor_type": "nation_state",
    },
    "Frankenstein": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "GALLIUM": {
        "aliases": ["Granite Typhoon"],
        "actor_type": "nation_state",
    },
    "Gallmaker": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "GCMAN": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Gelsemium": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "GOLD SOUTHFIELD": {
        "aliases": ["Pinchy Spider"],
        "actor_type": "nation_state",
    },
    "Gorgon Group": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Group5": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "HAFNIUM": {
        "aliases": ["Operation Exchange Marauder", "Silk Typhoon"],
        "actor_type": "nation_state",
    },
    "HEXANE": {
        "aliases": ["Lyceum", "Siamesekitten", "Spirlin"],
        "actor_type": "nation_state",
    },
    "Higaisa": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Honeybee": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Inception": {
        "aliases": ["Inception Framework", "Cloud Atlas"],
        "actor_type": "nation_state",
    },
    "IndigoZebra": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Ke3chang": {
        "aliases": ["APT15", "Mirage", "Vixen Panda", "GREF", "Playful Dragon", "RoyalAPT", "NICKEL", "Nylon Typhoon"],
        "actor_type": "nation_state",
    },
    "LazyScripter": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Leafminer": {
        "aliases": ["Raspite"],
        "actor_type": "nation_state",
    },
    "Lotus Blossom": {
        "aliases": ["DRAGONFISH", "Spring Dragon", "RADIUM", "Raspberry Typhoon"],
        "actor_type": "nation_state",
    },
    "LuminousMoth": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Machete": {
        "aliases": ["APT-C-43", "El Machete"],
        "actor_type": "nation_state",
    },
    "Malteiro": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Metador": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Moafee": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Mofang": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Molerats": {
        "aliases": ["Operation Molerats", "Gaza Cybergang"],
        "actor_type": "nation_state",
    },
    "MONSOON": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Moonstone Sleet": {
        "aliases": ["Storm-1789"],
        "actor_type": "nation_state",
    },
    "Moses Staff": {
        "aliases": ["DEV-0500", "Marigold Sandstorm"],
        "actor_type": "nation_state",
    },
    "MoustachedBouncer": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Mustard Tempest": {
        "aliases": ["DEV-0206", "TA569", "GOLD PRELUDE", "UNC1543"],
        "actor_type": "nation_state",
    },
    "Naikon": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "NEODYMIUM": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Night Dragon": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Nomadic Octopus": {
        "aliases": ["DustSquad"],
        "actor_type": "nation_state",
    },
    "Operation Wocao": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Orangeworm": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Patchwork": {
        "aliases": ["Hangover Group", "Dropping Elephant", "Chinastrats", "MONSOON", "Operation Hangover"],
        "actor_type": "nation_state",
    },
    "PittyTiger": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "PLATINUM": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "POLONIUM": {
        "aliases": ["Plaid Rain"],
        "actor_type": "nation_state",
    },
    "Poseidon Group": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "PROMETHIUM": {
        "aliases": ["StrongPity"],
        "actor_type": "nation_state",
    },
    "Putter Panda": {
        "aliases": ["APT2", "MSUpdater"],
        "actor_type": "nation_state",
    },
    "Rancor": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "RedCurl": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Rocke": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "RTM": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Saint Bear": {
        "aliases": ["Storm-0587", "TA471", "UAC-0056", "Lorec53"],
        "actor_type": "nation_state",
    },
    "Scarlet Mimic": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Sharpshooter": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "SideCopy": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Sidewinder": {
        "aliases": ["T-APT-04", "Rattlesnake"],
        "actor_type": "nation_state",
    },
    "Silence": {
        "aliases": ["Whisper Spider"],
        "actor_type": "nation_state",
    },
    "Silent Librarian": {
        "aliases": ["TA407", "COBALT DICKENS"],
        "actor_type": "nation_state",
    },
    "SilverTerrier": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Sowbug": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Star Blizzard": {
        "aliases": ["SEABORGIUM", "Callisto Group", "TA446", "COLDRIVER"],
        "actor_type": "nation_state",
    },
    "Stealth Falcon": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Stolen Pencil": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Strider": {
        "aliases": ["ProjectSauron"],
        "actor_type": "nation_state",
    },
    "Suckfly": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TA2541": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TA459": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TA551": {
        "aliases": ["GOLD CABIN", "Shathak"],
        "actor_type": "nation_state",
    },
    "TA577": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TA578": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Taidoor": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TeamTNT": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "TEMP.Veles": {
        "aliases": ["XENOTIME"],
        "actor_type": "nation_state",
    },
    "The White Company": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Threat Group-1314": {
        "aliases": ["TG-1314"],
        "actor_type": "nation_state",
    },
    "Threat Group-3390": {
        "aliases": ["Earth Smilodon", "TG-3390", "Emissary Panda", "BRONZE UNION", "APT27", "Iron Tiger", "LuckyMouse"],
        "actor_type": "nation_state",
    },
    "Thrip": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "ToddyCat": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Tonto Team": {
        "aliases": ["Earth Akhlut", "BRONZE HUNTLEY", "CactusPete", "Karma Panda"],
        "actor_type": "nation_state",
    },
    "Transparent Tribe": {
        "aliases": ["COPPER FIELDSTONE", "APT36", "Mythic Leopard", "ProjectM"],
        "actor_type": "nation_state",
    },
    "Tropic Trooper": {
        "aliases": ["Pirate Panda", "KeyBoy"],
        "actor_type": "nation_state",
    },
    "Volatile Cedar": {
        "aliases": ["Lebanese Cedar"],
        "actor_type": "nation_state",
    },
    "Whitefly": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Windigo": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Windshift": {
        "aliases": ["Bahamut"],
        "actor_type": "nation_state",
    },
    "Winnti Group": {
        "aliases": ["Blackfly"],
        "actor_type": "nation_state",
    },
    "Winter Vivern": {
        "aliases": ["TA473", "UAC-0114"],
        "actor_type": "nation_state",
    },
    "WIRTE": {
        "aliases": [],
        "actor_type": "nation_state",
    },
    "Wizard Spider": {
        "aliases": ["UNC1878", "TEMP.MixMaster", "Grim Spider", "FIN12", "GOLD BLACKBURN", "ITG23", "Periwinkle Tempest", "DEV-0193"],
        "actor_type": "nation_state",
    },
    "ZIRCONIUM": {
        "aliases": ["APT31", "Violet Typhoon"],
        "actor_type": "nation_state",
    },

    # ---------- Added from ransomware.live ----------
    "0mega": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "Abrahams_Ax": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "abyss": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "adminlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "againstthewest": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "AiLock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ako": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ALP-001": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "alphalocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "anubis": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "apos": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "apt73": {
        "aliases": ["bashe"],
        "actor_type": "cybercriminal",
    },
    "arcusmedia": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "argonauts": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "arkana": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "arvinclub": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "atomsilo": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "AuditTeam": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "aurora": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "avaddon": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "avos": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "avoslocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "aware": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "aztroteam": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "babuk": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "babuk2": {
        "aliases": ["Satanlock"],
        "actor_type": "cybercriminal",
    },
    "babyduck": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "beast": {
        "aliases": ["GIGAKICK"],
        "actor_type": "cybercriminal",
    },
    "benzona": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bert": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blacklock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blackmatter": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blacknevas": {
        "aliases": ["Trial Recovery"],
        "actor_type": "cybercriminal",
    },
    "blackout": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blackshadow": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blackshrantac": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blacktor": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "blackwater": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bluebox": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bluelocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bluesky": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bonacigroup": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bqtlock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "bravox": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "brotherhood": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cactus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cephalus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "chaos": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cheers": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "chilelocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "chort": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cicada3301": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ciphbit": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cipherforce": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cloak": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "CMDOrganization": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "coinbasecartel": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ContFR": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cooming": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "crazyhunter": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "crosslock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "crylock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cryptbb": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cryptnet": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "crypto24": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "cuba": {
        "aliases": ["Colddraw"],
        "actor_type": "cybercriminal",
    },
    "cyclops": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "d4rk4rmy": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dagonlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "daixin": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dAn0n": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkangels": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkbit": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkleakmarket": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkpower": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkrace": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "darkvault": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "datacarry": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "datakeeper": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dataleak": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "desolator": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "devman": {
        "aliases": ["Devman 2.0"],
        "actor_type": "cybercriminal",
    },
    "diavol": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "direwolf": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dispossessor": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "donex": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "donutleaks": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "doppelpaymer": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dragonransomware": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dread": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "dunghill": {
        "aliases": ["darkangel"],
        "actor_type": "cybercriminal",
    },
    "ech0raix": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ElDorado": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "embargo": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "entropy": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ep918": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "esxiargs": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "everest": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "exitium": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "exorcist": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "fletchen": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "flocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "frag": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "freecivilian": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "fsteam": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "fulcrumsec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "funksec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "GDLockerSec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "genesis": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "global": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "grief": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "groove": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "gunra": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hades": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "haron": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hellcat": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "helldown": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hellogookie": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hellokitty": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "holyghost": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hotarus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "hunters": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "Icarus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "icefire": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "IMNCrew": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "incransom": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "insane": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "insomnia": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "interlock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kairos": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "karakurt": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "karma": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kawa4096": {
        "aliases": ["KaWaLocker"],
        "actor_type": "cybercriminal",
    },
    "kazu": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kelvinsecurity": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "killsec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kittykatkrew": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "knight": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kraken": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "krybit": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kryptos": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "kyber": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "la_piovra": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lamashtu": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "LeakBazaar": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "leaktheanalyst": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lilith": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "linkc": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lockbit2": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lockbit3": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lockbit3_fs": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lockbit5": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lockdata": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "Loki": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lolnek": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lorenz": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "losttrust": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lunalock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lv": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "lynx": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "madcat": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "madliberator": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "malas": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "malekteam": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mallox": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mamona": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "marketo": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mbc": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "meow": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "metaencryptor": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "midas": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mindware": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "minteye": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mogilevich": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "monti": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "morpheus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mosesstaff": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "mountlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ms13089": {
        "aliases": ["ms13-089"],
        "actor_type": "cybercriminal",
    },
    "mydecryptor": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "n3tworm": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nasirsecurity": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nefilim": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nemty": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "netrunner": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "netwalker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nevada": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nightsky": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nightspire": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "noescape": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nokoyawa": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "nova": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "obscura": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "onepercent": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "onyx": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "orca": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "orion": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "osiris": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "pandora": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "pay2key": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "Payday": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "payload": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "payloadbin": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "payoutsking": {
        "aliases": ["Payouts King"],
        "actor_type": "cybercriminal",
    },
    "pear": {
        "aliases": ["Pure Extraction And Ransom"],
        "actor_type": "cybercriminal",
    },
    "playboy": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "PrinzEugen": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "projectrelic": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "prolock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "prometheus": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "promptlock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "pysa": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "qiulong": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "qlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "quantum": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "rabbithole": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "radar": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "radiant": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ragnarlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ragnarok": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ralord": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ramp": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "rancoz": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ranion": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ransombay": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ransomcartel": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ransomcortex": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ransomed": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ransomexx": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ranstreet": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ranzy": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "raworld": {
        "aliases": ["ragroup"],
        "actor_type": "cybercriminal",
    },
    "raznatovic": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "rebornvc": {
        "aliases": ["RansomedVC2"],
        "actor_type": "cybercriminal",
    },
    "redalert": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "redransomware": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "reynolds": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "robinhood": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "rook": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "rransom": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "RunSomeWares": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "sabbath": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "safepay": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "sarcoma": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "satanlockv2": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "secp0": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "securotrop": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "SenSayQ": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "shadow": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ShadowByt3$": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "shaoleaks": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ShinySp1d3r": {
        "aliases": ["ShinySpider"],
        "actor_type": "cybercriminal",
    },
    "sicarii": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "silent": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "SilentRansomGroup": {
        "aliases": ["leakeddata"],
        "actor_type": "cybercriminal",
    },
    "sinobi": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "skira": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "slug": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "solidbit": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "spacebears": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "sparta": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "spook": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "stormous": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "sugar": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "suncrypt": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "synack": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "teamxxx": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "tengu": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "termite": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "thegentlemen": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "thegreenbloodgroup": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "threeam": {
        "aliases": ["3Am"],
        "actor_type": "cybercriminal",
    },
    "TiMc": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "toufan": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "tridentlocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "trinity": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "trisec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "u-bomb": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "underground": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "unknown": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "unsafe": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "ValenciaLeaks": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "VanHelsing": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "vanirgroup": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "vect": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "vendetta": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "vfokx": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "walocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "wannacry": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "warlock": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "werewolves": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "weyhro": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "worldleaks": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "x001xs": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "xinglocker": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "xinof": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "yanluowang": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "yurei": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "zeon": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "zerolockersec": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
    "zerotolerance": {
        "aliases": [],
        "actor_type": "cybercriminal",
    },
}
