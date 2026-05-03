use rand::seq::SliceRandom;

static ADJECTIVES: &[&str] = &[
    "amber", "ancient", "arctic", "bold", "brave", "bright", "calm", "clever",
    "cobalt", "cosmic", "crimson", "crystal", "dark", "dawn", "deep", "deft",
    "distant", "dusk", "eager", "early", "elder", "ember", "emerald", "endless",
    "fast", "fierce", "fiery", "firm", "fleet", "frosty", "gentle", "gilded",
    "glacial", "golden", "grand", "grave", "green", "grim", "hidden", "hollow",
    "hushed", "icy", "idle", "indigo", "iron", "jade", "keen", "kind",
    "late", "lean", "light", "lofty", "lone", "long", "lucky", "lunar",
    "mighty", "misty", "muted", "mystic", "noble", "northern", "obsidian", "odd",
    "old", "onyx", "open", "pale", "patient", "phantom", "plain", "polar",
    "proud", "quick", "quiet", "radiant", "rapid", "raven", "red", "regal",
    "remote", "restless", "rough", "royal", "ruby", "rugged", "rust", "sacred",
    "sage", "scarlet", "sharp", "silent", "silver", "sleek", "slow", "small",
    "solar", "solid", "stark", "steady", "steel", "still", "stone", "storm",
    "strange", "strong", "sturdy", "subtle", "sunlit", "swift", "tall", "tame",
    "tawny", "tender", "thin", "tidal", "timeless", "tiny", "twilight", "vast",
    "velvet", "verdant", "vivid", "wandering", "warm", "wild", "wise", "young",
];

static NOUNS: &[&str] = &[
    "anvil", "apex", "archer", "arrow", "atlas", "axe", "badger", "beacon",
    "bear", "blade", "blaze", "bolt", "boulder", "bridge", "buck", "canyon",
    "cedar", "cipher", "circuit", "citadel", "cliff", "cloud", "comet", "condor",
    "creek", "crow", "cycle", "delta", "drifter", "drum", "dune", "eagle",
    "echo", "ember", "engine", "falcon", "fang", "fern", "field", "flare",
    "flint", "flux", "forge", "fox", "frost", "gale", "gate", "glacier",
    "glyph", "gorge", "grove", "hammer", "harbor", "hawk", "hearth", "helm",
    "herald", "heron", "hollow", "horizon", "hunter", "iris", "jaguar", "kelp",
    "lance", "lantern", "lark", "ledge", "lens", "leopard", "lever", "light",
    "linx", "lion", "loch", "lynx", "magpie", "maple", "marble", "marsh",
    "mesa", "meteor", "monk", "moon", "moss", "moth", "mountain", "nexus",
    "oak", "orbit", "otter", "owl", "path", "peak", "pebble", "pilot",
    "pine", "pixel", "plume", "prism", "pulse", "raven", "reef", "ridge",
    "river", "rock", "root", "runner", "sage", "scout", "seal", "shard",
    "shore", "signal", "skiff", "slope", "smoke", "spark", "spire", "spruce",
    "stag", "star", "stone", "storm", "stream", "summit", "swan", "swift",
    "talon", "thorn", "tide", "timber", "torch", "tower", "trail", "vale",
    "vault", "vector", "veil", "vista", "vortex", "wave", "wolf", "wraith",
];

/// Generate a random two-word session name like "swift-badger" or "crimson-falcon".
pub fn generate() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES.choose(&mut rng).unwrap_or(&"bold");
    let noun = NOUNS.choose(&mut rng).unwrap_or(&"falcon");
    format!("{}-{}", adj, noun)
}
