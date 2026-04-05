"""Platform and SaaS secret patterns."""

PATTERNS = [
    {
        "name": "Vercel Access Token",
        "pattern": r"vercel_[A-Za-z0-9_\-]{24,}",
        "severity": "high",
        "provider": "vercel",
    },
    {
        "name": "Supabase Service Role Key",
        "pattern": r"sbp_[a-f0-9]{40}",
        "severity": "critical",
        "provider": "supabase",
    },
    {
        "name": "Supabase Anon Key (JWT)",
        "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJzdXBhYmFzZSI",
        "severity": "medium",
        "provider": "supabase",
    },
    {
        "name": "Shopify Access Token",
        "pattern": r"shpat_[a-f0-9]{32}",
        "severity": "high",
        "provider": "shopify",
    },
    {
        "name": "Shopify Custom App Token",
        "pattern": r"shpca_[a-f0-9]{32}",
        "severity": "high",
        "provider": "shopify",
    },
    {
        "name": "Shopify Private App Password",
        "pattern": r"shppa_[a-f0-9]{32}",
        "severity": "high",
        "provider": "shopify",
    },
    {
        "name": "Shopify Shared Secret",
        "pattern": r"shpss_[a-f0-9]{32}",
        "severity": "high",
        "provider": "shopify",
    },
    {
        "name": "PlanetScale Database Token",
        "pattern": r"pscale_tkn_[A-Za-z0-9_\-]{40,}",
        "severity": "high",
        "provider": "planetscale",
    },
    {
        "name": "PlanetScale OAuth Token",
        "pattern": r"pscale_oauth_[A-Za-z0-9_\-]{40,}",
        "severity": "high",
        "provider": "planetscale",
    },
    {
        "name": "Databricks API Token",
        "pattern": r"dapi[a-f0-9]{32}",
        "severity": "high",
        "provider": "databricks",
    },
    {
        "name": "Linear API Key",
        "pattern": r"lin_api_[A-Za-z0-9]{40}",
        "severity": "high",
        "provider": "linear",
    },
    {
        "name": "Netlify Access Token",
        "pattern": r"nfp_[A-Za-z0-9]{40,}",
        "severity": "high",
        "provider": "netlify",
    },
    {
        "name": "Fly.io Access Token",
        "pattern": r"fo1_[A-Za-z0-9_\-]{40,}",
        "severity": "high",
        "provider": "flyio",
    },
]
