"""Cloud AI provider secret patterns."""

PATTERNS = [
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-proj-[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "provider": "openai",
    },
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "provider": "anthropic",
    },
    {
        "name": "Groq API Key",
        "pattern": r"gsk_[A-Za-z0-9]{20,}",
        "severity": "high",
        "provider": "groq",
    },
    {
        "name": "Cohere API Key",
        "pattern": r"co-[A-Za-z0-9]{40,}",
        "severity": "high",
        "provider": "cohere",
    },
    {
        "name": "Hugging Face Token",
        "pattern": r"hf_[A-Za-z0-9]{34,}",
        "severity": "high",
        "provider": "huggingface",
    },
    {
        "name": "Replicate API Token",
        "pattern": r"r8_[A-Za-z0-9]{38,}",
        "severity": "high",
        "provider": "replicate",
    },
]
