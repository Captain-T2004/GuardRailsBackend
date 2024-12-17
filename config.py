from guardrails import Guard
from guardrails.hub import (
    RegexMatch,
    ValidLength,
    EndsWith,
    ContainsString,
    CompetitorCheck,
    DetectPII,
    GibberishText,
    NSFWText,
    SecretsPresent,
    ToxicLanguage,
    FinancialTone,
    GuardrailsPII,
    HasUrl,
    LowerCase,
    MentionsDrugs,
    OneLine,
    RedundantSentences,
    ValidPython,
)

input_validators = {
    "valid_length": ValidLength(min=1, max=100, on_fail="reask"),
    "ends_with": EndsWith(end=".", on_fail="reask"),
    "detect_pii": DetectPII(on_fail="reask"),
    "gibberish_text": GibberishText(on_fail="reask"),
    "nsfw_text": NSFWText(on_fail="reask"),
    "secrets_present": SecretsPresent(on_fail="reask"),
    "toxic_language": ToxicLanguage(on_fail="reask"),
}

output_validators = {
    "financial_tone": FinancialTone(on_fail="reask"),
    "guardrails_pii": GuardrailsPII(entities=["DATE_TIME", "PHONE_NUMBER"], on_fail="reask"),
    "has_url": HasUrl(on_fail="reask"),
    "lowercase": LowerCase(on_fail="reask"),
    "mentions_drugs": MentionsDrugs(on_fail="reask"),
    "redundant_sentences": RedundantSentences(on_fail="reask"),
    "valid_python": ValidPython(on_fail="reask"),
    "detect_pii": DetectPII(on_fail="reask"),
}

def create_guard(validator_type="input", selected_validators=None):
    if validator_type == "input": validators_set = input_validators.values()
    elif validator_type == "output": validators_set = output_validators.values()
    else: raise ValueError("Invalid validator_type. Must be 'input' or 'output'.")
    return Guard(name=f"{validator_type}-dynamic-validator").use_many(*validators_set)
