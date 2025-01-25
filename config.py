from guardrails import Guard
from guardrails.hub import (
    DetectPII, GibberishText, NSFWText,
    ProfanityFree, SecretsPresent, ToxicLanguage,
    DetectJailbreak, FinancialTone, GuardrailsPII, HasUrl,
    MentionsDrugs, RedundantSentences, ValidJson,
    ValidPython, ValidURL, ValidSQL, ValidOpenApiSpec, WebSanitization
)

input_validators = {
    "DetectPII": DetectPII(on_fail="noop"),
    "SecretsPresent": SecretsPresent(on_fail="noop"),
    "DetectJailbreak": DetectJailbreak(on_fail="noop"),
    "MentionsDrugs": MentionsDrugs(on_fail="noop"),
}

output_validators = {
    "DetectPII": DetectPII(on_fail="noop"),
    "ProfanityFree":ProfanityFree(on_fail="noop"),
    "WebSanitization": WebSanitization(on_fail="noop"),
    "GibberishText": GibberishText(on_fail="noop"),
    "NSFWText": NSFWText(on_fail="noop"),
    "FinancialTone": FinancialTone(on_fail="noop"),
    "SecretsPresent": SecretsPresent(on_fail="noop"),
    "MentionsDrugs": MentionsDrugs(on_fail="noop"),
    "RedundantSentences": RedundantSentences(on_fail="noop"),
    "ToxicLanguage": ToxicLanguage(on_fail="noop"),
    "ValidPython": ValidPython(on_fail="noop"),
    "DetectJailbreak": DetectJailbreak(on_fail="noop"),
    "ValidOpenApiSpec": ValidOpenApiSpec(on_fail="noop"),
    "ValidJson": ValidJson(on_fail="noop"),
    "ValidSQL": ValidSQL(on_fail="noop"),
    "ValidURL": ValidURL(on_fail="noop"),
    "HasUrl": HasUrl(on_fail="noop"),
}

def create_guard(validator_type="input", selected_validators=None):
    if validator_type == "input": validators_set = [input_validators[validator] for validator in selected_validators]
    elif validator_type == "output": validators_set = [output_validators[validator] for validator in selected_validators]
    else: raise ValueError("Invalid validator_type. Must be 'input' or 'output'.")
    return Guard(name=f"{validator_type}-dynamic-validator").use_many(*validators_set)

def parse_validation_output(validation_outcome):
    if not validation_outcome:
        return []

    parsed_outcome = {
        "validation_passed": getattr(validation_outcome, "validation_passed", False),
        "error": getattr(validation_outcome, "error", None),
        "validation_summaries": [],
        "raw_llm_output": getattr(validation_outcome, "validated_output", None),
    }

    validation_summaries = getattr(validation_outcome, "validation_summaries", [])
    for summary in validation_summaries:
        validator_name = getattr(summary, "validator_name", "Unknown")
        validator_status = getattr(summary, "validator_status", "Unknown")
        failure_reason = getattr(summary, "failure_reason", "No reason provided")
        
        error_spans = []
        if getattr(summary, "error_spans", None):
            error_spans = [
                [getattr(span, "start", 0), getattr(span, "end", 0), getattr(span, "reason", "Unknown")]
                for span in summary.error_spans
            ]

        parsed_outcome["validation_summaries"].append({
            "validator_name": validator_name,
            "validator_status": validator_status,
            "failure_reason": failure_reason,
            "error_spans": error_spans,
        })
    return parsed_outcome