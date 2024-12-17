from guardrails import Guard
from guardrails.hub import (
    DetectPII, GibberishText, NSFWText, SecretsPresent,
    ToxicLanguage, FinancialTone, GuardrailsPII, HasUrl,
    MentionsDrugs, RedundantSentences, ValidPython
)

input_validators = {
    "detect_pii": DetectPII(on_fail="noop"),
    "gibberish_text": GibberishText(on_fail="noop"),
    "nsfw_text": NSFWText(on_fail="noop"),
    "secrets_present": SecretsPresent(on_fail="noop"),
    "toxic_language": ToxicLanguage(on_fail="noop"),
}

output_validators = {
    "financial_tone": FinancialTone(on_fail="noop"),
    "guardrails_pii": GuardrailsPII(entities=["CREDIT_CARD", "CRYPTO", "PHONE_NUMBER"], on_fail="fix"),
    "has_url": HasUrl(on_fail="noop"),
    "mentions_drugs": MentionsDrugs(on_fail="noop"),
    "redundant_sentences": RedundantSentences(on_fail="noop"),
    "valid_python": ValidPython(on_fail="noop"),
    "detect_pii": DetectPII(on_fail="noop"),
}

def create_guard(validator_type="input", selected_validators=None):
    if(selected_validators):
        if validator_type == "input": validators_set = [input_validators[validator] for validator in selected_validators]
        elif validator_type == "output": validators_set = [output_validators[validator] for validator in selected_validators]
        else: raise ValueError("Invalid validator_type. Must be 'input' or 'output'.")
    else:
        if validator_type == "input": validators_set = input_validators.values()
        elif validator_type == "output": validators_set = output_validators.values()
        else: raise ValueError("Invalid validator_type. Must be 'input' or 'output'.")
    return Guard(name=f"{validator_type}-dynamic-validator").use_many(*validators_set)

def parse_validation_output(validation_outcome):
    if( not validation_outcome): return []
    parsed_outcome = {
        "validation_passed": validation_outcome.validation_passed,
        "error": validation_outcome.error,
        "validation_summaries": [],
        "raw_llm_output": validation_outcome.raw_llm_output,
    }
    parsed_outcome["validation_summaries"] = [
        {
            "validator_name": i.validator_name,
            "validator_status": i.validator_status,
            "failure_reason": i.failure_reason,
            "error_spans": [[j.start, j.end, j.reason] for j in i.error_spans],
        } for i in validation_outcome.validation_summaries ]
    return parsed_outcome


"""
# Guardrails PII supported validations:
    "CREDIT_CARD",
    "CRYPTO",
    "DATE_TIME",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "NRP",
    "LOCATION",
    "PERSON",
    "PHONE_NUMBER",
    "MEDICAL_LICENSE",
    "URL",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
    "UK_NHS",
    "ES_NIF",
    "ES_NIE",
    "IT_FISCAL_CODE",
    "IT_DRIVER_LICENSE",
    "IT_VAT_CODE",
    "IT_PASSPORT",
    "IT_IDENTITY_CARD",
    "PL_PESEL",
    "SG_NRIC_FIN",
    "SG_UEN",
    "AU_ABN",
    "AU_ACN",
    "AU_TFN",
    "AU_MEDICARE",
    "IN_PAN",
    "IN_AADHAAR",
    "IN_VEHICLE_REGISTRATION",
    "IN_VOTER",
    "IN_PASSPORT",
    "FI_PERSONAL_IDENTITY_CODE"
"""