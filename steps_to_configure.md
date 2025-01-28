# need to have redis installed and running locally for fastapi rate limiting.
# and make .env file just like env_sample and add all db info.
# make sure ngrok is installed.

## In one terminal:

1. python -m venv env

2. pip install -r requirements.txt

3. guardrails configure( need guardrails api key )

4. chmod +x commands.sh

5. ./commands.sh

6. copy the contents of ./modifications/guardrails_grhub_detect_jailbreak to ./env/lib/python3/site-packages/guardrails_grhub_detect_jailbreak

7. Place .env file to the app folder.

8. uvicorn main:app --host 0.0.0.0 --port 8000

## In 2nd terminal run:

1. ngrok config add-authtoken $NGROK_AUTH_TOKEN
2. ngrok http --domain=immune-louse-dynamic.ngrok-free.app 8000
