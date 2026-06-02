"""Test fixture with AI/ML security issues."""

import torch
import joblib

# Hardcoded AI key
OPENAI_API_KEY = "sk-abc123def456"


def load_model_unsafe(path):
    return torch.load(path)


def load_sklearn_model(path):
    return joblib.load(path)


def prompt_injection(client, user_input):
    response = client.chat.create(prompt=f"Answer: {user_input}")
    return response


def log_response(response):
    print(response.completion)


def api_in_loop(client, items):
    for item in items:
        client.completions.create(prompt=item)


def api_no_limits(client, text):
    return client.chat.generate(prompt=text)


def train_without_seed(model, X, y):
    model.fit(X, y)
