from app.services.actor_recognition import attribute_events


def actor_recognition_job():
    """
    Pipeline stage that runs deterministic threat-actor recognition over
    every clustered event with a victim and no (or generic) actor. Replaces
    the prior LLM-based enrichment stage.
    """
    return attribute_events()
