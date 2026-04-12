from app.services.clustering import (
    get_ready_for_clustering,
    get_extraction,
    find_candidate_events,
    find_best_match,
    attach_to_event,
    create_event,
    refresh_event,
)


def cluster_events_job():
    """
    Entry point for clustering stage.
    """
    articles = get_ready_for_clustering()

    for article in articles:
        extraction = get_extraction(article)

        candidates = find_candidate_events(extraction)
        best_match = find_best_match(extraction, candidates)

        if best_match.score >= 0.8:
            attach_to_event(article, best_match)
            refresh_event(best_match.event_id)
        else:
            new_event = create_event(article, extraction)
            attach_to_event(article, new_event)

    return True